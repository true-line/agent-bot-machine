package members

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func driverCaseBegin(profile string) stage2aQualificationBeginV1 {
	return stage2aQualificationBeginV1{
		SessionID: strings.Repeat("1", 32), Profile: profile,
		InstallationID: "install-1", StartID: "st_111111111111111111111111",
		ReservationSHA256: "sha256:" + strings.Repeat("2", 64),
		TestPlanSHA256:    "sha256:" + strings.Repeat("3", 64),
		DeadlineAt:        time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339Nano),
	}
}

func TestStage2aQualificationDriverPairsFixedSchedule(t *testing.T) {
	for _, run := range []struct {
		profile string
		phase   stage2aDriverRunPhase
		gates   string
	}{
		{"managed-protected", stage2aDriverBeforeLaunch, "T02 T03"},
		{"managed-protected", stage2aDriverLiveStart, "T01 T02 T02 T03"},
		{"managed-protected", stage2aDriverRestart, "T01 T02"},
		{"managed-cooperative", stage2aDriverBeforeLaunch, "T21"},
		{"managed-cooperative", stage2aDriverLiveStart, "T21 T21"},
		{"managed-cooperative", stage2aDriverRestart, "T21 T21"},
	} {
		t.Run(run.profile+"/"+string(run.phase), func(t *testing.T) {
			a, driver := net.Pipe()
			defer a.Close()
			defer driver.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			begin := driverCaseBegin(run.profile)
			done := make(chan error, 1)
			var digest string
			go func() {
				done <- serveStage2aQualificationDriverCases(ctx, driver, begin, run.phase,
					func(_ context.Context, command stage2aDriverCommand) (string, error) {
						return stage2aQualificationSHA256([]byte(command.Challenge)), nil
					})
			}()
			var seen []string
			trace, err := exchangeStage2aDriverCases(ctx, a, begin, run.phase, func() error { return nil },
				func(_ context.Context, command stage2aDriverCommand, hash string) (stage2aDriverCorroboration, error) {
					artifact := []byte(command.Challenge)
					digest = stage2aQualificationSHA256(artifact)
					if hash != digest || command.Sequence != len(seen)+1 {
						return stage2aDriverCorroboration{}, errors.New("capture mismatch")
					}
					return stage2aDriverCorroboration{
						artifact: artifact, osWitness: []byte(`{"fixture":true}`),
						probe: stage2aQualificationObserveV1{Paths: []stage2aQualificationPathRequestV1{
							{Role: "a-selected", Path: "/private/var/db/managed-machine"},
						}},
					}, nil
				},
				func(probe stage2aQualificationObserveV1) ([]byte, error) {
					if probe.StimulusRef == nil || probe.StimulusRef.SHA256 != digest ||
						probe.Phase != string(run.phase) || probe.Processes == nil || len(probe.Paths) != 1 {
						return nil, errors.New("invalid Q stimulus binding")
					}
					seen = append(seen, probe.Gate)
					return nil, nil
				})
			if err != nil || strings.Join(seen, " ") != run.gates || len(trace) != len(seen) {
				t.Fatalf("exchange recorded %v, %d paired frames, error %v", seen, len(trace), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStage2aQualificationDriverRejectsArtifactReplayAndUnverifiedCase(t *testing.T) {
	for _, replay := range []bool{true, false} {
		a, driver := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		done := make(chan error, 1)
		go func() {
			defer driver.Close()
			raw, err := readStage2aQualificationFrame(driver)
			if err != nil {
				done <- err
				return
			}
			hash := stage2aQualificationSHA256(raw)
			if replay {
				var prior stage2aDriverCommand
				_ = json.Unmarshal(raw, &prior)
				prior.SessionID = strings.Repeat("a", 32)
				replayRaw, _ := marshalStage2aReservationJCS(prior)
				hash = stage2aQualificationSHA256(replayRaw)
			}
			_, err = writeStage2aQualificationFrame(driver, stage2aDriverResponse{
				Schema: stage2aDriverCaseSchema, Kind: "captured",
				RequestSHA: hash, ArtifactSHA: "sha256:" + strings.Repeat("4", 64),
			})
			done <- err
		}()
		verified, observed := false, false
		trace, err := exchangeStage2aDriverCases(ctx, a, driverCaseBegin("managed-cooperative"),
			stage2aDriverBeforeLaunch, func() error { return nil },
			func(context.Context, stage2aDriverCommand, string) (stage2aDriverCorroboration, error) {
				verified = true
				return stage2aDriverCorroboration{}, errors.New("bad service signature")
			}, func(stage2aQualificationObserveV1) ([]byte, error) {
				observed = true
				return nil, nil
			})
		cancel()
		a.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err == nil || trace != nil || observed || verified == replay {
			t.Fatalf("accepted case replay=%v: trace=%v verified=%v observed=%v err=%v", replay, trace, verified, observed, err)
		}
	}
}

func TestStage2aQualificationDriverSignsExactQJoin(t *testing.T) {
	begin := driverCaseBegin("managed-cooperative")
	begin.Schema, begin.Kind = stage2aQualificationSchemaV1, "begin"
	begin.PathRoots = []string{"/private"}
	challenge := make([]byte, 32)
	begin.ChallengeBase64URL = base64.RawURLEncoding.EncodeToString(challenge)
	challengeHash := stage2aQualificationSHA256(challenge)
	phase := stage2aDriverBeforeLaunch
	step := stage2aDriverSchedule(begin.Profile, phase)[0]
	request := mustStage2aQualificationFrame(t, stage2aDriverCommand{
		Schema: stage2aDriverCaseSchema, Kind: "capture", SessionID: begin.SessionID,
		InstallationID: begin.InstallationID, StartID: begin.StartID,
		ReservationSHA256: begin.ReservationSHA256, TestPlanSHA256: begin.TestPlanSHA256,
		Challenge: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		Sequence:  1, Profile: begin.Profile, Phase: phase, Gate: step.Gate, Event: step.Event,
	})
	artifactRaw := []byte("synthetic service receipt")
	artifact := stage2aQualificationSHA256(artifactRaw)
	response := mustStage2aQualificationFrame(t, stage2aDriverResponse{
		Schema: stage2aDriverCaseSchema, Kind: "captured", RequestSHA: stage2aQualificationSHA256(request[4:]),
		ArtifactSHA: artifact,
	})
	trace := []stage2aDriverEvidence{{request: request, response: response, artifact: artifactRaw, osWitness: []byte(`{"fixture":true}`)}}
	stimulus := stage2aQualificationStimulusRefV1{URI: stage2aDriverStimulusURI(begin.SessionID, step.Event), SHA256: artifact}
	qRequest := mustStage2aQualificationFrame(t, stage2aQualificationObserveV1{
		Schema: stage2aQualificationSchemaV1, Kind: "observe", SessionID: begin.SessionID,
		Sequence: 1, Gate: step.Gate, Phase: string(phase), EventID: step.Event, StimulusRef: &stimulus,
		Processes: []stage2aQualificationProcessRequestV1{},
		Paths:     []stage2aQualificationPathRequestV1{{Role: "baseline", Path: "/private/baseline"}},
	})
	now := time.Now().UTC().Truncate(time.Millisecond)
	captured := now.Format("2006-01-02T15:04:05.000Z")
	qResponse := mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "observation", "session_id": begin.SessionID,
		"sequence": 1, "challenge_sha256": challengeHash, "request_sha256": stage2aQualificationSHA256(qRequest[4:]),
		"gate": step.Gate, "phase": string(phase), "event_id": step.Event, "stimulus_ref": stimulus,
		"captured_at": captured, "processes": []any{}, "paths": []any{map[string]any{
			"role": "baseline", "path": "/private/baseline", "exists": false, "error": "ENOENT",
		}},
	})
	sourceHash := "sha256:" + strings.Repeat("f", 64)
	result := stage2aQualificationSessionResultV1{
		begin: begin, beginFrame: mustStage2aQualificationFrame(t, begin),
		peer:         stage2aQualificationPeerV1{uid: 451, gid: 452, pid: 453},
		sourceSHA256: sourceHash, challengeSHA256: challengeHash, validated: true, count: 1,
		cleanEOFObserved: true, eofObservedAt: now,
		requestFrames: qRequest, requestsSHA256: stage2aQualificationSHA256(qRequest),
		observationFrames: qResponse, observationsSHA256: stage2aQualificationSHA256(qResponse),
		readyFrame: mustStage2aQualificationFrame(t, map[string]any{
			"schema": stage2aQualificationSchemaV1, "kind": "ready", "session_id": begin.SessionID,
			"sequence": 0, "challenge_sha256": challengeHash, "captured_at": captured,
			"uid": 451, "gid": 452, "pid": 453, "source_sha256": sourceHash,
		}),
		finishRequestFrame: mustStage2aQualificationFrame(t, map[string]any{
			"schema": stage2aQualificationSchemaV1, "kind": "finish", "session_id": begin.SessionID, "sequence": 2,
		}),
		finishedFrame: mustStage2aQualificationFrame(t, map[string]any{
			"schema": stage2aQualificationSchemaV1, "kind": "finished", "session_id": begin.SessionID, "sequence": 2,
			"observation_count": 1, "observations_sha256": stage2aQualificationSHA256(qResponse),
			"challenge_sha256": challengeHash, "captured_at": captured,
		}),
	}
	executable := "/private/owner-driver"
	argv := []string{executable, "--connect", "/private/driver.sock"}
	review := stage2aDriverReview{
		Schema: stage2aDriverCaseSchema, Socket: argv[2], Argv: argv, testPlanSHA256: begin.TestPlanSHA256,
		Executable: qualificationFile{Path: executable, SHA256: strings.Repeat("a", 64)},
	}
	peer := stage2aQualificationDriverPeer{pid: 13, execPath: executable, argv: argv, kernel: soulKernelProcessSnapshot{
		PID: 13, ParentPID: 12, ProcessGroupID: 13, StartSeconds: now.Unix(),
		RealUID: 502, EffectiveUID: 502, SavedUID: 502, RealGID: 20, PrimaryGroupGID: 20, SavedGID: 20,
	}}
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issueStage2aDriverReceipt(result, phase, review, peer, trace, now, key,
		func(raw []byte) ([]byte, error) { return ed25519.Sign(private, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStage2aDriverReceipt(signed, result, phase, review, peer, trace, key); err != nil {
		t.Fatal(err)
	}
	if verifyStage2aDriverReceipt(signed, result, stage2aDriverRestart, review, peer, trace, key) == nil {
		t.Fatal("baseline receipt accepted for restart")
	}
	tampered := append([]stage2aDriverEvidence(nil), trace...)
	tampered[0].artifact = []byte("substituted capture")
	if _, err := issueStage2aDriverReceipt(result, phase, review, peer, tampered, now, key,
		func(raw []byte) ([]byte, error) { return ed25519.Sign(private, raw), nil }); err == nil {
		t.Fatal("receipt issued over substituted capture bytes")
	}
	objects := stage2aQualificationPreSignArtifactsV1{
		WireSHA256:       stage2aQualificationSHA256([]byte("wire")),
		IndexSHA256:      stage2aQualificationSHA256([]byte("index")),
		EOFReceiptSHA256: stage2aQualificationSHA256([]byte("eof")),
	}
	archive, err := marshalStage2aDriverArchive(stage2aDriverPhaseCapture{phase, review, peer, trace},
		result, objects, now, key, func(raw []byte) ([]byte, error) { return ed25519.Sign(private, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	var sealed struct {
		Receipt  string                         `json:"receipt_base64url"`
		Evidence []stage2aDriverArchiveEvidence `json:"evidence"`
	}
	if json.Unmarshal(archive, &sealed) != nil || len(sealed.Evidence) != len(trace) ||
		sealed.Evidence[0].SourceBase64URL != base64.RawURLEncoding.EncodeToString(trace[0].artifact) ||
		sealed.Evidence[0].WitnessBase64URL != base64.RawURLEncoding.EncodeToString(trace[0].osWitness) {
		t.Fatal("driver archive did not retain the exact source and witness bytes")
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(sealed.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	rawPayload, err := verifyStage2aStoredARecordV3(envelope, stage2aDriverReceiptPurpose, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	var archivedReceipt stage2aDriverReceipt
	if json.Unmarshal(rawPayload, &archivedReceipt) != nil || archivedReceipt.QWireSHA256 != objects.WireSHA256 ||
		archivedReceipt.QEOFSHA256 != objects.EOFReceiptSHA256 || archivedReceipt.QIndexSHA256 != objects.IndexSHA256 {
		t.Fatal("signed archived capture did not bind the exact Q pre-sign objects")
	}
	peer.kernel.StartSeconds++
	if verifyStage2aDriverReceipt(signed, result, phase, review, peer, trace, key) == nil {
		t.Fatal("another driver generation inherited the capture")
	}
}

func TestStage2aQualificationDriverReviewPinsWholePlan(t *testing.T) {
	dir := t.TempDir()
	executable, socket := "/private/approved/driver", "/private/approved/control.sock"
	material := stage2aDriverReview{
		Schema: stage2aDriverCaseSchema, Socket: socket,
		Executable: qualificationFile{Path: executable, SHA256: strings.Repeat("b", 64)},
		Argv:       []string{executable, "--connect", socket},
	}
	raw, err := json.Marshal(material)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "test-plan.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	digest := stage2aQualificationSHA256(raw)
	pin := qualificationFile{Path: name, SHA256: strings.TrimPrefix(digest, "sha256:")}
	review, err := loadStage2aQualificationDriverReview(pin)
	if err != nil || review.testPlanSHA256 != digest || review.Socket != socket {
		t.Fatalf("review not pinned: %v, %v", review, err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(name, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStage2aQualificationDriverReview(qualificationFile{Path: alias, SHA256: pin.SHA256}); err == nil {
		t.Fatal("test plan through symlink accepted")
	}
	if err := os.WriteFile(name, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStage2aQualificationDriverReview(pin); err == nil {
		t.Fatal("changed test plan accepted")
	}
}
