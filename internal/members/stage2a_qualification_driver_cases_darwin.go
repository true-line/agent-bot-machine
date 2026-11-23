package members

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const stage2aDriverCaseSchema = "agent-bot-machine/qualification-owner-driver/v1"

type stage2aDriverRunPhase string

const (
	stage2aDriverBeforeLaunch stage2aDriverRunPhase = "before-launch"
	stage2aDriverLiveStart    stage2aDriverRunPhase = "live-start"
	stage2aDriverRestart      stage2aDriverRunPhase = "live-restart"
)

type stage2aDriverCase struct {
	Gate  string
	Event string
}

// A derives phase from the local reservation and launch state. A baseline
// provides no physical T credit. A restart needs its own start and session.
func stage2aDriverSchedule(profile string, phase stage2aDriverRunPhase) []stage2aDriverCase {
	switch profile {
	case "managed-protected":
		switch phase {
		case stage2aDriverBeforeLaunch:
			return []stage2aDriverCase{{"T02", "custody-baseline"}, {"T03", "policy-baseline"}}
		case stage2aDriverLiveStart:
			return []stage2aDriverCase{
				{"T01", "copied-handle-refused"},
				{"T02", "member-custody-refused"}, {"T02", "paired-operation"},
				{"T03", "direct-route-refused"},
			}
		case stage2aDriverRestart:
			return []stage2aDriverCase{{"T01", "copied-handle-refused"}, {"T02", "paired-operation"}}
		}
	case "managed-cooperative":
		switch phase {
		case stage2aDriverBeforeLaunch:
			return []stage2aDriverCase{{"T21", "cooperative-baseline"}}
		case stage2aDriverLiveStart, stage2aDriverRestart:
			return []stage2aDriverCase{{"T21", "protected-claim-refused"}, {"T21", "cooperative-receipt"}}
		}
	}
	return nil
}

type stage2aDriverCommand struct {
	Schema            string                `json:"schema"`
	Kind              string                `json:"kind"`
	SessionID         string                `json:"session_id"`
	InstallationID    string                `json:"installation_id"`
	StartID           string                `json:"start_id"`
	ReservationSHA256 string                `json:"reservation_sha256"`
	TestPlanSHA256    string                `json:"test_plan_sha256"`
	Challenge         string                `json:"challenge_base64url"`
	Sequence          int                   `json:"sequence"`
	Profile           string                `json:"profile"`
	Phase             stage2aDriverRunPhase `json:"phase"`
	Gate              string                `json:"gate"`
	Event             string                `json:"event"`
}

type stage2aDriverResponse struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	RequestSHA  string `json:"request_sha256"`
	ArtifactSHA string `json:"artifact_sha256"`
}

func parseStage2aDriverResponse(raw, commandRaw []byte) (stage2aDriverResponse, error) {
	var r stage2aDriverResponse
	_, err := stage2aQualificationKeysV1(raw, []string{"schema", "kind", "request_sha256", "artifact_sha256"}, "")
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Schema != stage2aDriverCaseSchema ||
		r.Kind != "captured" || r.RequestSHA != stage2aQualificationSHA256(commandRaw) ||
		!stage2aQualificationDigest(r.ArtifactSHA) {
		return stage2aDriverResponse{}, errStage2aReservationAuthority
	}
	return r, nil
}

type stage2aDriverEvidence struct {
	request, response   []byte
	artifact, osWitness []byte
}

type stage2aDriverCorroboration struct {
	artifact, osWitness []byte
	probe               stage2aQualificationObserveV1
}

func (c stage2aDriverCorroboration) matches(digest string) bool {
	return len(c.artifact) != 0 && len(c.artifact) <= stage2aQualificationFrameMax &&
		stage2aQualificationSHA256(c.artifact) == digest &&
		stage2aQualificationCanonical(c.osWitness) == nil
}

// The verifier reads the exact receipt from A's local store by digest,
// authenticates its issuing service and challenge-bound operation, and
// derives Q's request from A's independent OS checks. Failure spends the run.
type stage2aDriverVerify func(context.Context, stage2aDriverCommand, string) (stage2aDriverCorroboration, error)

func runStage2aQualificationDriverCases(ctx context.Context, conn *net.UnixConn, peer stage2aQualificationDriverPeer,
	begin stage2aQualificationBeginV1, phase stage2aDriverRunPhase, checkLive func() error,
	verify stage2aDriverVerify, observe func(stage2aQualificationObserveV1) ([]byte, error)) ([]stage2aDriverEvidence, error) {
	if conn != nil {
		defer conn.Close()
	}
	return runStage2aQualificationDriverCasesAtSequence(ctx, conn, peer, begin, phase, 1, nil,
		checkLive, verify, observe)
}

// A retained Q session uses one monotonically increasing command/observation
// sequence across baseline and live phases. A preallocated challenge is used
// only for the exact T03 sequence that A signed before child I/O began.
func runStage2aQualificationDriverCasesAtSequence(ctx context.Context, conn *net.UnixConn, peer stage2aQualificationDriverPeer,
	begin stage2aQualificationBeginV1, phase stage2aDriverRunPhase, firstSequence int,
	preallocated map[int]string, checkLive func() error,
	verify stage2aDriverVerify, observe func(stage2aQualificationObserveV1) ([]byte, error)) ([]stage2aDriverEvidence, error) {
	if conn == nil {
		return nil, errStage2aReservationAuthority
	}
	if checkLive == nil {
		return nil, errStage2aReservationAuthority
	}
	return exchangeStage2aDriverCasesAtSequence(ctx, conn, begin, phase, firstSequence, preallocated, func() error {
		if err := peer.recheck(); err != nil {
			return err
		}
		return checkLive()
	}, verify, observe)
}

func exchangeStage2aDriverCases(ctx context.Context, conn net.Conn, begin stage2aQualificationBeginV1,
	phase stage2aDriverRunPhase, checkLive func() error, verify stage2aDriverVerify,
	observe func(stage2aQualificationObserveV1) ([]byte, error)) ([]stage2aDriverEvidence, error) {
	return exchangeStage2aDriverCasesAtSequence(ctx, conn, begin, phase, 1, nil, checkLive, verify, observe)
}

func exchangeStage2aDriverCasesAtSequence(ctx context.Context, conn net.Conn, begin stage2aQualificationBeginV1,
	phase stage2aDriverRunPhase, firstSequence int, preallocated map[int]string,
	checkLive func() error, verify stage2aDriverVerify,
	observe func(stage2aQualificationObserveV1) ([]byte, error)) ([]stage2aDriverEvidence, error) {
	schedule := stage2aDriverSchedule(begin.Profile, phase)
	deadline, err := time.Parse(time.RFC3339Nano, begin.DeadlineAt)
	if ctx == nil || checkLive == nil || verify == nil || observe == nil || len(schedule) == 0 ||
		firstSequence < 1 || firstSequence+len(schedule)-1 > 1024 ||
		err != nil || !time.Now().Before(deadline) || !stage2aQualificationDigest(begin.ReservationSHA256) ||
		!stage2aQualificationDigest(begin.TestPlanSHA256) || len(begin.SessionID) != 32 || !stage2aQualificationHex(begin.SessionID) {
		return nil, errStage2aReservationAuthority
	}
	if len(preallocated) > 1 {
		return nil, errStage2aReservationAuthority
	}
	for sequence := range preallocated {
		index := sequence - firstSequence
		if index < 0 || index >= len(schedule) || schedule[index] != (stage2aDriverCase{"T03", "direct-route-refused"}) {
			return nil, errStage2aReservationAuthority
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	deadline, _ = ctx.Deadline()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	trace := make([]stage2aDriverEvidence, 0, len(schedule))
	usedArtifacts := make(map[string]bool, len(schedule))
	usedChallenges := make(map[string]bool, len(schedule))
	for i, step := range schedule {
		frameDeadline := time.Now().Add(30 * time.Second)
		if deadline.Before(frameDeadline) {
			frameDeadline = deadline
		}
		if ctx.Err() != nil || checkLive() != nil ||
			conn.SetDeadline(frameDeadline) != nil || ctx.Err() != nil {
			return nil, errStage2aReservationAuthority
		}
		sequence := firstSequence + i
		challenge := preallocated[sequence]
		if challenge == "" {
			var nonce [32]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return nil, err
			}
			challenge = base64.RawURLEncoding.EncodeToString(nonce[:])
		} else {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
			if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != challenge ||
				step.Gate != "T03" || step.Event != "direct-route-refused" {
				return nil, errStage2aReservationAuthority
			}
		}
		if usedChallenges[challenge] {
			return nil, errStage2aReservationAuthority
		}
		usedChallenges[challenge] = true
		command := stage2aDriverCommand{
			Schema: stage2aDriverCaseSchema, Kind: "capture", SessionID: begin.SessionID,
			InstallationID: begin.InstallationID, StartID: begin.StartID,
			ReservationSHA256: begin.ReservationSHA256, TestPlanSHA256: begin.TestPlanSHA256,
			Challenge: challenge, Sequence: sequence, Profile: begin.Profile,
			Phase: phase, Gate: step.Gate, Event: step.Event,
		}
		request, err := writeStage2aQualificationFrame(conn, command)
		if err != nil {
			return nil, err
		}
		raw, response, err := readStage2aQualificationObservedFrame(conn)
		if err != nil || ctx.Err() != nil || checkLive() != nil {
			return nil, errStage2aReservationAuthority
		}
		r, err := parseStage2aDriverResponse(raw, request[4:])
		if err != nil || usedArtifacts[r.ArtifactSHA] {
			return nil, errStage2aReservationAuthority
		}
		usedArtifacts[r.ArtifactSHA] = true
		corroboration, err := verify(ctx, command, r.ArtifactSHA)
		probe := corroboration.probe
		if err != nil || ctx.Err() != nil || checkLive() != nil ||
			!corroboration.matches(r.ArtifactSHA) || len(probe.Processes)+len(probe.Paths) == 0 {
			return nil, fmt.Errorf("%s %s: %w", step.Gate, step.Event, errStage2aReservationAuthority)
		}
		probe.Gate, probe.Phase, probe.EventID = step.Gate, string(phase), step.Event
		probe.StimulusRef = &stage2aQualificationStimulusRefV1{
			URI: stage2aDriverStimulusURI(begin.SessionID, step.Event), SHA256: r.ArtifactSHA,
		}
		if probe.Processes == nil {
			probe.Processes = []stage2aQualificationProcessRequestV1{}
		}
		if probe.Paths == nil {
			probe.Paths = []stage2aQualificationPathRequestV1{}
		}
		if _, err := observe(probe); err != nil {
			return nil, err
		}
		trace = append(trace, stage2aDriverEvidence{
			request: request, response: response,
			artifact: bytes.Clone(corroboration.artifact), osWitness: bytes.Clone(corroboration.osWitness),
		})
	}
	if ctx.Err() != nil || checkLive() != nil {
		return nil, errStage2aReservationAuthority
	}
	return trace, nil
}

// The A launcher opens the one-use Q session from the durable reservation,
// then drives a phase using its own launch-state check and case verifiers.
// The listener remains the caller's responsibility and must be retired
// under the installed owner plan before a later phase can reuse its path.
func driveStage2aQualificationPhase(ctx context.Context, listener *stage2aQualificationDriverListener,
	testPlan qualificationFile, session *stage2aQualificationSessionV1, phase stage2aDriverRunPhase,
	checkLive func() error, verify stage2aDriverVerify) (stage2aDriverReview, stage2aQualificationDriverPeer, []stage2aDriverEvidence, error) {
	var emptyReview stage2aDriverReview
	var emptyPeer stage2aQualificationDriverPeer
	if ctx == nil || ctx.Err() != nil || session == nil || session.closed || checkLive == nil ||
		verify == nil || checkLive() != nil || len(stage2aDriverSchedule(session.begin.Profile, phase)) == 0 ||
		session.begin.TestPlanSHA256 != "sha256:"+testPlan.SHA256 {
		return emptyReview, emptyPeer, nil, errStage2aReservationAuthority
	}
	review, err := loadStage2aQualificationDriverReview(testPlan)
	if err != nil {
		session.close()
		return emptyReview, emptyPeer, nil, err
	}
	conn, peer, err := acceptStage2aReviewedQualificationDriver(ctx, listener, review)
	if err != nil {
		session.close()
		return emptyReview, emptyPeer, nil, err
	}
	trace, err := runStage2aQualificationDriverCases(ctx, conn, peer, session.begin, phase, checkLive, verify, session.observe)
	if err != nil {
		session.close()
		return emptyReview, emptyPeer, nil, err
	}
	return review, peer, trace, nil
}
