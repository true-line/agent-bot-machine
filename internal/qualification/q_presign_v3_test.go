package qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

type qFixtureV3 struct {
	wire, index, eof, reservation []byte
	key                           ed25519.PublicKey
	private                       ed25519.PrivateKey
	now                           time.Time
}

// qAggregateConfigV3 is test-only material for complete report-path fixtures.
type qAggregateConfigV3 struct {
	private   ed25519.PrivateKey
	binding   map[string]any
	session   string
	candidate bool
}

func qJSONFixtureV3(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func qFrameFixtureV3(t *testing.T, value any) []byte {
	t.Helper()
	raw := qJSONFixtureV3(t, value)
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	return append(header[:], raw...)
}

func qSignFixtureV3(t *testing.T, value any, purpose string, version int, priv ed25519.PrivateKey) []byte {
	t.Helper()
	payload := qJSONFixtureV3(t, value)
	return qJSONFixtureV3(t, machineRecordV3{
		SchemaVersion: version, Purpose: purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		PayloadSHA256:            digest(payload), PayloadBase64URL: base64.RawURLEncoding.EncodeToString(payload),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, preimage(purpose, payload))),
	})
}

func makeQFixtureV3(t *testing.T, observationSequence int, cleanEOF bool, launchMatches bool, roleUIDs ...int) qFixtureV3 {
	return makeQFixtureContractV3(t, observationSequence, cleanEOF, launchMatches, "machine/v2", 2, qReservationPurposeV3, nil, roleUIDs...)
}

func makeQFixtureContractV3(t *testing.T, observationSequence int, cleanEOF bool, launchMatches bool, contract string, version int, purpose string, attempt map[string]any, roleUIDs ...int) qFixtureV3 {
	return makeQFixtureWithConfigV3(t, observationSequence, cleanEOF, launchMatches, contract, version, purpose, attempt, nil, roleUIDs...)
}

func makeQFixtureWithConfigV3(t *testing.T, observationSequence int, cleanEOF bool, launchMatches bool, contract string, version int, purpose string, attempt map[string]any, cfg *qAggregateConfigV3, roleUIDs ...int) qFixtureV3 {
	t.Helper()
	runnerUID, bridgeUID := 310, 311
	if len(roleUIDs) == 2 {
		runnerUID, bridgeUID = roleUIDs[0], roleUIDs[1]
	} else if len(roleUIDs) != 0 {
		t.Fatal("role UID fixture requires both R and B")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const schema = qSessionSchemaV3
	session := "1234567890abcdef1234567890abcdef"
	const cohort = "fixture-cohort"
	install := "fixture-install"
	soul := "agent_12345678-1234-1234-1234-1234567890ab"
	start := "st_1234567890abcdef12345678"
	host := "fixture-host"
	if cfg != nil {
		priv = cfg.private
		pub = priv.Public().(ed25519.PublicKey)
		session = cfg.session
		install = cfg.binding["installation_id"].(string)
		soul = cfg.binding["soul_id"].(string)
		start = cfg.binding["start_id"].(string)
		host = cfg.binding["host_id"].(string)
	}
	const profile = "managed-protected"
	challenge := bytes.Repeat([]byte{0x42}, 32)
	launch := digest([]byte("launch challenge"))
	snapshot := func(root, inode string) map[string]any {
		return map[string]any{
			"root_path": root, "device": "1", "inode": inode, "generation": "1", "birthtime_ns": "1000",
			"owner_uid": 501, "owner_gid": 20, "mode": "0555",
		}
	}
	reservationPayload := map[string]any{
		"contract": contract, "kind": "stage2a-reservation", "schema_version": version,
		"admission_challenge_sha256": launch, "host_id": host,
		"assignment": map[string]any{"installation_id": install, "soul_id": soul, "start_id": start,
			"launch_id": "ln_1234567890abcdef12345678", "plan_id": "plan-20261122T120000Z-abcd",
			"plan_digest": "1111111111111111111111111111111111111111111111111111111111111111",
			"hq_epoch":    "2222222222222222222222222222222222222222222222222222222222222222",
			"runner_uid":  runnerUID, "bridge_uid": bridgeUID},
		"measurement_binding": map[string]any{
			"contract": "machine/v2", "kind": "stage2a-measurement-binding", "schema_version": 2,
			"installation_id": install, "soul_id": soul, "start_id": start, "launch_id": "ln_1234567890abcdef12345678",
			"host_id": host, "hq_epoch": "2222222222222222222222222222222222222222222222222222222222222222",
			"plan_id":               "plan-20261122T120000Z-abcd",
			"installed_plan_digest": "1111111111111111111111111111111111111111111111111111111111111111",
			"package_sha256":        "3333333333333333333333333333333333333333333333333333333333333333",
			"soul_artifact_sha256":  "4444444444444444444444444444444444444444444444444444444444444444",
			"profile_in_force":      profile, "claimed_definition_digest": digest([]byte("definition")),
			"definition_measurement":   digest([]byte("definition bytes")),
			"launch_input_measurement": digest([]byte("launch inputs")),
			"snapshots":                map[string]any{"definition": snapshot("/tmp/definition", "2"), "launch_inputs": snapshot("/tmp/launch-inputs", "3")},
		},
	}
	if cfg != nil {
		reservationPayload["measurement_binding"] = cfg.binding
		a := reservationPayload["assignment"].(map[string]any)
		for _, name := range []string{"launch_id", "plan_id", "hq_epoch"} {
			a[name] = cfg.binding[name]
		}
		a["plan_digest"] = cfg.binding["installed_plan_digest"]
		a["h_service_descriptor_digest"] = cfg.binding["h_service_descriptor_digest"]
		a["r_inventory_digest"] = cfg.binding["r_inventory"].(map[string]any)["inventory_digest"]
		reservationPayload["issued_at"] = "2026-11-22T11:59:50Z"
		reservationPayload["expires_at"] = "2026-11-22T12:00:15Z"
	}
	if attempt != nil {
		reservationPayload["kind"] = "stage2a-qualification-candidate-reservation"
		reservationPayload["qualification_attempt"] = attempt
	}
	envelopeVersion := 3
	if purpose == qReservationPurposeV3 {
		envelopeVersion = 2
	}
	reservation := qSignFixtureV3(t, reservationPayload, purpose, envelopeVersion, priv)
	reservationSHA := digest(reservation)
	begin := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "begin", "session_id": session,
		"challenge_base64url": base64.RawURLEncoding.EncodeToString(challenge),
		"cohort_id":           cohort, "installation_id": install, "soul_id": soul, "start_id": start,
		"host_id": host, "profile": profile, "reservation_sha256": reservationSHA,
		"test_plan_sha256": digest([]byte("plan")), "suite_revision": "1111111111111111111111111111111111111111",
		"ps_sha256": digest([]byte("ps")), "path_roots": []string{"/tmp/q-root"},
		"q_uid": 501, "q_gid": 20, "deadline_at": "2026-11-22T12:05:00Z", "require_argv_proof": true,
	})
	ready := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "ready", "session_id": session,
		"challenge_sha256": digest(challenge), "sequence": 0,
		"pid": 812, "uid": 501, "gid": 20, "source_sha256": digest([]byte("q source")),
		"captured_at": "2026-11-22T12:00:00Z", "exec_path": "/usr/local/bin/node",
		"argv": []string{"/usr/local/bin/node", "--", "/tmp/q.mjs"},
	})
	request := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "observe", "session_id": session, "sequence": 1,
		"gate": "T01", "phase": "launch", "event_id": "first", "processes": []any{}, "paths": []any{},
	})
	observation := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "observation", "session_id": session,
		"challenge_sha256": digest(challenge), "sequence": observationSequence,
		"request_sha256": digest(request[4:]), "captured_at": "2026-11-22T12:00:01Z",
		"gate": "T01", "phase": "launch", "event_id": "first", "processes": []any{}, "paths": []any{},
	})
	finish := qFrameFixtureV3(t, map[string]any{"schema": schema, "kind": "finish", "session_id": session, "sequence": 2})
	finished := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "finished", "session_id": session,
		"challenge_sha256": digest(challenge), "sequence": 2, "observation_count": 1,
		"observations_sha256": digest(observation), "captured_at": "2026-11-22T12:00:02Z",
	})
	ordered := bytes.Join([][]byte{begin, ready, request, observation, finish, finished}, nil)
	wire := qJSONFixtureV3(t, qWireV3{
		Schema: schema, Kind: "framed-wire", SessionID: session,
		Begin: base64.RawURLEncoding.EncodeToString(begin), Ready: base64.RawURLEncoding.EncodeToString(ready),
		Requests: base64.RawURLEncoding.EncodeToString(request), Observations: base64.RawURLEncoding.EncodeToString(observation),
		FinishRequest: base64.RawURLEncoding.EncodeToString(finish), Finished: base64.RawURLEncoding.EncodeToString(finished),
	})
	indexLaunch := launch
	if !launchMatches {
		indexLaunch = digest([]byte("different launch challenge"))
	}
	idx := qIndexV3{
		Schema: schema, Kind: "pre-sign-index", CohortID: cohort, InstallationID: install, SoulID: soul,
		StartID: start, HostID: host, Profile: profile, ReservationSHA256: reservationSHA, SessionID: session,
		QChallengeSHA256: digest(challenge), LaunchChallengeSHA256: indexLaunch,
		QSourceSHA256: digest([]byte("q source")), TestPlanSHA256: digest([]byte("plan")),
		QSocketPath: "/tmp/q.sock", QSocketDevice: 1, QSocketInode: 2,
		QSocketBirthSeconds: 1795348700, QSocketBirthNanos: 123,
		QPID: 812, QUID: 501, QGID: 20, QParentPID: 811, QProcessGroupID: 811,
		QStartSeconds: 1795348750, QStartMicros: 123456,
		QExecutable: "/usr/local/bin/node", QArgv: []string{"/usr/local/bin/node", "--", "/tmp/q.mjs"},
		WireSHA256: digest(wire), OrderedFramesSHA256: digest(ordered),
		BeginFrameSHA256: digest(begin), ReadyFrameSHA256: digest(ready),
		RequestFramesSHA256: digest(request), ObservationFramesSHA256: digest(observation),
		FinishRequestFrameSHA256: digest(finish), FinishedFrameSHA256: digest(finished),
		ObservationCount: 1, IssuedAt: "2026-11-22T12:00:04Z",
	}
	index := qSignFixtureV3(t, idx, QFrameIndexPurposeV3, 1, priv)
	eof := qSignFixtureV3(t, qEOFV3{
		Schema: schema, Kind: "finished-clean-eof", SessionID: session,
		IndexEnvelopeSHA256: digest(index), WireSHA256: digest(wire), FinishedFrameSHA256: digest(finished),
		ObservationCount: 1, CleanEOFObserved: cleanEOF, NoTrailingBytes: true,
		EOFObservedAt: "2026-11-22T12:00:03Z", IssuedAt: "2026-11-22T12:00:04Z",
	}, QFinishedEOFPurposeV3, 1, priv)
	return qFixtureV3{wire: wire, index: index, eof: eof, reservation: reservation, key: pub, private: priv,
		now: time.Date(2026, 11, 22, 12, 0, 10, 0, time.UTC)}
}

func TestQSerializedPOSIXPathsV3(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/tmp/q", true}, {"/usr/local/bin/q", true},
		{"/tmp/../q", false}, {"/tmp//q", false}, {"/tmp/q/", false},
		{"C:/tmp/q", false}, {"/tmp/\\q", false}, {"relative", false}, {"/", false},
	} {
		if got := qPathV3(tc.path); got != tc.want {
			t.Errorf("qPathV3(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestVerifyQPreSignV3(t *testing.T) {
	good := makeQFixtureV3(t, 1, true, true)
	got, err := VerifyQPreSignV3(good.wire, good.index, good.eof, good.reservation, good.key, good.now)
	if err != nil || !got.verified || got.ObservationCount != 1 || got.IndexSHA256 != digest(good.index) {
		t.Fatalf("valid signed Q component refused: %+v %v", got, err)
	}
	attempt := map[string]any{
		"test_plan_sha256": digest([]byte("plan")),
		"suite_revision":   "1111111111111111111111111111111111111111",
	}
	for _, c := range []struct {
		name    string
		purpose string
		attempt map[string]any
	}{
		{"ordinary v3 reservation", qOrdinaryReservationPurposeV3, nil},
		{"candidate v3 reservation", qCandidateReservationPurposeV3, attempt},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := makeQFixtureContractV3(t, 1, true, true, "machine/v3", 3, c.purpose, c.attempt)
			if _, err := VerifyQPreSignV3(f.wire, f.index, f.eof, f.reservation, f.key, f.now); err != nil {
				t.Fatal(err)
			}
		})
	}

	cases := []struct {
		name    string
		fixture qFixtureV3
	}{
		{"coherently signed wrong sequence", makeQFixtureV3(t, 2, true, true)},
		{"signed missing EOF", makeQFixtureV3(t, 1, false, true)},
		{"signed launch mismatch", makeQFixtureV3(t, 1, true, false)},
		{"signed legacy reservation", makeQFixtureContractV3(t, 1, true, true, "machine/v1", 1, qReservationPurposeV3, nil)},
		{"candidate with wrong suite", makeQFixtureContractV3(t, 1, true, true, "machine/v3", 3, qCandidateReservationPurposeV3,
			map[string]any{"test_plan_sha256": digest([]byte("plan")), "suite_revision": "2222222222222222222222222222222222222222"})},
		{"candidate signed under ordinary purpose", makeQFixtureContractV3(t, 1, true, true, "machine/v3", 3, qOrdinaryReservationPurposeV3, attempt)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.fixture
			if _, err := VerifyQPreSignV3(f.wire, f.index, f.eof, f.reservation, f.key, f.now); err == nil {
				t.Fatal("invalid signed component accepted")
			}
		})
	}
	t.Run("changed raw wire", func(t *testing.T) {
		changed := append([]byte(nil), good.wire...)
		changed[len(changed)-2] ^= 1
		if _, err := VerifyQPreSignV3(changed, good.index, good.eof, good.reservation, good.key, good.now); err == nil {
			t.Fatal("changed wire accepted")
		}
	})
	t.Run("wrong enrolled A key", func(t *testing.T) {
		wrong, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := VerifyQPreSignV3(good.wire, good.index, good.eof, good.reservation, wrong, good.now); err == nil {
			t.Fatal("wrong A key accepted")
		}
	})
	t.Run("missing EOF receipt", func(t *testing.T) {
		if _, err := VerifyQPreSignV3(good.wire, good.index, nil, good.reservation, good.key, good.now); err == nil {
			t.Fatal("missing EOF accepted")
		}
	})
}

func TestQTranscriptRequiresChallengeBoundArgvProofV3(t *testing.T) {
	good := makeQFixtureV3(t, 1, true, true)
	var wire qWireV3
	if err := json.Unmarshal(good.wire, &wire); err != nil {
		t.Fatal(err)
	}
	frame := func(encoded string) []byte {
		t.Helper()
		framed, err := decode(encoded, qFrameMaxV3+4)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := qFrameV3(framed)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	begin, ready := frame(wire.Begin), frame(wire.Ready)
	finish, finished := frame(wire.FinishRequest), frame(wire.Finished)
	requestBytes, err := decode(wire.Requests, qStreamMaxV3)
	if err != nil {
		t.Fatal(err)
	}
	observationBytes, err := decode(wire.Observations, qStreamMaxV3)
	if err != nil {
		t.Fatal(err)
	}
	_, requests, err := qFramesV3(requestBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, observations, err := qFramesV3(observationBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	indexBytes, err := qSignedRecordV3(good.index, QFrameIndexPurposeV3, 1, good.key)
	if err != nil {
		t.Fatal(err)
	}
	var index qIndexV3
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	eofAt := time.Date(2026, 11, 22, 12, 0, 3, 0, time.UTC)
	check := func(beginBytes, readyBytes []byte) error {
		return qVerifyTranscriptV3(beginBytes, readyBytes, requests, observations,
			finish, finished, observationBytes, index, eofAt)
	}
	if err := check(begin, ready); err != nil {
		t.Fatalf("challenge-bound argv proof refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing executable", func(m map[string]any) { delete(m, "exec_path") }},
		{"wrong executable", func(m map[string]any) { m["exec_path"] = "/tmp/other-node" }},
		{"missing argv", func(m map[string]any) { delete(m, "argv") }},
		{"changed argv", func(m map[string]any) { m["argv"].([]any)[2] = "/tmp/other.mjs" }},
		{"extra field", func(m map[string]any) { m["unreviewed"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal(ready, &fields); err != nil {
				t.Fatal(err)
			}
			tc.change(fields)
			if err := check(begin, qJSONFixtureV3(t, fields)); err == nil {
				t.Fatal("unbound Q Ready argv accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing requirement", func(m map[string]any) { delete(m, "require_argv_proof") }},
		{"disabled requirement", func(m map[string]any) { m["require_argv_proof"] = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal(begin, &fields); err != nil {
				t.Fatal(err)
			}
			tc.change(fields)
			if err := check(qJSONFixtureV3(t, fields), ready); err == nil {
				t.Fatal("Q session without required argv proof accepted")
			}
		})
	}
}
