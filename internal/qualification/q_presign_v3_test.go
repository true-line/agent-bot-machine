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
	now                           time.Time
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

func makeQFixtureV3(t *testing.T, observationSequence int, cleanEOF bool, launchMatches bool) qFixtureV3 {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const schema = qSessionSchemaV3
	const session = "1234567890abcdef1234567890abcdef"
	const cohort = "fixture-cohort"
	const install = "fixture-install"
	const soul = "agent_12345678-1234-1234-1234-1234567890ab"
	const start = "st_1234567890abcdef12345678"
	const host = "fixture-host"
	const profile = "managed-protected"
	challenge := bytes.Repeat([]byte{0x42}, 32)
	launch := digest([]byte("launch challenge"))
	reservation := qSignFixtureV3(t, map[string]any{
		"contract": "machine/v1", "kind": "stage2a-reservation", "schema_version": 1,
		"admission_challenge_sha256": launch, "host_id": host,
		"assignment":          map[string]any{"installation_id": install, "soul_id": soul, "start_id": start},
		"measurement_binding": map[string]any{"installation_id": install, "soul_id": soul, "start_id": start, "host_id": host, "profile_in_force": profile},
	}, qReservationPurposeV3, 2, priv)
	reservationSHA := digest(reservation)
	begin := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "begin", "session_id": session,
		"challenge_base64url": base64.RawURLEncoding.EncodeToString(challenge),
		"cohort_id":           cohort, "installation_id": install, "soul_id": soul, "start_id": start,
		"host_id": host, "profile": profile, "reservation_sha256": reservationSHA,
		"test_plan_sha256": digest([]byte("plan")), "suite_revision": "1111111111111111111111111111111111111111",
		"ps_sha256": digest([]byte("ps")), "path_roots": []string{"/tmp/q-root"},
		"q_uid": 501, "q_gid": 20, "deadline_at": "2026-11-22T12:05:00Z",
	})
	ready := qFrameFixtureV3(t, map[string]any{
		"schema": schema, "kind": "ready", "session_id": session,
		"challenge_sha256": digest(challenge), "sequence": 0,
		"pid": 812, "uid": 501, "gid": 20, "source_sha256": digest([]byte("q source")),
		"captured_at": "2026-11-22T12:00:00Z",
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
	return qFixtureV3{wire: wire, index: index, eof: eof, reservation: reservation, key: pub,
		now: time.Date(2026, 11, 22, 12, 0, 10, 0, time.UTC)}
}

func TestVerifyQPreSignV3(t *testing.T) {
	good := makeQFixtureV3(t, 1, true, true)
	got, err := VerifyQPreSignV3(good.wire, good.index, good.eof, good.reservation, good.key, good.now)
	if err != nil || !got.verified || got.ObservationCount != 1 || got.IndexSHA256 != digest(good.index) {
		t.Fatalf("valid signed Q component refused: %+v %v", got, err)
	}
	cases := []struct {
		name    string
		fixture qFixtureV3
	}{
		{"coherently signed wrong sequence", makeQFixtureV3(t, 2, true, true)},
		{"signed missing EOF", makeQFixtureV3(t, 1, false, true)},
		{"signed launch mismatch", makeQFixtureV3(t, 1, true, false)},
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
