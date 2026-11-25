package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	QFrameIndexPurposeV3           = "agent-bot/stage2a-q-frame-index/v1"
	QFinishedEOFPurposeV3          = "agent-bot/stage2a-q-finished-eof/v1"
	qReservationPurposeV3          = "agent-bot/stage2a-reservation/v2"
	qOrdinaryReservationPurposeV3  = "agent-bot/stage2a-reservation/v3"
	qCandidateReservationPurposeV3 = "agent-bot/stage2a-qualification-candidate-reservation/v3"
	qSessionSchemaV3               = "soul-conformance/qualification-session/v1"
	qFrameMaxV3                    = 65536
	qStreamMaxV3                   = 128 * (qFrameMaxV3 + 4)
)

var (
	qTimeV3         = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$`)
	qTokenV3        = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	qInstallationV3 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	qSoulV3         = regexp.MustCompile(`^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	qStartV3        = regexp.MustCompile(`^st_[0-9a-f]{24}$`)
)

// VerifiedQPreSignV3 authenticates one A-observed Q wire/index/EOF chain.
// It carries no physical gate verdict and grants neither launch nor release.
type VerifiedQPreSignV3 struct {
	verified                                                              bool
	SessionID, CohortID, InstallationID, SoulID, StartID, HostID, Profile string
	ReservationSHA256, WireSHA256, IndexSHA256, EOFReceiptSHA256          string
	QSourceSHA256, TestPlanSHA256, QChallengeSHA256, SuiteRevision        string
	ObservationCount                                                      int
}

type qWireV3 struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	SessionID     string `json:"session_id"`
	Begin         string `json:"begin_frame_base64url"`
	Ready         string `json:"ready_frame_base64url"`
	Requests      string `json:"request_frames_base64url"`
	Observations  string `json:"observation_frames_base64url"`
	FinishRequest string `json:"finish_request_frame_base64url"`
	Finished      string `json:"finished_frame_base64url"`
}

type qIndexV3 struct {
	Schema                   string   `json:"schema"`
	Kind                     string   `json:"kind"`
	CohortID                 string   `json:"cohort_id"`
	InstallationID           string   `json:"installation_id"`
	SoulID                   string   `json:"soul_id"`
	StartID                  string   `json:"start_id"`
	HostID                   string   `json:"host_id"`
	Profile                  string   `json:"profile"`
	ReservationSHA256        string   `json:"reservation_sha256"`
	SessionID                string   `json:"session_id"`
	QChallengeSHA256         string   `json:"q_challenge_sha256"`
	LaunchChallengeSHA256    string   `json:"launch_challenge_sha256"`
	QSourceSHA256            string   `json:"q_source_sha256"`
	TestPlanSHA256           string   `json:"test_plan_sha256"`
	QSocketPath              string   `json:"q_socket_path"`
	QSocketDevice            uint64   `json:"q_socket_device"`
	QSocketInode             uint64   `json:"q_socket_inode"`
	QSocketBirthSeconds      int64    `json:"q_socket_birth_seconds"`
	QSocketBirthNanos        int64    `json:"q_socket_birth_nanos"`
	QPID                     int      `json:"q_pid"`
	QUID                     int      `json:"q_uid"`
	QGID                     int      `json:"q_gid"`
	QParentPID               int      `json:"q_parent_pid"`
	QProcessGroupID          int      `json:"q_process_group_id"`
	QStartSeconds            int64    `json:"q_start_seconds"`
	QStartMicros             int32    `json:"q_start_micros"`
	QExecutable              string   `json:"q_executable"`
	QArgv                    []string `json:"q_argv"`
	WireSHA256               string   `json:"wire_sha256"`
	OrderedFramesSHA256      string   `json:"ordered_frames_sha256"`
	BeginFrameSHA256         string   `json:"begin_frame_sha256"`
	ReadyFrameSHA256         string   `json:"ready_frame_sha256"`
	RequestFramesSHA256      string   `json:"request_frames_sha256"`
	ObservationFramesSHA256  string   `json:"observation_frames_sha256"`
	FinishRequestFrameSHA256 string   `json:"finish_request_frame_sha256"`
	FinishedFrameSHA256      string   `json:"finished_frame_sha256"`
	ObservationCount         int      `json:"observation_count"`
	IssuedAt                 string   `json:"issued_at"`
}

type qEOFV3 struct {
	Schema              string `json:"schema"`
	Kind                string `json:"kind"`
	SessionID           string `json:"session_id"`
	IndexEnvelopeSHA256 string `json:"index_envelope_sha256"`
	WireSHA256          string `json:"wire_sha256"`
	FinishedFrameSHA256 string `json:"finished_frame_sha256"`
	ObservationCount    int    `json:"observation_count"`
	CleanEOFObserved    bool   `json:"clean_eof_observed"`
	NoTrailingBytes     bool   `json:"no_trailing_bytes"`
	EOFObservedAt       string `json:"eof_observed_at"`
	IssuedAt            string `json:"issued_at"`
}

func qSignedRecordV3(raw []byte, purpose string, version int, key ed25519.PublicKey) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || len(key) != ed25519.PublicKeySize {
		return nil, ErrUnqualified
	}
	f, err := canonicalBytes(raw, 64<<10)
	if err != nil || !hasFields(f, "schema_version", "purpose", "issuer_public_key_base64url", "payload_sha256", "payload_base64url", "signature_base64url") {
		return nil, ErrUnqualified
	}
	var e machineRecordV3
	if json.Unmarshal(raw, &e) != nil || e.SchemaVersion != version || e.Purpose != purpose || e.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(key) {
		return nil, ErrUnqualified
	}
	payload, err := decode(e.PayloadBase64URL, 48<<10)
	if err != nil || digest(payload) != e.PayloadSHA256 {
		return nil, ErrUnqualified
	}
	if _, err = canonicalBytes(payload, 48<<10); err != nil {
		return nil, ErrUnqualified
	}
	sig, err := decode(e.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, preimage(purpose, payload), sig) {
		return nil, ErrUnqualified
	}
	return payload, nil
}

func qFrameV3(frame []byte) ([]byte, error) {
	if len(frame) < 5 || len(frame) > qFrameMaxV3+4 || int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 {
		return nil, ErrUnqualified
	}
	raw := frame[4:]
	if _, err := canonicalBytes(raw, qFrameMaxV3); err != nil {
		return nil, ErrUnqualified
	}
	return raw, nil
}

func qFramesV3(stream []byte, expected int) ([][]byte, [][]byte, error) {
	if expected < 1 || expected > 128 || len(stream) == 0 || len(stream) > qStreamMaxV3 {
		return nil, nil, ErrUnqualified
	}
	frames, payloads := make([][]byte, 0, expected), make([][]byte, 0, expected)
	for len(stream) > 0 {
		if len(frames) == expected || len(stream) < 5 {
			return nil, nil, ErrUnqualified
		}
		n := int(binary.BigEndian.Uint32(stream[:4]))
		if n < 1 || n > qFrameMaxV3 || len(stream) < 4+n {
			return nil, nil, ErrUnqualified
		}
		frame := stream[:4+n]
		payload, err := qFrameV3(frame)
		if err != nil {
			return nil, nil, ErrUnqualified
		}
		frames, payloads = append(frames, frame), append(payloads, payload)
		stream = stream[4+n:]
	}
	if len(frames) != expected {
		return nil, nil, ErrUnqualified
	}
	return frames, payloads, nil
}

func qTimeParsedV3(value string) (time.Time, error) {
	if !qTimeV3.MatchString(value) {
		return time.Time{}, ErrUnqualified
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, ErrUnqualified
	}
	return t, nil
}

func qExactObjectV3(raw []byte, keys ...string) bool {
	f, err := canonicalBytes(raw, qFrameMaxV3)
	return err == nil && hasFields(f, keys...)
}

func qPathV3(value string) bool {
	if len(value) < 2 || len(value) > 4096 || !path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, "\\") ||
		strings.Contains(value, "//") {
		return false
	}
	for _, c := range value {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// VerifyQPreSignV3 checks exact raw framed Q bytes against separate A-signed
// pre-sign index and clean-EOF receipts. The Machine key is independently
// enrolled. The signed reservation is required to join the launch challenge;
// its full lifecycle is checked by the separate one-use verifier.
func VerifyQPreSignV3(wireRaw, indexEnvelope, eofEnvelope, reservationEnvelope []byte,
	machineKey ed25519.PublicKey, now time.Time) (VerifiedQPreSignV3, error) {
	var zero VerifiedQPreSignV3
	if now.IsZero() || len(wireRaw) == 0 || len(wireRaw) > 32<<20 {
		return zero, ErrUnqualified
	}
	wf, err := canonicalBytes(wireRaw, 32<<20)
	if err != nil || !hasFields(wf, "schema", "kind", "session_id", "begin_frame_base64url", "ready_frame_base64url", "request_frames_base64url", "observation_frames_base64url", "finish_request_frame_base64url", "finished_frame_base64url") {
		return zero, ErrUnqualified
	}
	var wire qWireV3
	if json.Unmarshal(wireRaw, &wire) != nil || wire.Schema != qSessionSchemaV3 || wire.Kind != "framed-wire" {
		return zero, ErrUnqualified
	}
	indexRaw, err := qSignedRecordV3(indexEnvelope, QFrameIndexPurposeV3, 1, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	ifields, err := canonicalBytes(indexRaw, 48<<10)
	if err != nil || !hasFields(ifields, "schema", "kind", "cohort_id", "installation_id", "soul_id", "start_id", "host_id", "profile", "reservation_sha256", "session_id", "q_challenge_sha256", "launch_challenge_sha256", "q_source_sha256", "test_plan_sha256", "q_socket_path", "q_socket_device", "q_socket_inode", "q_socket_birth_seconds", "q_socket_birth_nanos", "q_pid", "q_uid", "q_gid", "q_parent_pid", "q_process_group_id", "q_start_seconds", "q_start_micros", "q_executable", "q_argv", "wire_sha256", "ordered_frames_sha256", "begin_frame_sha256", "ready_frame_sha256", "request_frames_sha256", "observation_frames_sha256", "finish_request_frame_sha256", "finished_frame_sha256", "observation_count", "issued_at") {
		return zero, ErrUnqualified
	}
	var idx qIndexV3
	if json.Unmarshal(indexRaw, &idx) != nil || idx.Schema != qSessionSchemaV3 || idx.Kind != "pre-sign-index" || idx.SessionID != wire.SessionID || len(idx.SessionID) != 32 || !qLowerHexV3(idx.SessionID) || idx.ObservationCount < 1 || idx.ObservationCount > 128 || idx.WireSHA256 != digest(wireRaw) || !validSHA(idx.ReservationSHA256) || !validSHA(idx.QChallengeSHA256) || !validSHA(idx.LaunchChallengeSHA256) || idx.QChallengeSHA256 == idx.LaunchChallengeSHA256 || !validSHA(idx.QSourceSHA256) || !validSHA(idx.TestPlanSHA256) || !qIndexIdentityV3(idx) {
		return zero, ErrUnqualified
	}
	eofRaw, err := qSignedRecordV3(eofEnvelope, QFinishedEOFPurposeV3, 1, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	ef, err := canonicalBytes(eofRaw, 48<<10)
	if err != nil || !hasFields(ef, "schema", "kind", "session_id", "index_envelope_sha256", "wire_sha256", "finished_frame_sha256", "observation_count", "clean_eof_observed", "no_trailing_bytes", "eof_observed_at", "issued_at") {
		return zero, ErrUnqualified
	}
	var eof qEOFV3
	if json.Unmarshal(eofRaw, &eof) != nil || eof.Schema != qSessionSchemaV3 || eof.Kind != "finished-clean-eof" || eof.SessionID != idx.SessionID || eof.IndexEnvelopeSHA256 != digest(indexEnvelope) || eof.WireSHA256 != idx.WireSHA256 || eof.FinishedFrameSHA256 != idx.FinishedFrameSHA256 || eof.ObservationCount != idx.ObservationCount || !eof.CleanEOFObserved || !eof.NoTrailingBytes {
		return zero, ErrUnqualified
	}
	issued, e1 := parseTime(idx.IssuedAt)
	eofAt, e2 := parseTime(eof.EOFObservedAt)
	eofIssued, e3 := parseTime(eof.IssuedAt)
	if e1 != nil || e2 != nil || e3 != nil || eofAt.After(issued) || issued.After(eofAt.Add(30*time.Second)) || !eofIssued.Equal(issued) || issued.After(now) {
		return zero, ErrUnqualified
	}
	if digest(reservationEnvelope) != idx.ReservationSHA256 {
		return zero, ErrUnqualified
	}
	begin, e1 := decode(wire.Begin, qFrameMaxV3+4)
	ready, e2 := decode(wire.Ready, qFrameMaxV3+4)
	requests, e3 := decode(wire.Requests, qStreamMaxV3)
	observations, e4 := decode(wire.Observations, qStreamMaxV3)
	finish, e5 := decode(wire.FinishRequest, qFrameMaxV3+4)
	finished, e6 := decode(wire.Finished, qFrameMaxV3+4)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || digest(begin) != idx.BeginFrameSHA256 || digest(ready) != idx.ReadyFrameSHA256 || digest(requests) != idx.RequestFramesSHA256 || digest(observations) != idx.ObservationFramesSHA256 || digest(finish) != idx.FinishRequestFrameSHA256 || digest(finished) != idx.FinishedFrameSHA256 {
		return zero, ErrUnqualified
	}
	beginRaw, e1 := qFrameV3(begin)
	readyRaw, e2 := qFrameV3(ready)
	finishRaw, e3 := qFrameV3(finish)
	finishedRaw, e4 := qFrameV3(finished)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return zero, ErrUnqualified
	}
	reqFrames, reqRaw, err := qFramesV3(requests, idx.ObservationCount)
	if err != nil {
		return zero, ErrUnqualified
	}
	obsFrames, obsRaw, err := qFramesV3(observations, idx.ObservationCount)
	if err != nil {
		return zero, ErrUnqualified
	}
	var ordered bytes.Buffer
	ordered.Write(begin)
	ordered.Write(ready)
	for i := range reqFrames {
		ordered.Write(reqFrames[i])
		ordered.Write(obsFrames[i])
	}
	ordered.Write(finish)
	ordered.Write(finished)
	var scope struct {
		SuiteRevision string `json:"suite_revision"`
	}
	if json.Unmarshal(beginRaw, &scope) != nil || digest(ordered.Bytes()) != idx.OrderedFramesSHA256 ||
		qReservationJoinV3(reservationEnvelope, machineKey, idx, scope.SuiteRevision) != nil || qVerifyTranscriptV3(beginRaw, readyRaw, reqRaw, obsRaw, finishRaw, finishedRaw, observations, idx, eofAt) != nil {
		return zero, ErrUnqualified
	}
	return VerifiedQPreSignV3{verified: true, SessionID: idx.SessionID, CohortID: idx.CohortID, InstallationID: idx.InstallationID, SoulID: idx.SoulID, StartID: idx.StartID, HostID: idx.HostID, Profile: idx.Profile, ReservationSHA256: idx.ReservationSHA256, WireSHA256: idx.WireSHA256, IndexSHA256: digest(indexEnvelope), EOFReceiptSHA256: digest(eofEnvelope), QSourceSHA256: idx.QSourceSHA256, TestPlanSHA256: idx.TestPlanSHA256, QChallengeSHA256: idx.QChallengeSHA256, SuiteRevision: scope.SuiteRevision, ObservationCount: idx.ObservationCount}, nil
}

func qLowerHexV3(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func qIndexIdentityV3(x qIndexV3) bool {
	if !qPrintableV3(x.CohortID, 128) || !qInstallationV3.MatchString(x.InstallationID) || !qSoulV3.MatchString(x.SoulID) || !qStartV3.MatchString(x.StartID) || !qPrintableV3(x.HostID, 128) || (x.Profile != "managed-protected" && x.Profile != "managed-cooperative") || !qPathV3(x.QSocketPath) || !qPathV3(x.QExecutable) || x.QSocketDevice == 0 || x.QSocketInode == 0 || x.QSocketBirthSeconds <= 0 || x.QSocketBirthNanos < 0 || x.QSocketBirthNanos >= 1_000_000_000 || x.QPID <= 0 || x.QPID > 2147483647 || x.QUID <= 399 || x.QUID > 2147483647 || x.QGID <= 0 || x.QGID > 2147483647 || x.QParentPID <= 0 || x.QParentPID > 2147483647 || x.QProcessGroupID <= 0 || x.QProcessGroupID > 2147483647 || x.QStartSeconds <= 0 || x.QStartMicros < 0 || x.QStartMicros >= 1_000_000 || len(x.QArgv) < 3 || len(x.QArgv) > 128 || x.QArgv[0] != x.QExecutable {
		return false
	}
	for _, a := range x.QArgv {
		if a == "" || strings.ContainsRune(a, '\x00') {
			return false
		}
	}
	return true
}

func qPrintableV3(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func qReservationRecordV3(envelope []byte, key ed25519.PublicKey) ([]byte, string, error) {
	// Select the expected purpose and version together, then authenticate the
	// envelope and match its payload to the selected contract.
	var header struct {
		Purpose string `json:"purpose"`
	}
	if len(envelope) > 64<<10 || json.Unmarshal(envelope, &header) != nil {
		return nil, "", ErrUnqualified
	}
	contract, kind, version := "machine/v3", "stage2a-reservation", 3
	switch header.Purpose {
	case qReservationPurposeV3:
		contract, version = "machine/v2", 2
	case qOrdinaryReservationPurposeV3:
	case qCandidateReservationPurposeV3:
		kind = "stage2a-qualification-candidate-reservation"
	default:
		return nil, "", ErrUnqualified
	}
	payload, err := qSignedRecordV3(envelope, header.Purpose, version, key)
	if err != nil {
		return nil, "", ErrUnqualified
	}
	fields, err := canonicalBytes(payload, 48<<10)
	if err != nil || string(fields["contract"]) != `"`+contract+`"` ||
		string(fields["kind"]) != `"`+kind+`"` || string(fields["schema_version"]) != strconv.Itoa(version) {
		return nil, "", ErrUnqualified
	}
	return payload, header.Purpose, nil
}

func qReservationJoinV3(envelope []byte, key ed25519.PublicKey, idx qIndexV3, suiteRevision string) error {
	payload, purpose, err := qReservationRecordV3(envelope, key)
	if err != nil {
		return ErrUnqualified
	}
	var p struct {
		HostID                   string `json:"host_id"`
		AdmissionChallengeSHA256 string `json:"admission_challenge_sha256"`
		Assignment               struct {
			InstallationID string `json:"installation_id"`
			SoulID         string `json:"soul_id"`
			StartID        string `json:"start_id"`
		} `json:"assignment"`
		MeasurementBinding struct {
			InstallationID string `json:"installation_id"`
			SoulID         string `json:"soul_id"`
			StartID        string `json:"start_id"`
			HostID         string `json:"host_id"`
			Profile        string `json:"profile_in_force"`
		} `json:"measurement_binding"`
		Attempt *struct {
			TestPlanSHA256 string `json:"test_plan_sha256"`
			SuiteRevision  string `json:"suite_revision"`
		} `json:"qualification_attempt"`
	}
	if json.Unmarshal(payload, &p) != nil || p.AdmissionChallengeSHA256 != idx.LaunchChallengeSHA256 || p.HostID != idx.HostID || p.Assignment.InstallationID != idx.InstallationID || p.Assignment.SoulID != idx.SoulID || p.Assignment.StartID != idx.StartID || p.MeasurementBinding.InstallationID != idx.InstallationID || p.MeasurementBinding.SoulID != idx.SoulID || p.MeasurementBinding.StartID != idx.StartID || p.MeasurementBinding.HostID != idx.HostID || p.MeasurementBinding.Profile != idx.Profile {
		return ErrUnqualified
	}
	if purpose == qCandidateReservationPurposeV3 {
		if p.Attempt == nil || p.Attempt.TestPlanSHA256 != idx.TestPlanSHA256 || p.Attempt.SuiteRevision != suiteRevision {
			return ErrUnqualified
		}
	} else if p.Attempt != nil {
		return ErrUnqualified
	}
	return nil
}

func qVerifyTranscriptV3(beginRaw, readyRaw []byte, requests, observations [][]byte,
	finishRaw, finishedRaw, observationFrames []byte, idx qIndexV3, eofAt time.Time) error {
	if !qExactObjectV3(beginRaw, "schema", "kind", "session_id", "challenge_base64url", "cohort_id", "installation_id", "soul_id", "start_id", "host_id", "profile", "reservation_sha256", "test_plan_sha256", "suite_revision", "ps_sha256", "path_roots", "q_uid", "q_gid", "deadline_at", "require_argv_proof") {
		return ErrUnqualified
	}
	var begin struct {
		Schema            string   `json:"schema"`
		Kind              string   `json:"kind"`
		SessionID         string   `json:"session_id"`
		Challenge         string   `json:"challenge_base64url"`
		CohortID          string   `json:"cohort_id"`
		InstallationID    string   `json:"installation_id"`
		SoulID            string   `json:"soul_id"`
		StartID           string   `json:"start_id"`
		HostID            string   `json:"host_id"`
		Profile           string   `json:"profile"`
		ReservationSHA256 string   `json:"reservation_sha256"`
		TestPlanSHA256    string   `json:"test_plan_sha256"`
		SuiteRevision     string   `json:"suite_revision"`
		PSSHA256          string   `json:"ps_sha256"`
		PathRoots         []string `json:"path_roots"`
		QUID              int      `json:"q_uid"`
		QGID              int      `json:"q_gid"`
		DeadlineAt        string   `json:"deadline_at"`
		RequireArgvProof  bool     `json:"require_argv_proof"`
	}
	if json.Unmarshal(beginRaw, &begin) != nil || begin.Schema != qSessionSchemaV3 || begin.Kind != "begin" || begin.SessionID != idx.SessionID || begin.CohortID != idx.CohortID || begin.InstallationID != idx.InstallationID || begin.SoulID != idx.SoulID || begin.StartID != idx.StartID || begin.HostID != idx.HostID || begin.Profile != idx.Profile || begin.ReservationSHA256 != idx.ReservationSHA256 || begin.TestPlanSHA256 != idx.TestPlanSHA256 || begin.QUID != idx.QUID || begin.QGID != idx.QGID || !begin.RequireArgvProof || len(begin.SuiteRevision) != 40 || !qLowerHexV3(begin.SuiteRevision) || !validSHA(begin.PSSHA256) || len(begin.PathRoots) < 1 || len(begin.PathRoots) > 16 {
		return ErrUnqualified
	}
	challenge, err := decode(begin.Challenge, 32)
	if err != nil || len(challenge) != 32 || digest(challenge) != idx.QChallengeSHA256 {
		return ErrUnqualified
	}
	deadline, err := qTimeParsedV3(begin.DeadlineAt)
	if err != nil {
		return ErrUnqualified
	}
	roots := map[string]bool{}
	for _, root := range begin.PathRoots {
		if len(root) < 2 || len(root) > 512 || !qPathV3(root) || strings.Contains(root, "..") || roots[root] {
			return ErrUnqualified
		}
		roots[root] = true
	}
	if !qExactObjectV3(readyRaw, "schema", "kind", "session_id", "challenge_sha256", "sequence", "pid", "uid", "gid", "source_sha256", "captured_at", "exec_path", "argv") {
		return ErrUnqualified
	}
	var ready struct {
		Schema          string   `json:"schema"`
		Kind            string   `json:"kind"`
		SessionID       string   `json:"session_id"`
		ChallengeSHA256 string   `json:"challenge_sha256"`
		Sequence        int      `json:"sequence"`
		PID             int      `json:"pid"`
		UID             int      `json:"uid"`
		GID             int      `json:"gid"`
		SourceSHA256    string   `json:"source_sha256"`
		CapturedAt      string   `json:"captured_at"`
		ExecPath        string   `json:"exec_path"`
		Argv            []string `json:"argv"`
	}
	// Q's challenged argv is joined to A's signed index. The separate installed
	// launchd and kernel-image evidence must still establish what actually ran.
	if json.Unmarshal(readyRaw, &ready) != nil || ready.Schema != qSessionSchemaV3 || ready.Kind != "ready" || ready.SessionID != idx.SessionID || ready.ChallengeSHA256 != idx.QChallengeSHA256 || ready.Sequence != 0 || ready.PID != idx.QPID || ready.UID != idx.QUID || ready.GID != idx.QGID || ready.SourceSHA256 != idx.QSourceSHA256 || ready.ExecPath != idx.QExecutable || !slices.Equal(ready.Argv, idx.QArgv) {
		return ErrUnqualified
	}
	last, err := qTimeParsedV3(ready.CapturedAt)
	if err != nil || !last.Before(deadline) || deadline.Sub(last) > time.Hour || last.After(eofAt) || time.Unix(idx.QStartSeconds, int64(idx.QStartMicros)*1000).After(last) || time.Unix(idx.QSocketBirthSeconds, idx.QSocketBirthNanos).After(last) {
		return ErrUnqualified
	}
	for i := range requests {
		captured, err := qVerifyPairV3(requests[i], observations[i], idx, i+1, begin.PathRoots)
		if err != nil || captured.Before(last) || captured.After(eofAt) || !captured.Before(deadline) {
			return ErrUnqualified
		}
		last = captured
	}
	if !qExactObjectV3(finishRaw, "schema", "kind", "session_id", "sequence") {
		return ErrUnqualified
	}
	var finish struct {
		Schema    string `json:"schema"`
		Kind      string `json:"kind"`
		SessionID string `json:"session_id"`
		Sequence  int    `json:"sequence"`
	}
	if json.Unmarshal(finishRaw, &finish) != nil || finish.Schema != qSessionSchemaV3 || finish.Kind != "finish" || finish.SessionID != idx.SessionID || finish.Sequence != idx.ObservationCount+1 {
		return ErrUnqualified
	}
	if !qExactObjectV3(finishedRaw, "schema", "kind", "session_id", "challenge_sha256", "sequence", "observation_count", "observations_sha256", "captured_at") {
		return ErrUnqualified
	}
	var finished struct {
		Schema             string `json:"schema"`
		Kind               string `json:"kind"`
		SessionID          string `json:"session_id"`
		ChallengeSHA256    string `json:"challenge_sha256"`
		Sequence           int    `json:"sequence"`
		ObservationCount   int    `json:"observation_count"`
		ObservationsSHA256 string `json:"observations_sha256"`
		CapturedAt         string `json:"captured_at"`
	}
	if json.Unmarshal(finishedRaw, &finished) != nil || finished.Schema != qSessionSchemaV3 || finished.Kind != "finished" || finished.SessionID != idx.SessionID || finished.ChallengeSHA256 != idx.QChallengeSHA256 || finished.Sequence != idx.ObservationCount+1 || finished.ObservationCount != idx.ObservationCount || finished.ObservationsSHA256 != digest(observationFrames) {
		return ErrUnqualified
	}
	finishedAt, err := qTimeParsedV3(finished.CapturedAt)
	if err != nil || finishedAt.Before(last) || finishedAt.After(eofAt) || !finishedAt.Before(deadline) {
		return ErrUnqualified
	}
	return nil
}

func qVerifyPairV3(requestRaw, responseRaw []byte, idx qIndexV3,
	sequence int, roots []string) (time.Time, error) {
	var refused = func() (time.Time, error) { return time.Time{}, ErrUnqualified }
	rf, err := canonicalBytes(requestRaw, qFrameMaxV3)
	if err != nil || !qFieldsWithOptionalV3(rf, "stimulus_ref", "schema", "kind", "session_id", "sequence", "gate", "phase", "event_id", "processes", "paths") {
		return refused()
	}
	of, err := canonicalBytes(responseRaw, qFrameMaxV3)
	if err != nil || !qFieldsWithOptionalV3(of, "stimulus_ref", "schema", "kind", "session_id", "challenge_sha256", "sequence", "request_sha256", "captured_at", "gate", "phase", "event_id", "processes", "paths") {
		return refused()
	}
	var req struct {
		Schema    string            `json:"schema"`
		Kind      string            `json:"kind"`
		SessionID string            `json:"session_id"`
		Sequence  int               `json:"sequence"`
		Gate      string            `json:"gate"`
		Phase     string            `json:"phase"`
		EventID   string            `json:"event_id"`
		Processes []json.RawMessage `json:"processes"`
		Paths     []json.RawMessage `json:"paths"`
	}
	var obs struct {
		Schema          string            `json:"schema"`
		Kind            string            `json:"kind"`
		SessionID       string            `json:"session_id"`
		ChallengeSHA256 string            `json:"challenge_sha256"`
		Sequence        int               `json:"sequence"`
		RequestSHA256   string            `json:"request_sha256"`
		CapturedAt      string            `json:"captured_at"`
		Gate            string            `json:"gate"`
		Phase           string            `json:"phase"`
		EventID         string            `json:"event_id"`
		Processes       []json.RawMessage `json:"processes"`
		Paths           []json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(requestRaw, &req) != nil || json.Unmarshal(responseRaw, &obs) != nil || !qJSONArrayV3(rf["processes"]) || !qJSONArrayV3(rf["paths"]) || !qJSONArrayV3(of["processes"]) || !qJSONArrayV3(of["paths"]) || req.Schema != qSessionSchemaV3 || req.Kind != "observe" || req.SessionID != idx.SessionID || req.Sequence != sequence || obs.Schema != qSessionSchemaV3 || obs.Kind != "observation" || obs.SessionID != idx.SessionID || obs.Sequence != sequence || obs.ChallengeSHA256 != idx.QChallengeSHA256 || obs.RequestSHA256 != digest(requestRaw) || obs.Gate != req.Gate || obs.Phase != req.Phase || obs.EventID != req.EventID || !qTokenV3.MatchString(req.Phase) || !qTokenV3.MatchString(req.EventID) || len(req.Processes) > 16 || len(req.Paths) > 32 || len(obs.Processes) != len(req.Processes) || len(obs.Paths) != len(req.Paths) || (idx.Profile == "managed-protected" && req.Gate == "T21") || (idx.Profile == "managed-cooperative" && req.Gate != "T21") || (req.Gate != "T01" && req.Gate != "T02" && req.Gate != "T03" && req.Gate != "T21") {
		return refused()
	}
	if (rf["stimulus_ref"] == nil) != (of["stimulus_ref"] == nil) || rf["stimulus_ref"] != nil && !bytes.Equal(rf["stimulus_ref"], of["stimulus_ref"]) {
		return refused()
	}
	if rf["stimulus_ref"] != nil {
		if !qExactObjectV3(rf["stimulus_ref"], "uri", "sha256") {
			return refused()
		}
		var stimulus struct {
			URI    string `json:"uri"`
			SHA256 string `json:"sha256"`
		}
		if json.Unmarshal(rf["stimulus_ref"], &stimulus) != nil || !qPrintableV3(stimulus.URI, 512) || !validSHA(stimulus.SHA256) {
			return refused()
		}
	}
	for i := range req.Processes {
		if qVerifyProcessV3(req.Processes[i], obs.Processes[i]) != nil {
			return refused()
		}
	}
	for i := range req.Paths {
		if qVerifyPathV3(req.Paths[i], obs.Paths[i], roots) != nil {
			return refused()
		}
	}
	captured, err := qTimeParsedV3(obs.CapturedAt)
	if err != nil {
		return refused()
	}
	return captured, nil
}

func qFieldsWithOptionalV3(fields map[string]json.RawMessage, optional string, required ...string) bool {
	if len(fields) == len(required) {
		return hasFields(fields, required...)
	}
	if len(fields) != len(required)+1 || fields[optional] == nil {
		return false
	}
	return hasFields(fields, append(required, optional)...)
}

func qJSONArrayV3(raw []byte) bool { return len(raw) >= 2 && raw[0] == '[' && raw[len(raw)-1] == ']' }

func qVerifyProcessV3(request, response []byte) error {
	if !qExactObjectV3(request, "role", "pid") || !qExactObjectV3(response, "role", "pid", "status", "stdout", "stderr") {
		return ErrUnqualified
	}
	var req struct {
		Role string `json:"role"`
		PID  int    `json:"pid"`
	}
	var obs struct {
		Role   string `json:"role"`
		PID    int    `json:"pid"`
		Status int    `json:"status"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	if json.Unmarshal(request, &req) != nil || json.Unmarshal(response, &obs) != nil || !qTokenV3.MatchString(req.Role) || req.PID <= 0 || req.PID > 2147483647 || obs.Role != req.Role || obs.PID != req.PID || obs.Status < 0 || obs.Status > 255 || len(obs.Stdout) > 2048 || len(obs.Stderr) > 2048 || !isASCII([]byte(obs.Stdout+obs.Stderr)) {
		return ErrUnqualified
	}
	return nil
}

func qVerifyPathV3(request, response []byte, roots []string) error {
	if !qExactObjectV3(request, "role", "path") {
		return ErrUnqualified
	}
	var req struct {
		Role string `json:"role"`
		Path string `json:"path"`
	}
	if json.Unmarshal(request, &req) != nil || !qTokenV3.MatchString(req.Role) || !qPathV3(req.Path) {
		return ErrUnqualified
	}
	within := false
	for _, root := range roots {
		if req.Path == root || strings.HasPrefix(req.Path, root+"/") {
			within = true
			break
		}
	}
	if !within {
		return ErrUnqualified
	}
	f, err := canonicalBytes(response, qFrameMaxV3)
	if err != nil || f["role"] == nil || f["path"] == nil || f["exists"] == nil {
		return ErrUnqualified
	}
	var obs struct {
		Role   string `json:"role"`
		Path   string `json:"path"`
		Exists *bool  `json:"exists"`
		Error  string `json:"error"`
		Dev    string `json:"dev"`
		Ino    string `json:"ino"`
		UID    int    `json:"uid"`
		GID    int    `json:"gid"`
		Mode   int    `json:"mode"`
		Type   string `json:"type"`
	}
	if json.Unmarshal(response, &obs) != nil || obs.Role != req.Role || obs.Path != req.Path {
		return ErrUnqualified
	}
	switch string(f["exists"]) {
	case "true":
		if !hasFields(f, "role", "path", "exists", "dev", "ino", "uid", "gid", "mode", "type") || !qDecimalV3(obs.Dev) || !qDecimalV3(obs.Ino) || obs.UID < 0 || obs.GID < 0 || obs.Mode < 0 || obs.Mode > 07777 || (obs.Type != "file" && obs.Type != "directory" && obs.Type != "symlink" && obs.Type != "other") {
			return ErrUnqualified
		}
	case "false", "null":
		if !hasFields(f, "role", "path", "exists", "error") || (string(f["exists"]) == "false" && obs.Error != "ENOENT" && obs.Error != "ENOTDIR") || (string(f["exists"]) == "null" && obs.Error != "EACCES" && obs.Error != "EPERM") {
			return ErrUnqualified
		}
	default:
		return ErrUnqualified
	}
	return nil
}

func qDecimalV3(s string) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
