//go:build darwin

package members

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const stage2aQualificationSchemaV1 = "soul-conformance/qualification-session/v1"

var stage2aQualificationTimestampV1 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$`)

type stage2aQualificationBeginV1 struct {
	Schema             string   `json:"schema"`
	Kind               string   `json:"kind"`
	SessionID          string   `json:"session_id"`
	ChallengeBase64URL string   `json:"challenge_base64url"`
	CohortID           string   `json:"cohort_id"`
	InstallationID     string   `json:"installation_id"`
	SoulID             string   `json:"soul_id"`
	StartID            string   `json:"start_id"`
	HostID             string   `json:"host_id"`
	Profile            string   `json:"profile"`
	ReservationSHA256  string   `json:"reservation_sha256"`
	TestPlanSHA256     string   `json:"test_plan_sha256"`
	SuiteRevision      string   `json:"suite_revision"`
	PSSHA256           string   `json:"ps_sha256"`
	PathRoots          []string `json:"path_roots"`
	QUID               int      `json:"q_uid"`
	QGID               int      `json:"q_gid"`
	DeadlineAt         string   `json:"deadline_at"`
}

type stage2aQualificationReadyV1 struct {
	Schema          string `json:"schema"`
	Kind            string `json:"kind"`
	SessionID       string `json:"session_id"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	Sequence        int    `json:"sequence"`
	PID             int    `json:"pid"`
	UID             int    `json:"uid"`
	GID             int    `json:"gid"`
	SourceSHA256    string `json:"source_sha256"`
	CapturedAt      string `json:"captured_at"`
}

type stage2aQualificationSessionV1 struct {
	conn             *net.UnixConn
	peer             stage2aQualificationPeerV1
	begin            stage2aQualificationBeginV1
	beginFrame       []byte
	readyFrame       []byte
	challengeSHA256  string
	sourceSHA256     string
	sequence         int
	observationCount int
	requests         bytes.Buffer
	observations     bytes.Buffer
	closed           bool
	lastCaptured     time.Time
	started          time.Time
}

func stage2aQualificationSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stage2aQualificationDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && stage2aLowerHex64(strings.TrimPrefix(s, "sha256:"))
}

func validStage2aQualificationBeginV1(b stage2aQualificationBeginV1, now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, b.DeadlineAt)
	if err != nil || now.IsZero() || !deadline.After(now) || deadline.After(now.Add(time.Hour)) ||
		!stage2aQualificationTimestampV1.MatchString(b.DeadlineAt) ||
		b.Schema != stage2aQualificationSchemaV1 || b.Kind != "begin" ||
		len(b.SessionID) != 32 || !stage2aQualificationHex(b.SessionID) ||
		!soulInstallationID.MatchString(b.InstallationID) || !soulIdentity.MatchString(b.SoulID) ||
		!soulStartID.MatchString(b.StartID) || !stage2aQualificationPrintable(b.CohortID, 128) ||
		!stage2aQualificationPrintable(b.HostID, 128) ||
		(b.Profile != "managed-protected" && b.Profile != "managed-cooperative") ||
		!stage2aQualificationDigest(b.ReservationSHA256) || !stage2aQualificationDigest(b.TestPlanSHA256) ||
		len(b.SuiteRevision) != 40 || !stage2aQualificationHex(b.SuiteRevision) ||
		!stage2aQualificationDigest(b.PSSHA256) || b.QUID <= 399 || b.QGID <= 0 ||
		b.QUID > 2147483647 || b.QGID > 2147483647 ||
		len(b.PathRoots) == 0 || len(b.PathRoots) > 16 {
		return false
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(b.ChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != b.ChallengeBase64URL {
		return false
	}
	seen := make(map[string]bool, len(b.PathRoots))
	for _, root := range b.PathRoots {
		if len(root) < 2 || len(root) > 512 || !stage2aAbsolutePath(root) || filepath.Clean(root) != root || strings.Contains(root, "..") {
			return false
		}
		if seen[root] {
			return false
		}
		seen[root] = true
		for _, c := range root {
			if c > 0x7e || c < 0x20 {
				return false
			}
		}
	}
	return true
}

func stage2aQualificationHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func stage2aQualificationPrintable(s string, max int) bool {
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

// beginStage2aQualificationSessionV1 reveals the challenge only after A has
// authenticated the accepted Q peer. Ready binds that challenge, exact Q
// identity and pinned source digest; it is never a test verdict.
func beginStage2aQualificationSessionV1(conn *net.UnixConn, peer stage2aQualificationPeerV1,
	input stage2aQualificationBeginV1, expectedSourceSHA256 string, now time.Time) (*stage2aQualificationSessionV1, error) {
	if conn == nil || peer.recheck() != nil || !stage2aQualificationDigest(expectedSourceSHA256) ||
		input.QUID != peer.uid || input.QGID != peer.gid {
		return nil, errStage2aReservationAuthority
	}
	var session [16]byte
	var challenge [32]byte
	if _, err := rand.Read(session[:]); err != nil {
		return nil, errStage2aReservationAuthority
	}
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, errStage2aReservationAuthority
	}
	input.Schema = stage2aQualificationSchemaV1
	input.Kind = "begin"
	input.SessionID = hex.EncodeToString(session[:])
	input.ChallengeBase64URL = base64.RawURLEncoding.EncodeToString(challenge[:])
	if !validStage2aQualificationBeginV1(input, now) {
		return nil, errStage2aReservationAuthority
	}
	if conn.SetDeadline(now.Add(10*time.Second)) != nil {
		return nil, errStage2aReservationAuthority
	}
	beginFrame, err := writeStage2aQualificationFrame(conn, input)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	raw, readyFrame, err := readStage2aQualificationObservedFrame(conn)
	if err != nil || peer.recheck() != nil {
		return nil, errStage2aReservationAuthority
	}
	var fields map[string]json.RawMessage
	var ready stage2aQualificationReadyV1
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 10 || json.Unmarshal(raw, &ready) != nil ||
		ready.Schema != stage2aQualificationSchemaV1 || ready.Kind != "ready" ||
		ready.SessionID != input.SessionID || ready.ChallengeSHA256 != stage2aQualificationSHA256(challenge[:]) ||
		ready.Sequence != 0 || ready.PID != peer.pid || ready.UID != peer.uid || ready.GID != peer.gid ||
		ready.SourceSHA256 != expectedSourceSHA256 {
		return nil, errStage2aReservationAuthority
	}
	captured, err := time.Parse(time.RFC3339Nano, ready.CapturedAt)
	if err != nil || !stage2aQualificationTimestampV1.MatchString(ready.CapturedAt) ||
		captured.Before(now.Add(-10*time.Second)) || captured.After(time.Now().Add(time.Second)) {
		return nil, errStage2aReservationAuthority
	}
	if conn.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		return nil, errStage2aReservationAuthority
	}
	return &stage2aQualificationSessionV1{conn: conn, peer: peer, begin: input,
		beginFrame: beginFrame, readyFrame: bytes.Clone(readyFrame),
		challengeSHA256: ready.ChallengeSHA256, sourceSHA256: expectedSourceSHA256,
		sequence: 1, lastCaptured: captured, started: now}, nil
}
