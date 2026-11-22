//go:build darwin

package members

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"time"
)

// stage2aQualificationSessionResultV1 can only be created after A has paired
// each outbound request with Q's response and checked Q's final transcript.
// It is still raw observation input, not physical corroboration or T credit.
type stage2aQualificationSessionResultV1 struct {
	begin              stage2aQualificationBeginV1
	peer               stage2aQualificationPeerV1
	beginFrame         []byte
	readyFrame         []byte
	finishedFrame      []byte
	sourceSHA256       string
	challengeSHA256    string
	requestFrames      []byte
	observationFrames  []byte
	requestsSHA256     string
	observationsSHA256 string
	count              int
	validated          bool
}

func verifyStage2aQualificationPairedFramesV1(result stage2aQualificationSessionResultV1) error {
	if !result.validated || result.count < 1 || result.count > 128 ||
		result.observationsSHA256 != stage2aQualificationSHA256(result.observationFrames) ||
		result.requestsSHA256 != stage2aQualificationSHA256(result.requestFrames) {
		return errStage2aReservationAuthority
	}
	beginReader := bytes.NewReader(result.beginFrame)
	beginRaw, err := readStage2aQualificationFrame(beginReader)
	if err != nil || beginReader.Len() != 0 || stage2aQualificationCanonical(result.readyFrame) != nil {
		return errStage2aReservationAuthority
	}
	var begin stage2aQualificationBeginV1
	var ready stage2aQualificationReadyV1
	var readyFields map[string]json.RawMessage
	challenge, decodeErr := base64.RawURLEncoding.Strict().DecodeString(result.begin.ChallengeBase64URL)
	canonicalBegin, canonicalErr := marshalStage2aReservationJCS(result.begin)
	if canonicalErr != nil || !bytes.Equal(beginRaw, canonicalBegin) ||
		json.Unmarshal(beginRaw, &begin) != nil || !reflect.DeepEqual(begin, result.begin) ||
		json.Unmarshal(result.readyFrame, &readyFields) != nil || len(readyFields) != 10 ||
		json.Unmarshal(result.readyFrame, &ready) != nil || decodeErr != nil || len(challenge) != 32 ||
		ready.Schema != stage2aQualificationSchemaV1 || ready.Kind != "ready" ||
		ready.SessionID != begin.SessionID || ready.ChallengeSHA256 != stage2aQualificationSHA256(challenge) ||
		ready.ChallengeSHA256 != result.challengeSHA256 || ready.Sequence != 0 ||
		ready.PID != result.peer.pid || ready.UID != result.peer.uid || ready.GID != result.peer.gid ||
		ready.SourceSHA256 != result.sourceSHA256 ||
		!stage2aQualificationTimestampV1.MatchString(ready.CapturedAt) {
		return errStage2aReservationAuthority
	}
	lastCaptured, err := time.Parse(time.RFC3339Nano, ready.CapturedAt)
	if err != nil {
		return errStage2aReservationAuthority
	}
	requests := bytes.NewReader(result.requestFrames)
	responses := bytes.NewReader(result.observationFrames)
	for sequence := 1; sequence <= result.count; sequence++ {
		requestRaw, err := readStage2aQualificationFrame(requests)
		if err != nil {
			return errStage2aReservationAuthority
		}
		responseRaw, err := readStage2aQualificationFrame(responses)
		if err != nil || validateStage2aQualificationObservationV1(requestRaw, responseRaw,
			result.begin.SessionID, result.challengeSHA256, sequence, result.begin.Profile,
			result.begin.PathRoots) != nil {
			return errStage2aReservationAuthority
		}
		var observed struct {
			CapturedAt string `json:"captured_at"`
		}
		if json.Unmarshal(responseRaw, &observed) != nil {
			return errStage2aReservationAuthority
		}
		captured, err := time.Parse(time.RFC3339Nano, observed.CapturedAt)
		if err != nil || captured.Before(lastCaptured) {
			return errStage2aReservationAuthority
		}
		lastCaptured = captured
	}
	if requests.Len() != 0 || responses.Len() != 0 {
		return errStage2aReservationAuthority
	}
	finishedAt, err := parseStage2aQualificationFinishedV1(result.finishedFrame,
		result.begin.SessionID, result.challengeSHA256, result.count+1, result.count,
		result.observationsSHA256)
	if err != nil || finishedAt.Before(lastCaptured) {
		return errStage2aReservationAuthority
	}
	return nil
}

func parseStage2aQualificationFinishedV1(raw []byte, sessionID, challengeSHA string,
	sequence, count int, observationsSHA string) (time.Time, error) {
	if _, err := stage2aQualificationKeysV1(raw, []string{"schema", "kind", "session_id",
		"challenge_sha256", "sequence", "observation_count", "observations_sha256", "captured_at"}, ""); err != nil {
		return time.Time{}, errStage2aReservationAuthority
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
	if json.Unmarshal(raw, &finished) != nil || finished.Schema != stage2aQualificationSchemaV1 ||
		finished.Kind != "finished" || finished.SessionID != sessionID ||
		finished.ChallengeSHA256 != challengeSHA || finished.Sequence != sequence ||
		finished.ObservationCount != count || finished.ObservationsSHA256 != observationsSHA ||
		!stage2aQualificationTimestampV1.MatchString(finished.CapturedAt) {
		return time.Time{}, errStage2aReservationAuthority
	}
	captured, err := time.Parse(time.RFC3339Nano, finished.CapturedAt)
	if err != nil {
		return time.Time{}, errStage2aReservationAuthority
	}
	return captured, nil
}

func (s *stage2aQualificationSessionV1) close() {
	if s != nil && !s.closed {
		s.closed = true
		if s.conn != nil {
			s.conn.Close()
		}
	}
}

func (s *stage2aQualificationSessionV1) setFrameDeadline() error {
	if s == nil || s.closed || s.conn == nil || s.peer.recheck() != nil ||
		s.sequence < 1 || s.sequence > 1024 || time.Since(s.started) >= time.Hour {
		return errStage2aReservationAuthority
	}
	limit, err := time.Parse(time.RFC3339Nano, s.begin.DeadlineAt)
	if err != nil || !time.Now().Before(limit) {
		return errStage2aReservationAuthority
	}
	deadline := time.Now().Add(60 * time.Second)
	if limit.Before(deadline) {
		deadline = limit
	}
	if s.conn.SetDeadline(deadline) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}

// observe sends one A-selected request, checks Q's raw response against the
// exact outbound bytes, and retains both length-prefixed frames for offline
// pairing. A must choose these probes from its owner-reviewed physical plan.
func (s *stage2aQualificationSessionV1) observe(request stage2aQualificationObserveV1) ([]byte, error) {
	if s == nil || s.observationCount >= 128 || s.setFrameDeadline() != nil {
		if s != nil {
			s.close()
		}
		return nil, errStage2aReservationAuthority
	}
	request.Schema = stage2aQualificationSchemaV1
	request.Kind = "observe"
	request.SessionID = s.begin.SessionID
	request.Sequence = s.sequence
	requestFrame, err := writeStage2aQualificationFrame(s.conn, request)
	if err != nil {
		s.close()
		return nil, errStage2aReservationAuthority
	}
	responseRaw, err := readStage2aQualificationFrame(s.conn)
	if err != nil || s.peer.recheck() != nil ||
		validateStage2aQualificationObservationV1(requestFrame[4:], responseRaw,
			s.begin.SessionID, s.challengeSHA256, s.sequence, s.begin.Profile, s.begin.PathRoots) != nil {
		s.close()
		return nil, errStage2aReservationAuthority
	}
	var observed struct {
		CapturedAt string `json:"captured_at"`
	}
	if json.Unmarshal(responseRaw, &observed) != nil {
		s.close()
		return nil, errStage2aReservationAuthority
	}
	captured, err := time.Parse(time.RFC3339Nano, observed.CapturedAt)
	if err != nil || captured.Before(s.lastCaptured) || captured.Before(s.started.Add(-time.Second)) ||
		captured.After(time.Now().Add(time.Second)) {
		s.close()
		return nil, errStage2aReservationAuthority
	}
	s.lastCaptured = captured
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(responseRaw)))
	s.requests.Write(requestFrame)
	s.observations.Write(header[:])
	s.observations.Write(responseRaw)
	s.observationCount++
	s.sequence++
	return append([]byte(nil), responseRaw...), nil
}

// finish validates Q's count and digest over the exact observed wire frames.
// It requires Q to close the stream and consumes the authenticated session.
func (s *stage2aQualificationSessionV1) finish() (stage2aQualificationSessionResultV1, error) {
	var zero stage2aQualificationSessionResultV1
	if s == nil || s.observationCount == 0 || s.setFrameDeadline() != nil {
		if s != nil {
			s.close()
		}
		return zero, errStage2aReservationAuthority
	}
	defer s.close()
	finish := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "finish",
		"session_id": s.begin.SessionID, "sequence": s.sequence}
	if _, err := writeStage2aQualificationFrame(s.conn, finish); err != nil {
		return zero, errStage2aReservationAuthority
	}
	raw, err := readStage2aQualificationFrame(s.conn)
	if err != nil {
		return zero, errStage2aReservationAuthority
	}
	observationsSHA := stage2aQualificationSHA256(s.observations.Bytes())
	captured, err := parseStage2aQualificationFinishedV1(raw, s.begin.SessionID,
		s.challengeSHA256, s.sequence, s.observationCount, observationsSHA)
	if err != nil || captured.Before(s.lastCaptured) || captured.After(time.Now().Add(time.Second)) {
		return zero, errStage2aReservationAuthority
	}
	if s.conn.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		return zero, errStage2aReservationAuthority
	}
	var trailing [1]byte
	if n, err := s.conn.Read(trailing[:]); n != 0 || err != io.EOF {
		return zero, errStage2aReservationAuthority
	}
	return stage2aQualificationSessionResultV1{
		begin: s.begin, peer: s.peer, sourceSHA256: s.sourceSHA256,
		beginFrame: bytes.Clone(s.beginFrame), readyFrame: bytes.Clone(s.readyFrame),
		finishedFrame:   bytes.Clone(raw),
		challengeSHA256: s.challengeSHA256,
		requestFrames:   bytes.Clone(s.requests.Bytes()), observationFrames: bytes.Clone(s.observations.Bytes()),
		requestsSHA256:     stage2aQualificationSHA256(s.requests.Bytes()),
		observationsSHA256: observationsSHA, count: s.observationCount, validated: true,
	}, nil
}
