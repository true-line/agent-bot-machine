//go:build darwin

package members

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestStage2aQualificationPairedFramesRejectSplice(t *testing.T) {
	sessionID := strings.Repeat("a", 32)
	challenge := "sha256:" + strings.Repeat("b", 64)
	request := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observe",
		"session_id": sessionID, "sequence": 1, "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes": []any{}, "paths": []any{}}
	var requests, observations bytes.Buffer
	requestFrame, err := writeStage2aQualificationFrame(&requests, request)
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observation",
		"session_id": sessionID, "challenge_sha256": challenge, "sequence": 1,
		"request_sha256": stage2aQualificationSHA256(requestFrame[4:]),
		"captured_at":    "2026-11-22T20:00:00.120Z", "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes": []any{}, "paths": []any{}}
	if _, err := writeStage2aQualificationFrame(&observations, response); err != nil {
		t.Fatal(err)
	}
	result := stage2aQualificationSessionResultV1{
		begin: stage2aQualificationBeginV1{Schema: stage2aQualificationSchemaV1, Kind: "begin",
			SessionID: sessionID, ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xbb}, 32)),
			Profile: "managed-protected", PathRoots: []string{"/private/tmp"}},
		peer:            stage2aQualificationPeerV1{pid: 42, uid: 501, gid: 20},
		sourceSHA256:    "sha256:" + strings.Repeat("c", 64),
		challengeSHA256: challenge, requestFrames: bytes.Clone(requests.Bytes()),
		observationFrames: bytes.Clone(observations.Bytes()), count: 1, validated: true,
		cleanEOFObserved: true, eofObservedAt: time.Date(2026, 11, 22, 20, 0, 1, 0, time.UTC),
	}
	result.requestsSHA256 = stage2aQualificationSHA256(result.requestFrames)
	result.observationsSHA256 = stage2aQualificationSHA256(result.observationFrames)
	// The test challenge digest must be derived from the exact begin bytes.
	result.challengeSHA256 = stage2aQualificationSHA256(bytes.Repeat([]byte{0xbb}, 32))
	response["challenge_sha256"] = result.challengeSHA256
	observations.Reset()
	if _, err := writeStage2aQualificationFrame(&observations, response); err != nil {
		t.Fatal(err)
	}
	result.observationFrames = bytes.Clone(observations.Bytes())
	result.observationsSHA256 = stage2aQualificationSHA256(result.observationFrames)
	var handshake bytes.Buffer
	result.beginFrame, err = writeStage2aQualificationFrame(&handshake, result.begin)
	if err != nil {
		t.Fatal(err)
	}
	result.readyFrame = mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "ready", "session_id": sessionID,
		"challenge_sha256": result.challengeSHA256, "sequence": 0,
		"pid": 42, "uid": 501, "gid": 20, "source_sha256": result.sourceSHA256,
		"captured_at": "2026-11-22T20:00:00.120Z",
	})
	finished := map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "finished", "session_id": sessionID,
		"challenge_sha256": result.challengeSHA256, "sequence": 2,
		"observation_count": 1, "observations_sha256": result.observationsSHA256,
		"captured_at": "2026-11-22T20:00:00.120Z",
	}
	result.finishRequestFrame = mustStage2aQualificationFrame(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "finish", "session_id": sessionID,
		"sequence": 2,
	})
	result.finishedFrame = mustStage2aQualificationFrame(t, finished)
	if err := verifyStage2aQualificationPairedFramesV1(result); err != nil {
		t.Fatal("valid paired frames refused", err)
	}
	missingEOF := result
	missingEOF.cleanEOFObserved = false
	if verifyStage2aQualificationPairedFramesV1(missingEOF) == nil {
		t.Fatal("Q session without A-observed clean EOF accepted")
	}
	earlyEOF := result
	earlyEOF.eofObservedAt = time.Date(2026, 11, 22, 19, 59, 59, 0, time.UTC)
	if verifyStage2aQualificationPairedFramesV1(earlyEOF) == nil {
		t.Fatal("A-observed EOF timestamp before Q finished accepted")
	}
	unframed := result
	unframed.readyFrame = mustStage2aQualificationJSON(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "ready", "session_id": sessionID,
		"challenge_sha256": result.challengeSHA256, "sequence": 0,
		"pid": 42, "uid": 501, "gid": 20, "source_sha256": result.sourceSHA256,
		"captured_at": "2026-11-22T20:00:00.120Z",
	})
	if verifyStage2aQualificationPairedFramesV1(unframed) == nil {
		t.Fatal("ready payload without observed length header accepted")
	}
	finished["captured_at"] = "2026-11-22T20:00:00.119Z"
	result.finishedFrame = mustStage2aQualificationFrame(t, finished)
	if verifyStage2aQualificationPairedFramesV1(result) == nil {
		t.Fatal("finished frame before observation accepted")
	}
	finished["captured_at"] = "2026-11-22T20:00:00.120Z"
	finished["observations_sha256"] = "sha256:" + strings.Repeat("d", 64)
	result.finishedFrame = mustStage2aQualificationFrame(t, finished)
	if verifyStage2aQualificationPairedFramesV1(result) == nil {
		t.Fatal("finished frame with another transcript digest accepted")
	}
	finished["observations_sha256"] = result.observationsSHA256
	response["gate"] = "T02"
	observations.Reset()
	if _, err := writeStage2aQualificationFrame(&observations, response); err != nil {
		t.Fatal(err)
	}
	result.observationFrames = bytes.Clone(observations.Bytes())
	result.observationsSHA256 = stage2aQualificationSHA256(result.observationFrames)
	finished["observations_sha256"] = result.observationsSHA256
	result.finishedFrame = mustStage2aQualificationFrame(t, finished)
	if verifyStage2aQualificationPairedFramesV1(result) == nil {
		t.Fatal("spliced response with recomputed transcript digest accepted")
	}
	response["gate"] = "T01"
	response["captured_at"] = "2026-11-22T19:59:59.999Z"
	observations.Reset()
	if _, err := writeStage2aQualificationFrame(&observations, response); err != nil {
		t.Fatal(err)
	}
	result.observationFrames = bytes.Clone(observations.Bytes())
	result.observationsSHA256 = stage2aQualificationSHA256(result.observationFrames)
	finished["observations_sha256"] = result.observationsSHA256
	result.finishedFrame = mustStage2aQualificationFrame(t, finished)
	if verifyStage2aQualificationPairedFramesV1(result) == nil {
		t.Fatal("observation before ready accepted")
	}
}
