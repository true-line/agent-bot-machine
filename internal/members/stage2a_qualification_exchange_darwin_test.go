//go:build darwin

package members

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
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
	result.readyFrame = mustStage2aQualificationJSON(t, map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "ready", "session_id": sessionID,
		"challenge_sha256": result.challengeSHA256, "sequence": 0,
		"pid": 42, "uid": 501, "gid": 20, "source_sha256": result.sourceSHA256,
		"captured_at": "2026-11-22T20:00:00.120Z",
	})
	if err := verifyStage2aQualificationPairedFramesV1(result); err != nil {
		t.Fatal("valid paired frames refused", err)
	}
	response["gate"] = "T02"
	observations.Reset()
	if _, err := writeStage2aQualificationFrame(&observations, response); err != nil {
		t.Fatal(err)
	}
	result.observationFrames = bytes.Clone(observations.Bytes())
	result.observationsSHA256 = stage2aQualificationSHA256(result.observationFrames)
	if verifyStage2aQualificationPairedFramesV1(result) == nil {
		t.Fatal("spliced response with recomputed transcript digest accepted")
	}
}
