//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestStage2aQualificationObservationBindsRequestAndUnknownPath(t *testing.T) {
	session := strings.Repeat("a", 32)
	challenge := "sha256:" + strings.Repeat("b", 64)
	ref := map[string]any{"uri": "fixture:acp-capture", "sha256": "sha256:" + strings.Repeat("c", 64)}
	request := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observe", "session_id": session,
		"sequence": 1, "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes":    []any{map[string]any{"role": "runner", "pid": 42}},
		"paths":        []any{map[string]any{"role": "member", "path": "/private/approved/member.sock"}},
		"stimulus_ref": ref}
	reqRaw, err := marshalStage2aReservationJCS(request)
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{"schema": stage2aQualificationSchemaV1, "kind": "observation", "session_id": session,
		"challenge_sha256": challenge, "sequence": 1, "request_sha256": stage2aQualificationSHA256(reqRaw),
		"captured_at": "2026-11-22T20:00:00.120Z", "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes":    []any{map[string]any{"role": "runner", "pid": 42, "status": 0, "stdout": "42 451 452 node\n", "stderr": ""}},
		"paths":        []any{map[string]any{"role": "member", "path": "/private/approved/member.sock", "exists": nil, "error": "EACCES"}},
		"stimulus_ref": ref}
	check := func() error {
		raw, err := marshalStage2aReservationJCS(response)
		if err != nil {
			return err
		}
		return validateStage2aQualificationObservationV1(reqRaw, raw, session, challenge, 1, "managed-protected", []string{"/private/approved"})
	}
	if err := check(); err != nil {
		t.Fatal("Q-compatible unknown observation refused", err)
	}
	response["captured_at"] = "2026-99-99T20:00:00.120Z"
	if check() == nil {
		t.Fatal("impossible Q observation timestamp accepted")
	}
	response["captured_at"] = "2026-11-22T20:00:00.120Z"
	delete(response, "stimulus_ref")
	if check() == nil {
		t.Fatal("missing ACP reference echo accepted")
	}
	response["stimulus_ref"] = ref
	response["paths"].([]any)[0].(map[string]any)["exists"] = false
	if check() == nil {
		t.Fatal("permission denied falsely treated as absent")
	}
	response["paths"].([]any)[0].(map[string]any)["exists"] = nil
	if raw, err := marshalStage2aReservationJCS(response); err != nil || validateStage2aQualificationObservationV1(reqRaw, raw, session, challenge, 1, "managed-protected", []string{"/private/other"}) == nil {
		t.Fatal("path outside reviewed root accepted")
	}
	request["processes"].([]any)[0].(map[string]any)["extra"] = "unreviewed"
	mutatedRequest := mustStage2aQualificationJSON(t, request)
	response["request_sha256"] = stage2aQualificationSHA256(mutatedRequest)
	if validateStage2aQualificationObservationV1(mutatedRequest, mustStage2aQualificationJSON(t, response), session, challenge, 1, "managed-protected", []string{"/private/approved"}) == nil {
		t.Fatal("unknown process request field accepted")
	}
}

func mustStage2aQualificationJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := marshalStage2aReservationJCS(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
