package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aChildReadyRequestRejectsWrongRoleOrReplayShape(t *testing.T) {
	q := Stage2aChildReadyRequest{Stage2aStopRequest: Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)},
		ChildLauncherPID: 4561, ChildPID: 4562, GrantSHA256: "sha256:" + strings.Repeat("d", 64)}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aChildReadyRequest(raw); err != nil {
		t.Fatalf("valid child readiness refused: %v", err)
	}
	q.ChildPID = q.ChildLauncherPID
	raw, _ = json.Marshal(q)
	if _, err := ParseStage2aChildReadyRequest(raw); err == nil {
		t.Fatal("wrapper self-claim accepted as stock child")
	}
	q.ChildPID = 4562
	raw, _ = json.Marshal(q)
	raw = append(raw[:len(raw)-1], []byte(`,"child_pid":4563}`)...)
	if _, err := ParseStage2aChildReadyRequest(raw); err == nil {
		t.Fatal("duplicate child PID accepted")
	}
}
