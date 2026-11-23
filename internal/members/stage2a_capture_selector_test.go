package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aCaptureSelectorRequestAcceptsOnlyChildReceiptSelectors(t *testing.T) {
	q := Stage2aCaptureSelectorRequest{Stage2aStopRequest: Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "installation-1", StartID: "st_" + strings.Repeat("b", 24),
		LaunchID: "ln_" + strings.Repeat("c", 24), PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("d", 64), HQEpoch: strings.Repeat("e", 64),
	}, ChildReceiptSHA256: "sha256:" + strings.Repeat("f", 64)}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseStage2aCaptureSelectorRequest(raw); err != nil || got != q {
		t.Fatalf("exact request refused: %+v %v", got, err)
	}
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(raw), `"child_receipt_sha256"`, `"caller_challenge"`, 1)),
		[]byte(strings.Replace(string(raw), `"sha256:`+strings.Repeat("f", 64)+`"`, `"not-a-digest"`, 1)),
		[]byte(strings.TrimSuffix(string(raw), "}") + `,"sequence":6}`),
	} {
		if _, err := ParseStage2aCaptureSelectorRequest(changed); err == nil {
			t.Fatalf("caller-selected capture field accepted: %s", changed)
		}
	}
}
