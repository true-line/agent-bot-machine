package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCooperativeMemberPolicyRequiresObservedB(t *testing.T) {
	q := SoulCooperativeMemberPolicyRequestV3{Stage2aStopRequest: Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)},
		BridgeObservedSHA256: "sha256:" + strings.Repeat("d", 64)}
	raw, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeMemberPolicyRequestV3(raw); err != nil {
		t.Fatalf("valid observed-B selector refused: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), q.BridgeObservedSHA256, "sha256:bad", 1),
		strings.TrimSuffix(string(raw), "}") + `,"unreviewed":true}`,
	} {
		if _, err := ParseSoulCooperativeMemberPolicyRequestV3([]byte(bad)); err == nil {
			t.Fatalf("invalid member policy request accepted: %s", bad)
		}
	}
}
