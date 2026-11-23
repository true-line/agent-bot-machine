package members

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCooperativeBObserveRequiresExactNativeAndRelayClaim(t *testing.T) {
	q := SoulCooperativeBObserveRequestV3{Stage2aStopRequest: Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)},
		BridgeAssignmentSHA256: "sha256:" + strings.Repeat("d", 64),
		BindReceiptSHA256:      "sha256:" + strings.Repeat("e", 64),
		GrantNonce:             base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		BridgePID:              4001, BridgeStartSeconds: 100, BridgeStartMicros: 42,
		RelaySocket: Stage2aRelayClaim{Path: "/private/example/relay.sock",
			Socket: Stage2aKernelNodeClaim{UID: 310, GID: 311, Device: "1", Inode: "2", Mode: 0660}}}
	raw, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeBObserveRequestV3(raw); err != nil {
		t.Fatalf("valid observation refused: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"bridge_pid":4001`, `"bridge_pid":0`, 1),
		strings.Replace(string(raw), `"bridge_start_micros":42`, `"bridge_start_micros":1000000`, 1),
		strings.Replace(string(raw), `"grant_nonce":"`+q.GrantNonce+`"`, `"grant_nonce":"invalid"`, 1),
		strings.Replace(string(raw), `"inode":"2"`, `"inode":2`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`,
	} {
		if _, err := ParseSoulCooperativeBObserveRequestV3([]byte(bad)); err == nil {
			t.Fatalf("invalid observation accepted: %s", bad)
		}
	}
}
