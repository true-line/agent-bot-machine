package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aFinalizeBRequestRejectsUnboundRelayClaim(t *testing.T) {
	base := Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64),
	}
	q := Stage2aFinalizeBRequest{Stage2aStopRequest: base,
		BindReceiptSHA256: "sha256:" + strings.Repeat("d", 64),
		RelaySocket: Stage2aRelayClaim{Path: "/private/example/relay.sock",
			Socket: Stage2aKernelNodeClaim{UID: 310, GID: 311, Device: "18446744073709551615", Inode: "9007199254740993", Mode: 0660}},
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseStage2aFinalizeBRequest(raw); err != nil || parsed.RelaySocket.Socket.Inode != q.RelaySocket.Socket.Inode {
		t.Fatalf("exact decimal inode was not preserved: %+v %v", parsed, err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"bind_receipt_sha256":"sha256:`, `"bind_receipt_sha256":"`, 1),
		strings.Replace(string(raw), `"inode":"9007199254740993"`, `"inode":9007199254740993`, 1),
		strings.Replace(string(raw), `"device":"18446744073709551615"`, `"device":"18446744073709551616"`, 1),
		strings.TrimSuffix(string(raw), "}") + `,"unknown":true}`,
	} {
		if _, err := ParseStage2aFinalizeBRequest([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid relay claim: %s", bad)
		}
	}
}
