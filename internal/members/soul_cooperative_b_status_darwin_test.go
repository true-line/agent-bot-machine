//go:build darwin

package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCooperativeBStatusCarriesNativeBindAndGrant(t *testing.T) {
	status := soulCooperativeBStatusV3{BridgePID: 4001, BridgeStartSeconds: 100,
		BridgeStartMicros: 42, GrantNonce: strings.Repeat("a", 43)}
	status.BindReceipt = "sha256:" + strings.Repeat("b", 64)
	status.RelaySocket.UID, status.RelaySocket.GID = 310, 311
	status.RelaySocket.Device, status.RelaySocket.Inode, status.RelaySocket.Mode = 1, 2, 0660
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"bind_receipt_sha256"`, `"relay_socket"`,
		`"bridge_pid"`, `"bridge_start_seconds"`, `"bridge_start_micros"`, `"grant_nonce"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("cooperative status missing %s: %s", key, raw)
		}
	}
}
