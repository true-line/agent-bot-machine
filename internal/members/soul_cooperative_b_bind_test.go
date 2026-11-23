package members

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSoulCooperativeBBindV3SeparatesProfileAndSelectors(t *testing.T) {
	q := SoulCooperativeBVerifyRequestV3{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		BridgeAssignmentSHA256: "sha256:" + strings.Repeat("b", 64), InstallationID: "soul-one",
		StartID: "st_" + strings.Repeat("b", 24), LaunchID: "ln_" + strings.Repeat("c", 24),
		PlanID: "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("d", 64), HQEpoch: strings.Repeat("e", 64),
		Nonce: strings.Repeat("f", 64), Proof: strings.Repeat("0", 64)}
	preimage, err := soulCooperativeBBindPreimageV3(q, 310, "/private/var/example/broker.sock")
	if err != nil || strings.Count(string(preimage), "\x00") != 11 ||
		!strings.HasPrefix(string(preimage), soulCooperativeBBindContextV3+"\x00") ||
		strings.HasSuffix(string(preimage), "\x00") {
		t.Fatalf("invalid cooperative bind preimage: %v", err)
	}
	key := []byte(strings.Repeat("x", 32))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(preimage)
	q.Proof = hex.EncodeToString(mac.Sum(nil))
	if err := verifySoulCooperativeBBindV3(key, q, 310, "/private/var/example/broker.sock"); err != nil {
		t.Fatalf("valid cooperative bind refused: %v", err)
	}
	raw, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeBVerifyRequestV3(raw); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	q.BridgeAssignmentSHA256 = "sha256:" + strings.Repeat("c", 64)
	if verifySoulCooperativeBBindV3(key, q, 310, "/private/var/example/broker.sock") == nil {
		t.Fatal("different bridge assignment accepted")
	}
	q.BridgeAssignmentSHA256 = "sha256:" + strings.Repeat("b", 64)
	if verifySoulCooperativeBBindV3(key, q, 311, "/private/var/example/broker.sock") == nil {
		t.Fatal("different B UID accepted")
	}
}
