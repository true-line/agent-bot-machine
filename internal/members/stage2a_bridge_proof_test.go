package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aBridgeBindMatchesIndependentHMACVector(t *testing.T) {
	q := Stage2aVerifyBRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("d", 64),
		InstallationID:    "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567",
		PlanID:   "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("c", 64),
		HQEpoch: strings.Repeat("b", 64), Challenge: strings.Repeat("a", 64),
		Proof: "aa81ffd66d44449ee14f44fcee8bb7a209b0adb3045cd73190af0d9ab5267b6e",
	}
	a := SoulStartAssignment{
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch,
		BridgeUID: 331,
		Broker:    SoulStartEndpoint{SocketPath: "/var/agent-bot-hq/ipc/_abm-br-soul-one/broker.sock"},
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := verifyStage2aBridgeBind(key, q, a); err != nil {
		t.Fatalf("independent Python HMAC vector refused: %v", err)
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseStage2aVerifyBRequest(raw); err != nil || got != q {
		t.Fatalf("valid B selector refused: %+v %v", got, err)
	}
	changed := q
	changed.Challenge = strings.Repeat("e", 64)
	if err := verifyStage2aBridgeBind(key, changed, a); err == nil {
		t.Fatal("proof replayed against a different challenge")
	}
	changed = q
	changed.ReservationSHA256 = "sha256:" + strings.Repeat("e", 64)
	if err := verifyStage2aBridgeBind(key, changed, a); err == nil {
		t.Fatal("proof replayed against a different reservation")
	}
	changed = q
	changed.Proof = strings.ToUpper(q.Proof)
	if raw, err := json.Marshal(changed); err != nil {
		t.Fatal(err)
	} else if _, err := ParseStage2aVerifyBRequest(raw); err == nil {
		t.Fatal("noncanonical uppercase proof accepted")
	}
	if _, err := ParseStage2aVerifyBRequest(append(raw[:len(raw)-1], []byte(`,"proof":"`+q.Proof+`"}`)...)); err == nil {
		t.Fatal("duplicate proof field accepted")
	}
}
