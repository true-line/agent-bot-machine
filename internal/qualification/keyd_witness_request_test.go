package qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestKeydWitnessRequestBindsMachineAndLivePair(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ownerX, ownerY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 1, 2, 3, 0, time.UTC)
	input := KeydWitnessRequestInput{
		Mode: "sign", HostID: "fixture-host", MachinePub: base64.StdEncoding.EncodeToString(public),
		HQPub: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		HQUid: 504, HQEpoch: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		PairOwnerPub: base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), ownerX, ownerY)),
		OwnerRootHex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OwnerKeyID:   "fixture-root", PolicyEnvelope: []byte(`{}`), Challenge: bytes.Repeat([]byte{6}, 32),
		TrustedTime: true,
	}
	raw, err := BuildKeydWitnessRequest(input, private, now)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	sigText, ok := object["signature_base64url"].(string)
	if !ok {
		t.Fatal("missing signature")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil {
		t.Fatal(err)
	}
	delete(object, "signature_base64url")
	payload, err := json.Marshal(object)
	if err != nil || !ed25519.Verify(public, preimage(KeydWitnessRequestPurpose, payload), sig) {
		t.Fatal("Machine transcript does not verify")
	}
	if got := object["challenge_base64url"]; got != base64.RawURLEncoding.EncodeToString(input.Challenge) {
		t.Fatalf("challenge = %v", got)
	}
	for name, changed := range map[string]func(*KeydWitnessRequestInput){
		"untrusted time": func(v *KeydWitnessRequestInput) { v.TrustedTime = false },
		"other Machine":  func(v *KeydWitnessRequestInput) { v.MachinePub = v.HQPub },
		"bad owner point": func(v *KeydWitnessRequestInput) {
			v.PairOwnerPub = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 65))
		},
		"short challenge": func(v *KeydWitnessRequestInput) { v.Challenge = []byte{6} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := input
			changed(&bad)
			if _, err := BuildKeydWitnessRequest(bad, private, now); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
	input.Mode, input.Challenge = "init", nil
	if _, err := BuildKeydWitnessRequest(input, private, now); err != nil {
		t.Fatal(err)
	}
	input.Mode, input.PolicyEnvelope = "pin", nil
	if _, err := BuildKeydWitnessRequest(input, private, now); err != nil {
		t.Fatal(err)
	}
}
