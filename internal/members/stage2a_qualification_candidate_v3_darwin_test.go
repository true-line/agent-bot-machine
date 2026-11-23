package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestStage2aQualificationCandidateV3ContractEnvelope(t *testing.T) {
	var candidate struct {
		Envelope     string `json:"reservation_envelope_jcs"`
		Payload      string `json:"reservation_payload_jcs"`
		SpentAttempt string `json:"spent_attempt_bytes"`
	}
	raw, err := os.ReadFile("testdata/stage2a-qualification-candidate-v3-contract.json")
	if err != nil || stage2aDecodeExact(raw, &candidate) != nil {
		t.Fatal("invalid candidate fixture", err)
	}
	var ordinary struct {
		Key string `json:"issuer_public_key_base64url"`
		At  string `json:"verification_at"`
	}
	ordinaryRaw, err := os.ReadFile("testdata/stage2a-reservation-v3-contract.json")
	if err != nil || stage2aStrictJSONBounded(ordinaryRaw, 1<<20, 65_536) != nil {
		t.Fatal("invalid ordinary fixture", err)
	}
	// The ordinary fixture holds other conformance inputs as well.
	if err := json.Unmarshal(ordinaryRaw, &ordinary); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(ordinary.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal("invalid vector key", err)
	}
	now, err := time.Parse(time.RFC3339Nano, ordinary.At)
	if err != nil {
		t.Fatal(err)
	}
	var expected stage2aQualificationCandidateReservationV3
	if err := stage2aDecodeExact([]byte(candidate.Payload), &expected); err != nil {
		t.Fatal(err)
	}
	envelope := []byte(candidate.Envelope)
	digest := stage2aReservationSHA256(envelope)
	if _, err := verifyStage2aReservationModeV3(stage2aCandidateRunV3, envelope, digest, []byte(candidate.Payload), pub, now); err != nil {
		t.Fatal("matching signed mode refused", err)
	}
	for _, mode := range []stage2aReservationRunModeV3{stage2aQualifiedRunV3, "", "machine/v2"} {
		if _, err := verifyStage2aReservationModeV3(mode, envelope, digest, []byte(candidate.Payload), pub, now); err == nil {
			t.Fatalf("mismatched or missing run mode accepted: %q", mode)
		}
	}
	if expected.Attempt.AttemptReceiptSHA256 != stage2aReservationSHA256([]byte(candidate.SpentAttempt)) {
		t.Fatal("candidate detached from exact attempt receipt")
	}
	if err := verifyStage2aQualificationCandidateV3(envelope, digest, expected, pub, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyStage2aV3Envelope(envelope, stage2aReservationPurposeV3, pub); err == nil {
		t.Fatal("ordinary protected reservation accepted candidate purpose")
	}
	if err := verifyStage2aQualificationCandidateV3(envelope, digest, expected, pub, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted expired candidate reservation")
	}
	expected.Attempt.NetworkMode = "vendor-direct"
	if err := verifyStage2aQualificationCandidateV3(envelope, digest, expected, pub, now); err == nil {
		t.Fatal("accepted changed expected network mode")
	}
}
