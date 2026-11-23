//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type stage2aContractVectorV3 struct {
	SeedHex                string `json:"seed_hex"`
	HPayloadJCS            string `json:"h_payload_jcs"`
	HEnvelopeJCS           string `json:"h_envelope_jcs"`
	HDescriptorDigest      string `json:"h_descriptor_digest"`
	ReservationPayloadJCS  string `json:"reservation_payload_jcs"`
	ReservationEnvelopeJCS string `json:"reservation_envelope_jcs"`
}

func stage2aLoadContractVectorV3(t *testing.T) (stage2aContractVectorV3, ed25519.PrivateKey) {
	t.Helper()
	raw, err := os.ReadFile("testdata/stage2a-machine-hr-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector stage2aContractVectorV3
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid public Contracts v3 synthetic vector")
	}
	seed, err := hex.DecodeString(vector.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("invalid public synthetic seed")
	}
	return vector, ed25519.NewKeyFromSeed(seed)
}

func TestStage2aV3FixedPurposeEnvelope(t *testing.T) {
	vector, key := stage2aLoadContractVectorV3(t)
	pub := key.Public().(ed25519.PublicKey)
	sign := func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }
	for _, test := range []struct{ purpose, kind, payload, envelope string }{
		{stage2aHDescriptorPurposeV3, "stage2a-h-service-descriptor", vector.HPayloadJCS, vector.HEnvelopeJCS},
		{stage2aReservationPurposeV3, "stage2a-reservation", vector.ReservationPayloadJCS, vector.ReservationEnvelopeJCS},
	} {
		t.Run(test.kind, func(t *testing.T) {
			payload := []byte(test.payload)
			proof := stage2aVerifiedSigningPayloadV3{
				verified: true, purpose: test.purpose, payload: payload,
				machineUID: uint32(os.Getuid()), machineGID: uint32(os.Getgid()),
			}
			envelope, digest, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign)
			if err != nil || digest != stage2aV3PurposeDigest(test.purpose, payload) {
				t.Fatalf("sign fixed v3 envelope: %v", err)
			}
			if !bytes.Equal(envelope, []byte(test.envelope)) {
				t.Fatal("Machine signed bytes differ from Contracts v3 exact vector")
			}
			if test.purpose == stage2aHDescriptorPurposeV3 && digest != vector.HDescriptorDigest {
				t.Fatal("Machine H descriptor digest differs from Contracts v3")
			}
			got, gotDigest, err := verifyStage2aV3Envelope(envelope, test.purpose, pub)
			if err != nil || !bytes.Equal(got, payload) || gotDigest != digest {
				t.Fatalf("verify fixed v3 envelope: %v", err)
			}
			if _, _, err := verifyStage2aV3Envelope(envelope, test.purpose, bytes.Repeat([]byte{0}, 32)); err == nil {
				t.Fatal("envelope accepted a substituted A key")
			}
			otherPurpose := stage2aReservationPurposeV3
			if test.purpose == otherPurpose {
				otherPurpose = stage2aHDescriptorPurposeV3
			}
			if _, _, err := verifyStage2aV3Envelope(envelope, otherPurpose, pub); err == nil {
				t.Fatal("envelope accepted a different fixed purpose")
			}
			var decoded stage2aSignedReservation
			if err := json.Unmarshal(envelope, &decoded); err != nil {
				t.Fatal(err)
			}
			decoded.SignatureBase64URL = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0}, ed25519.SignatureSize))
			changed, _ := marshalStage2aReservationJCS(decoded)
			if _, _, err := verifyStage2aV3Envelope(changed, test.purpose, pub); err == nil {
				t.Fatal("envelope accepted an invalid A signature")
			}
			proof.machineUID++
			if _, _, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign); err == nil {
				t.Fatal("signer accepted another effective UID")
			}
			proof.machineUID--
			proof.verified = false
			if _, _, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign); err == nil {
				t.Fatal("signer accepted unverified installed inputs")
			}
		})
	}
}

func TestStage2aV3EnvelopeRejectsDowngradeAndNoncanonicalPayload(t *testing.T) {
	vector, key := stage2aLoadContractVectorV3(t)
	pub := key.Public().(ed25519.PublicKey)
	sign := func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }
	proof := stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aHDescriptorPurposeV3,
		machineUID: uint32(os.Getuid()), machineGID: uint32(os.Getgid()),
		payload: []byte(vector.HPayloadJCS),
	}
	proof.payload = bytes.Replace(proof.payload, []byte(`"contract":"machine/v3"`), []byte(`"contract":"machine/v2"`), 1)
	if _, _, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign); err == nil {
		t.Fatal("signed downgraded H descriptor")
	}
	proof.payload = append([]byte{' '}, []byte(vector.HPayloadJCS)...)
	if _, _, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign); err == nil {
		t.Fatal("signed noncanonical H descriptor")
	}
	proof.payload = []byte(`{"contract":"machine/v3","contract":"machine/v3","kind":"stage2a-h-service-descriptor","schema_version":3}`)
	if _, _, err := signStage2aVerifiedEnvelopeV3(proof, pub, sign); err == nil {
		t.Fatal("signed duplicate-key H descriptor")
	}
	proof.payload = []byte(vector.HPayloadJCS)
	_, _, err := signStage2aVerifiedEnvelopeV3(proof, pub,
		func([]byte) ([]byte, error) { return bytes.Repeat([]byte{0}, ed25519.SignatureSize), nil })
	if err == nil {
		t.Fatal("signer accepted a different private key")
	}
}
