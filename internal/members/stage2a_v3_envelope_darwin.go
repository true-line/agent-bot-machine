//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	stage2aHDescriptorPurposeV3 = "agent-bot/stage2a-h-service-descriptor/v3"
	stage2aReservationPurposeV3 = "agent-bot/stage2a-reservation/v3"
	stage2aV3EnvelopeLimit      = 64 << 10
	stage2aV3PayloadLimit       = 48 << 10
)

// stage2aVerifiedSigningPayloadV3 is constructed only after A has reopened and
// compared the final installed inputs with the owner-reviewed plan. It is not
// constructible from an HQ request or a shape-valid JSON document alone.
type stage2aVerifiedSigningPayloadV3 struct {
	verified               bool
	purpose                string
	payload                []byte
	machineUID, machineGID uint32
}

type stage2aV3PayloadHeader struct {
	Contract      string `json:"contract"`
	Kind          string `json:"kind"`
	SchemaVersion int    `json:"schema_version"`
}

func stage2aV3PurposeKind(purpose string) string {
	switch purpose {
	case stage2aHDescriptorPurposeV3:
		return "stage2a-h-service-descriptor"
	case stage2aReservationPurposeV3:
		return "stage2a-reservation"
	default:
		return ""
	}
}

func stage2aV3CanonicalPayload(raw []byte, purpose string) error {
	if stage2aV3PurposeKind(purpose) == "" || len(raw) == 0 || len(raw) > stage2aV3PayloadLimit ||
		stage2aStrictJSON(raw) != nil {
		return errStage2aReservationAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errStage2aReservationAuthority
	}
	var header stage2aV3PayloadHeader
	if json.Unmarshal(raw, &header) != nil || header.Contract != "machine/v3" ||
		header.Kind != stage2aV3PurposeKind(purpose) || header.SchemaVersion != 3 {
		return errStage2aReservationAuthority
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return errStage2aReservationAuthority
	}
	fields := []string{"contract", "kind", "schema_version"}
	if purpose == stage2aHDescriptorPurposeV3 {
		fields = append(fields, "host_id", "hq_installation_id", "owner_plan_digest",
			"h_inventory", "components", "outer_launch", "runtime")
	} else {
		fields = append(fields, "host_id", "issued_at", "expires_at",
			"installed_plan_receipt_sha256", "assignment", "member_endpoint",
			"measurement_binding", "admission_challenge_sha256")
	}
	if len(object) != len(fields) {
		return errStage2aReservationAuthority
	}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(value, []byte("null")) {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func stage2aV3PurposeDigest(purpose string, payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte(purpose+"\x00"), payload...)))
}

// signStage2aVerifiedEnvelopeV3 has no public request route. The producer must
// supply a proof from final A-owned remeasurement, and this call only signs in
// the secure administrator account with its independently enrolled key.
func signStage2aVerifiedEnvelopeV3(value stage2aVerifiedSigningPayloadV3,
	enrolledKey ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	if !value.verified || value.machineUID < 400 || value.machineGID == 0 ||
		uint32(os.Getuid()) != value.machineUID || uint32(os.Geteuid()) != value.machineUID ||
		uint32(os.Getgid()) != value.machineGID || uint32(os.Getegid()) != value.machineGID ||
		len(enrolledKey) != ed25519.PublicKeySize || sign == nil ||
		stage2aV3CanonicalPayload(value.payload, value.purpose) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	preimage := append([]byte(value.purpose+"\x00"), value.payload...)
	key := bytes.Clone(enrolledKey)
	signature, err := sign(bytes.Clone(preimage))
	if err != nil || !ed25519.Verify(key, preimage, signature) {
		return nil, "", errStage2aReservationAuthority
	}
	envelope, err := marshalStage2aReservationJCS(stage2aSignedReservation{
		SchemaVersion: 3, Purpose: value.purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(key),
		PayloadSHA256:            stage2aReservationSHA256(value.payload),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(value.payload),
		SignatureBase64URL:       base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil || len(envelope) > stage2aV3EnvelopeLimit {
		return nil, "", errStage2aReservationAuthority
	}
	return envelope, stage2aV3PurposeDigest(value.purpose, value.payload), nil
}

// verifyStage2aV3Envelope authenticates canonical bytes with an independently
// pinned A key. The returned payload still needs its owner plan, released
// files, H/R identities and one-use lifecycle checked by its specific reader.
func verifyStage2aV3Envelope(raw []byte, purpose string,
	enrolledKey ed25519.PublicKey) ([]byte, string, error) {
	if stage2aV3PurposeKind(purpose) == "" || len(raw) == 0 ||
		len(raw) > stage2aV3EnvelopeLimit || len(enrolledKey) != ed25519.PublicKeySize ||
		stage2aStrictJSON(raw) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	var envelope stage2aSignedReservation
	if stage2aDecodeExact(raw, &envelope) != nil || envelope.SchemaVersion != 3 ||
		envelope.Purpose != purpose || envelope.IssuerPublicKeyBase64URL !=
		base64.RawURLEncoding.EncodeToString(enrolledKey) {
		return nil, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, "", errStage2aReservationAuthority
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != envelope.PayloadBase64URL ||
		stage2aReservationSHA256(payload) != envelope.PayloadSHA256 ||
		stage2aV3CanonicalPayload(payload, purpose) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(sig) != envelope.SignatureBase64URL ||
		!ed25519.Verify(enrolledKey, append([]byte(purpose+"\x00"), payload...), sig) {
		return nil, "", errStage2aReservationAuthority
	}
	return payload, stage2aV3PurposeDigest(purpose, payload), nil
}
