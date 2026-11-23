package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const soulCooperativeReservationPurposeV3 = "agent-bot/soul-cooperative-reservation/v3"

type soulCooperativeEnvelopeV3 struct {
	IssuerPublicKeyBase64URL string `json:"issuer_public_key_base64url"`
	PayloadBase64URL         string `json:"payload_base64url"`
	PayloadSHA256            string `json:"payload_sha256"`
	Purpose                  string `json:"purpose"`
	SchemaVersion            int    `json:"schema_version"`
	SignatureBase64URL       string `json:"signature_base64url"`
}

// A signs only an already validated, A-built cooperative payload. The exact
// purpose prevents a cooperative receipt being accepted as a protected one.
func signSoulCooperativeEnvelopeV3(payload []byte, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	if len(payload) == 0 || len(payload) > 1<<20 || len(key) != ed25519.PublicKeySize || sign == nil ||
		stage2aStrictJSONBounded(payload, 1<<20, stage2aV3MaxJSONNodes) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(payload)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, "", errSoulCooperativeAuthority
	}
	preimage := append([]byte(soulCooperativeReservationPurposeV3+"\x00"), payload...)
	signature, err := sign(preimage)
	if err != nil || !ed25519.Verify(key, preimage, signature) {
		return nil, "", errSoulCooperativeAuthority
	}
	envelope := soulCooperativeEnvelopeV3{
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(key),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(payload),
		PayloadSHA256:            fmt.Sprintf("sha256:%x", sha256.Sum256(payload)),
		Purpose:                  soulCooperativeReservationPurposeV3, SchemaVersion: 3,
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	canonical, err = jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 2<<20 {
		return nil, "", errSoulCooperativeAuthority
	}
	return canonical, fmt.Sprintf("sha256:%x", sha256.Sum256(canonical)), nil
}

func verifySoulCooperativeEnvelopeV3(raw []byte, key ed25519.PublicKey) ([]byte, string, error) {
	return verifySoulCooperativePurposeV3(raw, key, soulCooperativeReservationPurposeV3)
}

func verifySoulCooperativePurposeV3(raw []byte, key ed25519.PublicKey,
	purpose string) ([]byte, string, error) {
	if len(raw) == 0 || len(raw) > 2<<20 || len(key) != ed25519.PublicKeySize ||
		purpose == "" ||
		stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, "", errSoulCooperativeAuthority
	}
	var envelope soulCooperativeEnvelopeV3
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF ||
		envelope.Purpose != purpose || envelope.SchemaVersion != 3 ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(key) {
		return nil, "", errSoulCooperativeAuthority
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || len(payload) == 0 || len(payload) > 1<<20 ||
		base64.RawURLEncoding.EncodeToString(payload) != envelope.PayloadBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(payload)) != envelope.PayloadSHA256 ||
		stage2aStrictJSONBounded(payload, 1<<20, stage2aV3MaxJSONNodes) != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	canonical, err = jsoncanonicalizer.Transform(payload)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, "", errSoulCooperativeAuthority
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != envelope.SignatureBase64URL ||
		!ed25519.Verify(key, append([]byte(purpose+"\x00"), payload...), signature) {
		return nil, "", errSoulCooperativeAuthority
	}
	return payload, fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}
