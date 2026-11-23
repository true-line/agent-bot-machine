//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

const stage2aInnerACPCaptureSelectorSchemaV1 = "agent-bot-machine/stage2a-inner-acp-capture-selector/v1"

// This selector is an A-signed capability for one already reviewed protected
// start and one Q session. Its caller must retain that live Q session and
// consume a separate durable one-use claim before releasing these bytes to HQ.
type stage2aInnerACPCaptureSelectorV1 struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	SessionID          string `json:"session_id"`
	Sequence           int    `json:"sequence"`
	TestPlanSHA256     string `json:"test_plan_sha256"`
	ChallengeBase64URL string `json:"challenge_base64url"`
	ExpiresAtMS        int64  `json:"expires_at_ms"`
}

type stage2aSignedInnerACPCaptureSelectorV1 struct {
	Selector           stage2aInnerACPCaptureSelectorV1 `json:"selector"`
	SignatureBase64URL string                           `json:"signature_base64url"`
}

func validStage2aInnerACPCaptureSelectorV1(q stage2aInnerACPCaptureSelectorV1, now time.Time) bool {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.ChallengeBase64URL)
	return q.Schema == stage2aInnerACPCaptureSelectorSchemaV1 &&
		validStage2aStopRequest(q.Stage2aStopRequest) &&
		len(q.SessionID) == 32 && stage2aQualificationHex(q.SessionID) &&
		q.Sequence > 0 && q.Sequence <= 1024 &&
		stage2aQualificationDigest(q.TestPlanSHA256) &&
		err == nil && len(challenge) == 32 &&
		base64.RawURLEncoding.EncodeToString(challenge) == q.ChallengeBase64URL &&
		q.ExpiresAtMS > now.UnixMilli() &&
		q.ExpiresAtMS <= now.Add(120*time.Second).UnixMilli()
}

func stage2aInnerACPCaptureSelectorPreimageV1(canonical []byte) []byte {
	return append([]byte(stage2aInnerACPCaptureSelectorSchemaV1+"\x00"), canonical...)
}

func signStage2aInnerACPCaptureSelectorV1(q stage2aInnerACPCaptureSelectorV1,
	now time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	if len(key) != ed25519.PublicKeySize || sign == nil || !validStage2aInnerACPCaptureSelectorV1(q, now) {
		return nil, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(q)
	if err != nil || len(canonical) > 2048 {
		return nil, "", errStage2aReservationAuthority
	}
	signature, err := sign(stage2aInnerACPCaptureSelectorPreimageV1(canonical))
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, stage2aInnerACPCaptureSelectorPreimageV1(canonical), signature) ||
		!time.Now().Before(time.UnixMilli(q.ExpiresAtMS)) {
		return nil, "", errStage2aReservationAuthority
	}
	wire, err := marshalStage2aReservationJCS(stage2aSignedInnerACPCaptureSelectorV1{
		Selector: q, SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil || len(wire) > 4096 {
		return nil, "", errStage2aReservationAuthority
	}
	return wire, stage2aQualificationSHA256(canonical), nil
}

func verifyStage2aInnerACPCaptureSelectorV1(raw []byte, key ed25519.PublicKey,
	now time.Time) (stage2aInnerACPCaptureSelectorV1, string, error) {
	var empty stage2aInnerACPCaptureSelectorV1
	if len(raw) == 0 || len(raw) > 4096 || len(key) != ed25519.PublicKeySize ||
		stage2aStrictJSON(raw) != nil {
		return empty, "", errStage2aReservationAuthority
	}
	var signed stage2aSignedInnerACPCaptureSelectorV1
	if stage2aDecodeExact(raw, &signed) != nil || !validStage2aInnerACPCaptureSelectorV1(signed.Selector, now) {
		return empty, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(signed.Selector)
	if err != nil || len(canonical) > 2048 {
		return empty, "", errStage2aReservationAuthority
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signed.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != signed.SignatureBase64URL ||
		!ed25519.Verify(key, stage2aInnerACPCaptureSelectorPreimageV1(canonical), signature) {
		return empty, "", errStage2aReservationAuthority
	}
	canonicalWire, err := marshalStage2aReservationJCS(signed)
	if err != nil || !bytes.Equal(raw, canonicalWire) {
		return empty, "", errStage2aReservationAuthority
	}
	return signed.Selector, stage2aQualificationSHA256(canonical), nil
}
