package members

import (
	"encoding/base64"
	"time"
)

const SoulCooperativeBLivePurposeV3 = "agent-bot/soul-cooperative-b-live-lease/v3"

type SoulCooperativeBLiveRequestV3 struct {
	Stage2aStopRequest
	BridgeObservedSHA256    string `json:"bridge_observed_sha256"`
	ReadySHA256             string `json:"ready_sha256"`
	BridgePID               int    `json:"bridge_pid"`
	BridgeStartSeconds      int64  `json:"bridge_start_seconds"`
	BridgeStartMicros       int32  `json:"bridge_start_micros"`
	ChallengeNonceBase64URL string `json:"challenge_nonce_base64url"`
	AfterSequence           uint64 `json:"after_sequence"`
	PriorExpiresAt          string `json:"prior_expires_at"`
}

type SoulCooperativeBLiveReplyV3 struct {
	ReadyEnvelopeBase64URL          string `json:"ready_envelope_base64url,omitempty"`
	ReadySHA256                     string `json:"ready_sha256,omitempty"`
	BridgeObservedEnvelopeBase64URL string `json:"bridge_observed_envelope_base64url,omitempty"`
	BridgeObservedSHA256            string `json:"bridge_observed_sha256,omitempty"`
	LeaseEnvelopeBase64URL          string `json:"lease_envelope_base64url"`
	LeaseSHA256                     string `json:"lease_sha256"`
	LeaseSequence                   uint64 `json:"lease_sequence"`
}

func ParseSoulCooperativeBLiveRequestV3(raw []byte) (SoulCooperativeBLiveRequestV3, error) {
	var q SoulCooperativeBLiveRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeObservedSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.ReadySHA256) ||
		q.BridgePID <= 1 || q.BridgeStartSeconds <= 0 ||
		q.BridgeStartMicros < 0 || q.BridgeStartMicros >= 1_000_000 ||
		q.AfterSequence >= (1<<53)-1 {
		return SoulCooperativeBLiveRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.ChallengeNonceBase64URL)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != q.ChallengeNonceBase64URL {
		return SoulCooperativeBLiveRequestV3{}, errSoulCooperativeAuthority
	}
	prior, err := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
	if err != nil || prior.IsZero() {
		return SoulCooperativeBLiveRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
