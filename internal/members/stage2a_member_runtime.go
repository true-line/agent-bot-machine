package members

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

const Stage2aMemberRuntimeLeasePurpose = "agent-bot/stage2a-member-runtime-lease/v1"

// The fixed R wrapper supplies the same peer-bound challenge fields as the
// prefinal inert-child lease. Ready is an admission anchor for first issuance;
// later renewals must prove the previous runtime lease sequence and expiry.
type Stage2aMemberRuntimeRequest struct {
	Stage2aMemberLiveRequest
	ReadyEnvelopeSHA256         string  `json:"ready_envelope_sha256"`
	HQFinalizationSHA256        string  `json:"hq_finalization_sha256"`
	HQFinalizationBase64URL     string  `json:"hq_finalization_base64url"`
	PreviousLeaseEnvelopeSHA256 *string `json:"previous_lease_envelope_sha256"`
}

func ParseStage2aMemberRuntimeRequest(raw []byte) (Stage2aMemberRuntimeRequest, error) {
	var q Stage2aMemberRuntimeRequest
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil ||
		validateStage2aMemberLiveRequest(q.Stage2aMemberLiveRequest) != nil ||
		!stage2aPrefixedDigest.MatchString(q.ReadyEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.HQFinalizationSHA256) ||
		(q.AfterSequence == 0 && q.PreviousLeaseEnvelopeSHA256 != nil) ||
		(q.AfterSequence != 0 && (q.PreviousLeaseEnvelopeSHA256 == nil ||
			!stage2aPrefixedDigest.MatchString(*q.PreviousLeaseEnvelopeSHA256))) {
		return Stage2aMemberRuntimeRequest{}, errors.New("invalid Stage 2a member runtime request")
	}
	if _, err := stage2aDecodeHQFinalizationRecord(q.HQFinalizationBase64URL,
		q.HQFinalizationSHA256); err != nil {
		return Stage2aMemberRuntimeRequest{}, err
	}
	return q, nil
}

func stage2aDecodeHQFinalizationRecord(encoded, digest string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(8192) ||
		!stage2aPrefixedDigest.MatchString(digest) {
		return nil, errors.New("invalid Stage 2a HQ finalization record")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 8192 ||
		base64.RawURLEncoding.EncodeToString(raw) != encoded ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != digest ||
		stage2aStrictJSON(raw) != nil {
		return nil, errors.New("invalid Stage 2a HQ finalization record")
	}
	return raw, nil
}
