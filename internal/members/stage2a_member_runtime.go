package members

import "errors"

const Stage2aMemberRuntimeLeasePurpose = "agent-bot/stage2a-member-runtime-lease/v1"

// The fixed R wrapper supplies the same peer-bound challenge fields as the
// prefinal inert-child lease. Ready is an admission anchor for first issuance;
// later renewals must prove the previous runtime lease sequence and expiry.
type Stage2aMemberRuntimeRequest struct {
	Stage2aMemberLiveRequest
	ReadyEnvelopeSHA256         string  `json:"ready_envelope_sha256"`
	HQFinalizationSHA256        string  `json:"hq_finalization_sha256"`
	PreviousLeaseEnvelopeSHA256 *string `json:"previous_lease_envelope_sha256"`
}

func ParseStage2aMemberRuntimeRequest(raw []byte) (Stage2aMemberRuntimeRequest, error) {
	var q Stage2aMemberRuntimeRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil ||
		validateStage2aMemberLiveRequest(q.Stage2aMemberLiveRequest) != nil ||
		!stage2aPrefixedDigest.MatchString(q.ReadyEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.HQFinalizationSHA256) ||
		(q.AfterSequence == 0 && q.PreviousLeaseEnvelopeSHA256 != nil) ||
		(q.AfterSequence != 0 && (q.PreviousLeaseEnvelopeSHA256 == nil ||
			!stage2aPrefixedDigest.MatchString(*q.PreviousLeaseEnvelopeSHA256))) {
		return Stage2aMemberRuntimeRequest{}, errors.New("invalid Stage 2a member runtime request")
	}
	return q, nil
}
