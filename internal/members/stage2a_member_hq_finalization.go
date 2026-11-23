package members

import "errors"

const Stage2aMemberHQFinalizationAckPurpose = "agent-bot/stage2a-member-finalization-ack/v1"

type Stage2aMemberHQFinalizationRequest struct {
	Stage2aStopRequest
	FinalizationBase64URL string `json:"finalization_base64url"`
	FinalizationSHA256    string `json:"finalization_sha256"`
}

func ParseStage2aMemberHQFinalizationRequest(raw []byte) (Stage2aMemberHQFinalizationRequest, error) {
	var q Stage2aMemberHQFinalizationRequest
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) {
		return Stage2aMemberHQFinalizationRequest{}, errors.New("invalid Stage 2a HQ member finalization request")
	}
	if _, err := stage2aDecodeHQFinalizationRecord(q.FinalizationBase64URL,
		q.FinalizationSHA256); err != nil {
		return Stage2aMemberHQFinalizationRequest{}, err
	}
	return q, nil
}
