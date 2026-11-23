package members

import (
	"encoding/json"
	"errors"
)

const Stage2aMemberReadyPurpose = "agent-bot/stage2a-member-set-ready/v1"

// H relays both exact B arm exchanges recorded on the already bound broker
// stream. A independently joins them to its signed two-child observation,
// cached B policy and live kernel processes before signing aggregate Ready.
type Stage2aMemberReadyRequest struct {
	Stage2aStopRequest
	ChildObservationEnvelopeSHA256 string                     `json:"child_observation_envelope_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                     `json:"member_b_authority_envelope_sha256"`
	Arms                           []Stage2aMemberArmExchange `json:"arms"`
}

type Stage2aMemberArmExchange struct {
	ArmRequest json.RawMessage `json:"arm_request"`
	ArmResult  json.RawMessage `json:"arm_result"`
}

func ParseStage2aMemberReadyRequest(raw []byte) (Stage2aMemberReadyRequest, error) {
	var q Stage2aMemberReadyRequest
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.ChildObservationEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.MemberBAuthorityEnvelopeSHA256) ||
		len(q.Arms) != 2 {
		return Stage2aMemberReadyRequest{}, errors.New("invalid Stage 2a two-member Ready request")
	}
	for _, arm := range q.Arms {
		if len(arm.ArmRequest) == 0 || len(arm.ArmRequest) > 4096 ||
			len(arm.ArmResult) == 0 || len(arm.ArmResult) > 2048 ||
			stage2aStrictJSON(arm.ArmRequest) != nil || stage2aStrictJSON(arm.ArmResult) != nil {
			return Stage2aMemberReadyRequest{}, errors.New("invalid Stage 2a member arm exchange")
		}
	}
	return q, nil
}
