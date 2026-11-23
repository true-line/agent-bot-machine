package members

import "encoding/json"

type SoulCooperativeMemberReadyRequestV3 struct {
	Stage2aStopRequest
	ChildObservationEnvelopeSHA256 string                         `json:"child_observation_envelope_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                         `json:"member_b_authority_envelope_sha256"`
	BridgeObservedSHA256           string                         `json:"bridge_observed_sha256"`
	Arms                           []SoulCooperativeArmExchangeV3 `json:"arms"`
}

type SoulCooperativeArmExchangeV3 struct {
	ArmRequest json.RawMessage `json:"arm_request"`
	ArmResult  json.RawMessage `json:"arm_result"`
}

func ParseSoulCooperativeMemberReadyRequestV3(raw []byte) (SoulCooperativeMemberReadyRequestV3, error) {
	var q SoulCooperativeMemberReadyRequestV3
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.ChildObservationEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.MemberBAuthorityEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeObservedSHA256) || len(q.Arms) != 2 {
		return SoulCooperativeMemberReadyRequestV3{}, errSoulCooperativeAuthority
	}
	for _, arm := range q.Arms {
		if len(arm.ArmRequest) == 0 || len(arm.ArmRequest) > 4096 ||
			len(arm.ArmResult) == 0 || len(arm.ArmResult) > 2048 ||
			stage2aStrictJSON(arm.ArmRequest) != nil || stage2aStrictJSON(arm.ArmResult) != nil {
			return SoulCooperativeMemberReadyRequestV3{}, errSoulCooperativeAuthority
		}
	}
	return q, nil
}
