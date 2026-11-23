package members

import (
	"bytes"
	"encoding/json"
	"io"
)

type SoulCooperativeMemberPolicyRequestV3 struct {
	Stage2aStopRequest
	BridgeObservedSHA256 string `json:"bridge_observed_sha256"`
}

type SoulCooperativeMemberPolicyReplyV3 struct {
	MemberSetAssignmentEnvelopeBase64URL string `json:"member_set_assignment_envelope_base64url"`
	MemberSetAssignmentSHA256            string `json:"member_set_assignment_sha256"`
	MemberBAuthorityEnvelopeBase64URL    string `json:"member_b_authority_envelope_base64url"`
	MemberBAuthoritySHA256               string `json:"member_b_authority_sha256"`
	BridgeObservedSHA256                 string `json:"bridge_observed_sha256"`
}

func ParseSoulCooperativeMemberPolicyRequestV3(raw []byte) (SoulCooperativeMemberPolicyRequestV3, error) {
	var q SoulCooperativeMemberPolicyRequestV3
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.BridgeObservedSHA256) {
		return SoulCooperativeMemberPolicyRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
