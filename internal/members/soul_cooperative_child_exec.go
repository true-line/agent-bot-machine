package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
)

type SoulCooperativeChildExecRequestV3 struct {
	Stage2aStopRequest
	MemberID       string `json:"member_id"`
	MemberLaunchID string `json:"member_launch_id"`
	MemberSelector string `json:"member_selector"`
	Nonce          string `json:"nonce"`
	PID            int    `json:"pid"`
}

func ParseSoulCooperativeChildExecRequestV3(raw []byte) (SoulCooperativeChildExecRequestV3, error) {
	var q SoulCooperativeChildExecRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		(q.MemberID != "m_lead" && q.MemberID != "m_spec") ||
		!soulLaunchID.MatchString(q.MemberLaunchID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) || q.PID <= 1 {
		return SoulCooperativeChildExecRequestV3{}, errSoulCooperativeAuthority
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce {
		return SoulCooperativeChildExecRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
