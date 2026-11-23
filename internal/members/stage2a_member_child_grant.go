package members

import (
	"encoding/base64"
	"errors"
)

// H relays an already-running R-UID child's challenge plus the exact assigned
// member name. A observes the wrapper and binds the selected member itself.
type Stage2aMemberChildGrantRequest struct {
	Stage2aStopRequest
	MemberID       string `json:"member_id"`
	MemberSelector string `json:"member_selector"`
	Nonce          string `json:"nonce"`
	PID            int    `json:"pid"`
}

func ParseStage2aMemberChildGrantRequest(raw []byte) (Stage2aMemberChildGrantRequest, error) {
	var q Stage2aMemberChildGrantRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aBindingID.MatchString(q.MemberID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) || q.PID <= 1 {
		return Stage2aMemberChildGrantRequest{}, errors.New("invalid Stage 2a member child grant request")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	if err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce {
		return Stage2aMemberChildGrantRequest{}, errors.New("invalid Stage 2a member child nonce")
	}
	return q, nil
}
