package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/qwts/managed-machine/internal/members"
)

const membersPlansVerb = "members-plans"

var errMembersPlans = errors.New("members plans unavailable")

func decodeSavedMembersPlan(id string, raw []byte) (members.Saved, []byte, error) {
	var saved members.Saved
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&saved) != nil || dec.Decode(new(any)) != io.EOF || saved.PlanID != id || !members.ValidApproval(id, saved.PlanDigest) {
		return members.Saved{}, nil, errMembersPlans
	}
	canonical, err := saved.Plan.Canonical()
	sum := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(sum[:]) != saved.PlanDigest {
		return members.Saved{}, nil, errMembersPlans
	}
	return saved, canonical, nil
}

func membersPlanBody(id string, raw []byte) ([]byte, error) {
	saved, canonical, err := decodeSavedMembersPlan(id, raw)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		ID        string `json:"plan_id"`
		Digest    string `json:"plan_digest"`
		Canonical string `json:"plan_canonical"`
	}{id, saved.PlanDigest, string(canonical)})
	if err != nil || len(body) > maxMessage-1024 { // signed response envelope and bounded request nonce
		return nil, errMembersPlans
	}
	return body, nil
}
