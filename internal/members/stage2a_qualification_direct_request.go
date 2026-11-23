package members

import (
	"bytes"
	"encoding/json"
	"io"
)

// The wire selectors are portable. Only the Darwin service can consume them
// to start the installed, OS-bound qualification observer.
type Stage2aDirectQFinishRequestV3 struct {
	SoulCooperativeLiveRequestV3
	PreResponseSHA256         string `json:"pre_response_sha256"`
	HQRefusalReceiptBase64URL string `json:"hq_refusal_receipt_base64url"`
	HQRefusalReceiptSHA256    string `json:"hq_refusal_receipt_sha256"`
}

func ParseStage2aDirectQFinishRequestV3(raw []byte) (Stage2aDirectQFinishRequestV3, error) {
	var q Stage2aDirectQFinishRequestV3
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.PreResponseSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.HQRefusalReceiptSHA256) {
		return Stage2aDirectQFinishRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}
