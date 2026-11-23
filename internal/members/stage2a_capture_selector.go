package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// HQ may request a selector only for A's already observed ChildReady. It
// contributes no challenge, Q session, sequence or target to this request.
type Stage2aCaptureSelectorRequest struct {
	Stage2aStopRequest
	ChildReceiptSHA256 string `json:"child_receipt_sha256"`
}

func ParseStage2aCaptureSelectorRequest(raw []byte) (Stage2aCaptureSelectorRequest, error) {
	var q Stage2aCaptureSelectorRequest
	invalid := errors.New("invalid Stage 2a capture selector request")
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, invalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || dec.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.ChildReceiptSHA256) {
		return Stage2aCaptureSelectorRequest{}, invalid
	}
	return q, nil
}
