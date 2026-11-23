package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type SoulCooperativeLiveRequestV3 struct {
	Stage2aStopRequest
	AttachSHA256 string `json:"attach_sha256"`
}

func ParseSoulCooperativeLiveRequestV3(raw []byte) (SoulCooperativeLiveRequestV3, error) {
	var q SoulCooperativeLiveRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid cooperative liveness request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) {
		return SoulCooperativeLiveRequestV3{}, errors.New("invalid cooperative liveness request")
	}
	return q, nil
}
