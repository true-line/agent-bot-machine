package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

type Stage2aLookupRequest struct {
	PackagePath string `json:"package_path"`
}

type Stage2aLookupReply struct {
	InstallationID string `json:"installation_id"`
	PlanID         string `json:"plan_id"`
	PlanDigest     string `json:"plan_digest"`
	RunnerAccount  string `json:"runner_account"`
	BridgeAccount  string `json:"bridge_account"`
}

func ParseStage2aLookupRequest(raw []byte) (Stage2aLookupRequest, error) {
	var q Stage2aLookupRequest
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a installed lookup")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || !stage2aLookupPath(q.PackagePath) {
		return Stage2aLookupRequest{}, errors.New("invalid Stage 2a installed lookup")
	}
	return q, nil
}

func stage2aLookupPath(value string) bool {
	return len(value) > 1 && len(value) <= 4096 && utf8.ValidString(value) &&
		value[0] == '/' && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}
