package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Stage2aReserveRequest is the complete variable input to Machine's protected
// start reservation. Installed authority selects every principal and path.
type Stage2aReserveRequest struct {
	PlanDigest     string `json:"plan_digest"`
	InstallationID string `json:"installation_id"`
	StartID        string `json:"start_id"`
	HQEpoch        string `json:"hq_epoch"`
	LaunchID       string `json:"launch_id"`
}

// ParseStage2aReserveRequest refuses duplicate, missing and extra fields. A
// bounded base64url string carries these bytes in Machine's signed transport.
func ParseStage2aReserveRequest(raw []byte) (Stage2aReserveRequest, error) {
	invalid := errors.New("invalid Stage 2a reserve request")
	if len(raw) == 0 || len(raw) > 2048 {
		return Stage2aReserveRequest{}, invalid
	}
	var request Stage2aReserveRequest
	fields := map[string]*string{
		"plan_digest": &request.PlanDigest, "installation_id": &request.InstallationID,
		"start_id": &request.StartID, "hq_epoch": &request.HQEpoch, "launch_id": &request.LaunchID,
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return Stage2aReserveRequest{}, invalid
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		target := fields[name]
		if err != nil || !ok || target == nil || decoder.Decode(target) != nil {
			return Stage2aReserveRequest{}, invalid
		}
		delete(fields, name)
	}
	end, err := decoder.Token()
	if len(fields) != 0 || err != nil || end != json.Delim('}') {
		return Stage2aReserveRequest{}, invalid
	}
	if _, err := decoder.Token(); err != io.EOF ||
		!(SoulRunRequest{PlanDigest: request.PlanDigest, InstallationID: request.InstallationID,
			StartID: request.StartID, HQEpoch: request.HQEpoch}).valid() ||
		!soulLaunchID.MatchString(request.LaunchID) {
		return Stage2aReserveRequest{}, invalid
	}
	return request, nil
}
