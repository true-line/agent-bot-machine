package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const Stage2aStopPurpose = "agent-bot/stage2a-stop/v1"

type Stage2aStopRequest struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	PlanID            string `json:"plan_id"`
	PlanDigest        string `json:"plan_digest"`
	HQEpoch           string `json:"hq_epoch"`
}
type Stage2aStopReply struct {
	EnvelopeBase64URL string `json:"envelope_base64url"`
	SHA256            string `json:"sha256"`
}
type Stage2aStopPayload struct {
	Schema             string `json:"schema"`
	ReservationSHA256  string `json:"reservation_sha256"`
	InstallationID     string `json:"installation_id"`
	StartID            string `json:"start_id"`
	LaunchID           string `json:"launch_id"`
	PlanID             string `json:"plan_id"`
	PlanDigest         string `json:"plan_digest"`
	HQEpoch            string `json:"hq_epoch"`
	RunnerUID          int    `json:"runner_uid"`
	BridgeUID          int    `json:"bridge_uid"`
	RunnerPID          int    `json:"runner_pid"`
	BridgePID          int    `json:"bridge_pid"`
	ChildLauncherPID   int    `json:"child_launcher_pid,omitempty"`
	ChildPID           int    `json:"child_pid,omitempty"`
	ChildReceiptSHA256 string `json:"child_receipt_sha256,omitempty"`
	BothUIDsIdle       bool   `json:"both_uids_idle"`
	StoppedAt          string `json:"stopped_at"`
}

func ParseStage2aStopRequest(raw []byte) (Stage2aStopRequest, error) {
	var q Stage2aStopRequest
	if len(raw) == 0 || len(raw) > 2048 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a stop request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !validStage2aStopRequest(q) {
		return Stage2aStopRequest{}, errors.New("invalid Stage 2a stop request")
	}
	return q, nil
}
func validStage2aStopRequest(q Stage2aStopRequest) bool {
	return strings.HasPrefix(q.ReservationSHA256, "sha256:") && stage2aLowerHex64(strings.TrimPrefix(q.ReservationSHA256, "sha256:")) &&
		soulInstallationID.MatchString(q.InstallationID) && soulStartID.MatchString(q.StartID) &&
		soulLaunchID.MatchString(q.LaunchID) && ValidApproval(q.PlanID, q.PlanDigest) && soulHQEpoch.MatchString(q.HQEpoch)
}
