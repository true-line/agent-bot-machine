package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const Stage2aChildStartPurpose = "agent-bot/stage2a-child-start/v1"

type Stage2aChildReadyRequest struct {
	Stage2aStopRequest
	ChildLauncherPID int    `json:"child_launcher_pid"`
	ChildPID         int    `json:"child_pid"`
	GrantSHA256      string `json:"grant_sha256"`
}

type Stage2aChildReadyReply struct {
	EnvelopeBase64URL string `json:"envelope_base64url"`
	SHA256            string `json:"sha256"`
	ExpiresAtMS       int64  `json:"expires_at_ms"`
}

type Stage2aChildStartPayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	FinalizationSHA256      string                            `json:"finalization_sha256"`
	HelloFinalizationSHA256 string                            `json:"hello_finalization_sha256"`
	BindReceiptSHA256       string                            `json:"bind_receipt_sha256"`
	GrantSHA256             string                            `json:"grant_sha256"`
	Runner                  Stage2aLiveRoleIdentity           `json:"runner"`
	Bridge                  Stage2aLiveRoleIdentity           `json:"bridge"`
	ChildLauncher           Stage2aLiveRoleIdentity           `json:"child_launcher"`
	Child                   Stage2aLiveRoleIdentity           `json:"child"`
	Executable              string                            `json:"executable"`
	ExecutableSHA256        string                            `json:"executable_sha256"`
	SandboxPath             string                            `json:"sandbox_path"`
	SandboxSHA256           string                            `json:"sandbox_sha256"`
	RelaySocket             string                            `json:"relay_socket"`
	EnvironmentSHA256       string                            `json:"environment_sha256"`
	ProtectedControlProbe   *Stage2aProtectedControlProbeSpec `json:"protected_control_probe,omitempty"`
	StartedAtMS             int64                             `json:"started_at_ms"`
	ExpiresAtMS             int64                             `json:"expires_at_ms"`
}

func ParseStage2aChildReadyRequest(raw []byte) (Stage2aChildReadyRequest, error) {
	var q Stage2aChildReadyRequest
	invalid := errors.New("invalid protected child readiness request")
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!validStage2aStopRequest(q.Stage2aStopRequest) ||
		q.ChildLauncherPID <= 1 || q.ChildPID <= 1 ||
		q.ChildLauncherPID == q.ChildPID || !stage2aPrefixedDigest.MatchString(q.GrantSHA256) {
		return Stage2aChildReadyRequest{}, invalid
	}
	return q, nil
}
