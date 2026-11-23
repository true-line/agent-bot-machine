package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const stage2aProtectedControlProbeLimit = 8192

// Stage2aProtectedControlProbeSpec is signed by A in ChildReady. A derives
// provider values from the installed plan and sibling values from an exact
// owner-reviewed live B2 assignment and its real B-only proof path; HQ and R
// cannot select probe targets or receive proof bytes.
type Stage2aProtectedControlProbeSpec struct {
	Schema                string `json:"schema"`
	InstallationID        string `json:"installation_id"`
	StartID               string `json:"start_id"`
	LaunchID              string `json:"launch_id"`
	PlanDigest            string `json:"plan_digest"`
	ProviderConfigSHA256  string `json:"provider_config_sha256"`
	HQEpoch               string `json:"hq_epoch"`
	ProviderPort          int    `json:"provider_port"`
	ProviderModel         string `json:"provider_model"`
	ProviderRequestSHA256 string `json:"provider_request_sha256"`
	SiblingInstallationID string `json:"sibling_installation_id"`
	SiblingStartID        string `json:"sibling_start_id"`
	SiblingBridgeUID      int    `json:"sibling_bridge_uid"`
	SiblingTokenPath      string `json:"sibling_token_path"`
	SiblingRelaySocket    string `json:"sibling_relay_socket"`
}

// Stage2aProtectedControlProbeUpload is an evidence input carried over the
// existing paired channel. Its sender does not attest to the OS result; A
// verifies the live run and stores the exact raw bytes without assigning T
// credit. The signed ChildReady payload, not this upload, selects targets.
type Stage2aProtectedControlProbeUpload struct {
	Stage2aStopRequest
	ChildReceiptSHA256 string `json:"child_receipt_sha256"`
	ArtifactBase64URL  string `json:"artifact_base64url"`
}

type Stage2aProtectedControlProbeReceipt struct {
	ArtifactSHA256 string `json:"artifact_sha256"`
	Kind           string `json:"kind"`
}

func ParseStage2aProtectedControlProbeUpload(raw []byte) (Stage2aProtectedControlProbeUpload, error) {
	var q Stage2aProtectedControlProbeUpload
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || !validStage2aStopRequest(q.Stage2aStopRequest) ||
		!stage2aPrefixedDigest.MatchString(q.ChildReceiptSHA256) ||
		len(q.ArtifactBase64URL) == 0 || len(q.ArtifactBase64URL) > 10924 {
		return Stage2aProtectedControlProbeUpload{}, errors.New("invalid protected control probe upload")
	}
	artifact, err := base64.RawURLEncoding.Strict().DecodeString(q.ArtifactBase64URL)
	if err != nil || len(artifact) == 0 || len(artifact) > stage2aProtectedControlProbeLimit ||
		base64.RawURLEncoding.EncodeToString(artifact) != q.ArtifactBase64URL ||
		!json.Valid(artifact) || !bytes.Equal(bytes.TrimSpace(artifact), artifact) {
		return Stage2aProtectedControlProbeUpload{}, errors.New("invalid protected control probe artifact")
	}
	return q, nil
}
