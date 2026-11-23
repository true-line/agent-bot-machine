package members

import "encoding/json"

const (
	Stage2aRoleExecPurpose = "agent-bot/stage2a-exec/v1"
	SoulAuthorityPin       = launchRuntimeDir + "/soul-authority.pub"
)

type Stage2aRoleGrant struct {
	ReservationSHA256                 string `json:"reservation_sha256"`
	Role                              string `json:"role"`
	Nonce                             string `json:"nonce"`
	PID                               int    `json:"pid"`
	LaunchID                          string `json:"launch_id"`
	InstallationID                    string `json:"installation_id"`
	StartID                           string `json:"start_id"`
	HQEpoch                           string `json:"hq_epoch"`
	ExpiresAt                         string `json:"expires_at"`
	InvocationSHA256                  string `json:"invocation_sha256"`
	MemberID                          string `json:"member_id,omitempty"`
	MemberLaunchID                    string `json:"member_launch_id,omitempty"`
	MemberSelector                    string `json:"member_selector,omitempty"`
	MemberSetAssignmentEnvelopeSHA256 string `json:"member_set_assignment_envelope_sha256,omitempty"`
}

type Stage2aExecReply struct {
	EnvelopeBase64URL   string `json:"envelope_base64url"`
	SHA256              string `json:"sha256"`
	InvocationBase64URL string `json:"invocation_base64url"`
}

type Stage2aRoleInvocation struct {
	Request    SoulRunRequest            `json:"request"`
	Start      SoulStartAssignment       `json:"start"`
	Runner     SoulRunner                `json:"runner"`
	Bridge     SoulBridge                `json:"bridge"`
	Binding    Stage2aMeasurementBinding `json:"measurement_binding"`
	Launch     Stage2aLaunchInputRecords `json:"launch_inputs"`
	RunnerExec *Stage2aRunnerExec        `json:"runner_exec,omitempty"`
	BridgeExec *Stage2aBridgeExec        `json:"bridge_exec,omitempty"`
	ChildExec  *Stage2aChildExec         `json:"child_exec,omitempty"`
}

type Stage2aRunnerExec struct {
	Definition                           []Stage2aDefinitionRecord `json:"definition"`
	Node                                 string                    `json:"node"`
	Entry                                string                    `json:"entry"`
	ReservationEnvelopeBase64URL         string                    `json:"reservation_envelope_base64url"`
	ReservationSHA256                    string                    `json:"reservation_sha256"`
	ReservationRunModeV3                 string                    `json:"reservation_run_mode_v3,omitempty"`
	ReservationV3                        json.RawMessage           `json:"reservation_v3,omitempty"`
	MemberSetAssignmentEnvelopeBase64URL string                    `json:"member_set_assignment_envelope_base64url,omitempty"`
}

type Stage2aBridgeExec struct {
	Executable          HarnessArtifact `json:"executable"`
	AssignmentBase64URL string          `json:"assignment_base64url"`
	ProofSHA256         string          `json:"proof_sha256"`
}

// The child command is selected from the installed, owner-reviewed launch
// inputs. HQ supplies no executable, argument, environment or socket value.
type Stage2aChildExec struct {
	MemberID                             string                       `json:"member_id,omitempty"`
	MemberLaunchID                       string                       `json:"member_launch_id,omitempty"`
	MemberSelector                       string                       `json:"member_selector,omitempty"`
	MemberSetAssignmentEnvelopeBase64URL string                       `json:"member_set_assignment_envelope_base64url,omitempty"`
	ProvisionalHQMapSHA256               string                       `json:"provisional_hq_mapping_sha256,omitempty"`
	ReservationSHA256                    string                       `json:"reservation_sha256"`
	FinalizationSHA256                   string                       `json:"finalization_sha256"`
	HelloFinalizationSHA256              string                       `json:"hello_finalization_sha256"`
	BindReceiptSHA256                    string                       `json:"bind_receipt_sha256"`
	Runner                               Stage2aLiveRoleIdentity      `json:"runner"`
	Bridge                               Stage2aLiveRoleIdentity      `json:"bridge"`
	Executable                           string                       `json:"executable"`
	ExecutableSHA256                     string                       `json:"executable_sha256"`
	RuntimeV3                            *stage2aDomainInventoryRefV3 `json:"runtime_v3,omitempty"`
	RelaySocket                          string                       `json:"relay_socket"`
	SandboxPath                          string                       `json:"sandbox_path"`
	SandboxSHA256                        string                       `json:"sandbox_sha256"`
	GrantExpiresAt                       string                       `json:"grant_expires_at"`
	Workdir                              string                       `json:"workdir"`
	Environment                          map[string]string            `json:"environment"`
}
