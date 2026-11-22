package members

const (
	Stage2aRoleExecPurpose = "agent-bot/stage2a-exec/v1"
	SoulAuthorityPin       = launchRuntimeDir + "/soul-authority.pub"
)

type Stage2aRoleGrant struct {
	ReservationSHA256 string `json:"reservation_sha256"`
	Role              string `json:"role"`
	Nonce             string `json:"nonce"`
	PID               int    `json:"pid"`
	LaunchID          string `json:"launch_id"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	HQEpoch           string `json:"hq_epoch"`
	ExpiresAt         string `json:"expires_at"`
	InvocationSHA256  string `json:"invocation_sha256"`
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
}

type Stage2aRunnerExec struct {
	Definition                   []Stage2aDefinitionRecord `json:"definition"`
	Node                         string                    `json:"node"`
	Entry                        string                    `json:"entry"`
	ReservationEnvelopeBase64URL string                    `json:"reservation_envelope_base64url"`
	ReservationSHA256            string                    `json:"reservation_sha256"`
}

type Stage2aBridgeExec struct {
	Executable          HarnessArtifact `json:"executable"`
	AssignmentBase64URL string          `json:"assignment_base64url"`
	ProofSHA256         string          `json:"proof_sha256"`
}
