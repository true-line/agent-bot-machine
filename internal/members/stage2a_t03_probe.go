package members

const stage2aT03ProbeSchema = "agent-bot-machine/stage2a-t03-probe/v1"

// Stage2aT03ProbeDirective is carried only inside A's signed child Live lease.
// It selects a second invocation of the measured stock CLI under the same
// installed child profile. The URLs are reviewed local test-provider canaries;
// this record grants no network permission or provider credential.
type Stage2aT03ProbeDirective struct {
	Schema                string `json:"schema"`
	ChallengeBase64URL    string `json:"challenge_base64url"`
	SessionID             string `json:"session_id"`
	TestPlanSHA256        string `json:"test_plan_sha256"`
	ReservationSHA256     string `json:"reservation_sha256"`
	InstallationID        string `json:"installation_id"`
	StartID               string `json:"start_id"`
	ChildReceiptSHA256    string `json:"child_receipt_sha256"`
	LeaseSequence         uint64 `json:"lease_sequence"`
	CLIExecutableSHA256   string `json:"cli_executable_sha256"`
	ProviderIPv4URL       string `json:"provider_ipv4_url"`
	ProviderIPv6URL       string `json:"provider_ipv6_url"`
	Model                 string `json:"model"`
	PromptBase64URL       string `json:"prompt_base64url"`
	SiblingCredentialPath string `json:"sibling_credential_path"`
	SiblingSocket         string `json:"sibling_socket"`
	ExpiresAtMS           int64  `json:"expires_at_ms"`
}

// A emits one go for each process it observed while that process is still
// waiting on stdin. A new signed Live lease carries this decision; R cannot
// invent or reuse it for another child or attempt.
type Stage2aT03ProbeGo struct {
	ChallengeBase64URL string `json:"challenge_base64url"`
	ChildReceiptSHA256 string `json:"child_receipt_sha256"`
	ProbeLeaseSequence uint64 `json:"probe_lease_sequence"`
	GoLeaseSequence    uint64 `json:"go_lease_sequence"`
	Kind               string `json:"kind"`
	PID                int    `json:"pid"`
	StartSeconds       int64  `json:"start_seconds"`
	StartMicros        int32  `json:"start_micros"`
}

type Stage2aT03ProbeReady struct {
	Schema              string `json:"schema"`
	ChallengeBase64URL  string `json:"challenge_base64url"`
	SessionID           string `json:"session_id"`
	ReservationSHA256   string `json:"reservation_sha256"`
	InstallationID      string `json:"installation_id"`
	StartID             string `json:"start_id"`
	ChildReceiptSHA256  string `json:"child_receipt_sha256"`
	ProbeLeaseSequence  uint64 `json:"probe_lease_sequence"`
	Kind                string `json:"kind"`
	Target              string `json:"target"`
	PID                 int    `json:"pid"`
	UID                 uint32 `json:"uid"`
	GID                 uint32 `json:"gid"`
	StartSeconds        int64  `json:"start_seconds"`
	StartMicros         int32  `json:"start_micros"`
	CLIExecutable       string `json:"cli_executable"`
	CLIExecutableSHA256 string `json:"cli_executable_sha256"`
	ArgvSHA256          string `json:"argv_sha256"`
	EnvSHA256           string `json:"env_sha256"`
	SandboxSHA256       string `json:"sandbox_sha256"`
}

// The R wrapper reports bounded source observations to HQ for A's independent
// corroboration. This record is not a verdict and carries no credential bytes.
type Stage2aT03ProbeResult struct {
	Schema                  string                   `json:"schema"`
	ChallengeBase64URL      string                   `json:"challenge_base64url"`
	SessionID               string                   `json:"session_id"`
	TestPlanSHA256          string                   `json:"test_plan_sha256"`
	ReservationSHA256       string                   `json:"reservation_sha256"`
	InstallationID          string                   `json:"installation_id"`
	StartID                 string                   `json:"start_id"`
	ChildReceiptSHA256      string                   `json:"child_receipt_sha256"`
	LeaseSequence           uint64                   `json:"lease_sequence"`
	CLIExecutable           string                   `json:"cli_executable"`
	CLIExecutableSHA256     string                   `json:"cli_executable_sha256"`
	SandboxSHA256           string                   `json:"sandbox_sha256"`
	CredentialPath          string                   `json:"credential_path"`
	CredentialDenialErrno   string                   `json:"credential_denial_errno"`
	CredentialAttemptedAtMS int64                    `json:"credential_attempted_at_ms"`
	Attempts                []Stage2aT03ProbeAttempt `json:"attempts"`
}

type Stage2aT03ProbeAttempt struct {
	Kind                 string `json:"kind"`
	Target               string `json:"target"`
	PID                  int    `json:"pid"`
	UID                  uint32 `json:"uid"`
	GID                  uint32 `json:"gid"`
	StartSeconds         int64  `json:"start_seconds"`
	StartMicros          int32  `json:"start_micros"`
	ArgvSHA256           string `json:"argv_sha256"`
	EnvSHA256            string `json:"env_sha256"`
	ExitCode             int    `json:"exit_code"`
	StdoutSHA256         string `json:"stdout_sha256"`
	StderrSHA256         string `json:"stderr_sha256"`
	StdoutBytes          int    `json:"stdout_bytes"`
	StderrBytes          int    `json:"stderr_bytes"`
	OutputCapped         bool   `json:"output_capped"`
	DenialErrno          string `json:"denial_errno,omitempty"`
	DenialTargetObserved bool   `json:"denial_target_observed"`
	ErrorClass           string `json:"error_class"`
	StartedAtMS          int64  `json:"started_at_ms"`
	FinishedAtMS         int64  `json:"finished_at_ms"`
}

// A asks only the already launched sibling R child to observe its own private
// credential canary. The signed Live lease binds the path and short challenge.
type Stage2aT03SiblingCredentialProbe struct {
	Schema                   string `json:"schema"`
	ChallengeBase64URL       string `json:"challenge_base64url"`
	PrimaryReservationSHA256 string `json:"primary_reservation_sha256"`
	SiblingReservationSHA256 string `json:"sibling_reservation_sha256"`
	SiblingInstallationID    string `json:"sibling_installation_id"`
	SiblingStartID           string `json:"sibling_start_id"`
	ChildReceiptSHA256       string `json:"child_receipt_sha256"`
	LeaseSequence            uint64 `json:"lease_sequence"`
	CredentialPath           string `json:"credential_path"`
	ExpiresAtMS              int64  `json:"expires_at_ms"`
}

type Stage2aT03CredentialMetadata struct {
	Schema        string `json:"schema"`
	Path          string `json:"path"`
	Device        string `json:"device"`
	Inode         string `json:"inode"`
	Generation    string `json:"generation"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Mode          string `json:"mode"`
	SizeBytes     string `json:"size_bytes"`
	BirthSeconds  string `json:"birth_seconds"`
	BirthNanos    string `json:"birth_nanos"`
	ModifySeconds string `json:"modify_seconds"`
	ModifyNanos   string `json:"modify_nanos"`
	ChangeSeconds string `json:"change_seconds"`
	ChangeNanos   string `json:"change_nanos"`
}

type Stage2aT03SiblingCredentialWitness struct {
	Schema                   string                       `json:"schema"`
	ChallengeBase64URL       string                       `json:"challenge_base64url"`
	PrimaryReservationSHA256 string                       `json:"primary_reservation_sha256"`
	SiblingReservationSHA256 string                       `json:"sibling_reservation_sha256"`
	SiblingInstallationID    string                       `json:"sibling_installation_id"`
	SiblingStartID           string                       `json:"sibling_start_id"`
	ChildReceiptSHA256       string                       `json:"child_receipt_sha256"`
	LeaseSequence            uint64                       `json:"lease_sequence"`
	CredentialPath           string                       `json:"credential_path"`
	Metadata                 Stage2aT03CredentialMetadata `json:"metadata"`
	MetadataSHA256           string                       `json:"metadata_sha256"`
	ObservedAtMS             int64                        `json:"observed_at_ms"`
}

type Stage2aT03SiblingCredentialWitnessRequest struct {
	Stage2aStopRequest
	Witness Stage2aT03SiblingCredentialWitness `json:"witness"`
}
