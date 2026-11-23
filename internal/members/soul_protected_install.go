package members

import "encoding/json"

// SoulProtectedLaunchInstall is an owner-reviewed request. The applied plan ID,
// root receipt, and descriptor-observed snapshot identities are deliberately
// absent: they are produced only after the exact plan has been approved.
const SoulProtectedLaunchInstallPurpose = "soul-protected-launch-install"
const SoulProtectedLaunchRetirePurpose = "soul-protected-launch-retire"

type SoulProtectedLaunchInstall struct {
	Schema             string                   `json:"schema"`
	MachinePublicKey   string                   `json:"machine_public_key"`
	ArtifactSource     string                   `json:"artifact_source"`
	BridgeBinarySource string                   `json:"bridge_binary_source"`
	DefinitionSource   string                   `json:"definition_source"`
	LaunchInputsSource string                   `json:"launch_inputs_source"`
	RuntimeV3          *stage2aRuntimeV3Install `json:"runtime_v3,omitempty"`
	// The owner selects the exact frozen two-member projection in the
	// approved install plan. Legacy single-member plans omit this field.
	OwnerPlanMemberSetSHA256 string          `json:"owner_plan_member_set_sha256,omitempty"`
	Policy                   json.RawMessage `json:"policy"`
}

// Retirement reviews the original install and disables only its per-Soul
// authority and sudo rule. Audit claims, snapshots, receipts and accounts stay.
type SoulProtectedLaunchRetire struct {
	Schema              string          `json:"schema"`
	InstalledPlanID     string          `json:"installed_plan_id"`
	InstalledPlanDigest string          `json:"installed_plan_digest"`
	InstalledPlan       json.RawMessage `json:"installed_plan"`
}

// The local broker fixture is exact reviewed input for one pilot bridge. It
// does not authorize network egress or stand in for a physical completion.
type Stage2aBridgeQualification struct {
	Model           string `json:"model"`
	RequestSHA256   string `json:"request_sha256"`
	HeadersSHA256   string `json:"headers_sha256"`
	ClientKeySHA256 string `json:"client_key_sha256"`
	HTTPHost        string `json:"http_host"`
	MessagesQuery   string `json:"messages_query"`
	ResponseText    string `json:"response_text"`
}
