package members

// Stage2aEndpointPolicy is the fixed per-installation directory rule. A
// start-specific socket basename is derived only after a signed reservation.
type Stage2aEndpointPolicy struct {
	Directory  string `json:"directory"`
	OwnerUID   int    `json:"owner_uid"`
	GroupGID   int    `json:"group_gid"`
	DirMode    uint32 `json:"dir_mode"`
	SocketMode uint32 `json:"socket_mode"`
}

type Stage2aInstalledAssignment struct {
	InstallationID       string                `json:"installation_id"`
	SoulID               string                `json:"soul_id"`
	PackageRoot          string                `json:"package_root"`
	PlanID               string                `json:"plan_id"`
	PlanDigest           string                `json:"plan_digest"`
	HQEpoch              string                `json:"hq_epoch"`
	HostID               string                `json:"host_id"`
	MachineUID           int                   `json:"machine_uid"`
	HQUID                int                   `json:"hq_uid"`
	RunnerAccount        string                `json:"runner_account"`
	RunnerUID            int                   `json:"runner_uid"`
	RunnerGID            int                   `json:"runner_gid"`
	BridgeAccount        string                `json:"bridge_account"`
	BridgeUID            int                   `json:"bridge_uid"`
	BridgeGID            int                   `json:"bridge_gid"`
	SoulArtifactSHA256   string                `json:"soul_artifact_sha256"`
	DefinitionDigest     string                `json:"definition_measurement"`
	ClaimedDefinition    string                `json:"claimed_definition_digest"`
	LaunchInputDigest    string                `json:"launch_input_measurement"`
	RootReceiptSHA256    string                `json:"root_receipt_sha256"`
	ProviderConfigSHA256 string                `json:"provider_config_sha256"`
	Broker               Stage2aEndpointPolicy `json:"broker"`
	Member               Stage2aEndpointPolicy `json:"member"`
	Relay                Stage2aEndpointPolicy `json:"relay"`
	Admission            Stage2aEndpointPolicy `json:"admission"`
}

type Stage2aListReply struct {
	MachinePublicKey string                       `json:"machine_public_key"`
	Installations    []Stage2aInstalledAssignment `json:"installations"`
}
