package members

type SoulCooperativeLookupReplyV3 struct {
	SourcePackagePath        string `json:"source_package_path"`
	InstallationID           string `json:"installation_id"`
	PlanID                   string `json:"plan_id"`
	PlanDigest               string `json:"plan_digest"`
	HostID                   string `json:"host_id"`
	HQEpoch                  string `json:"hq_epoch"`
	HQInstallationID         string `json:"hq_installation_id"`
	HOwnerPlanDigest         string `json:"h_owner_plan_digest"`
	RunnerUID                int    `json:"runner_uid"`
	RunnerGID                int    `json:"runner_gid"`
	AdmissionDir             string `json:"admission_directory"`
	AdmissionSocket          string `json:"admission_socket_path"`
	ReviewedStartID          string `json:"reviewed_start_id"`
	BrokerSocketPath         string `json:"broker_socket_path"`
	OwnerPlanMemberSetSHA256 string `json:"owner_plan_member_set_sha256"`
	BridgeLaunchSHA256       string `json:"bridge_launch_sha256"`
	AdapterTransport         string `json:"adapter_transport"`
}
