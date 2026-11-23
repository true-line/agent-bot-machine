package qualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"time"
)

const cooperativeBridgeAssignmentPurposeV3 = "agent-bot/soul-cooperative-bridge-assignment/v3"
const cooperativeRuntimeBaseV3 = "/Library/Application Support/ai.true-line.agent-bot-hq"

// VerifiedCooperativeBridgeAssignmentV3 authenticates the purpose-separated
// A-signed primary and private H/B assignment. It is a component, not a
// physical T21 verdict or a grant to start R/B. Installed bytes, observed
// sockets and one-use spending require independent evidence.
type VerifiedCooperativeBridgeAssignmentV3 struct {
	verified                                                                       bool
	HostID, InstallationID, SoulID, StartID, LaunchID, PlanID, PlanDigest, HQEpoch string
	ReservationSHA256, AssignmentSHA256, MeasurementBindingSHA256                  string
	BridgeLaunchSHA256, AdmissionChallengeSHA256, ProviderConfigSHA256             string
	RunnerUID, BridgeUID                                                           uint32
	IssuedAt, ExpiresAt                                                            time.Time
}

type cooperativeBridgePrimaryV3 struct {
	Contract                   string `json:"contract"`
	Kind                       string `json:"kind"`
	SchemaVersion              int    `json:"schema_version"`
	HostID                     string `json:"host_id"`
	IssuedAt                   string `json:"issued_at"`
	ExpiresAt                  string `json:"expires_at"`
	InstalledPlanReceiptSHA256 string `json:"installed_plan_receipt_sha256"`
	AdapterTransport           string `json:"adapter_transport"`
	BridgeLaunchSHA256         string `json:"bridge_launch_sha256"`
	AdmissionChallengeSHA256   string `json:"admission_challenge_sha256"`
	Assignment                 struct {
		InstallationID     string `json:"installation_id"`
		SoulID             string `json:"soul_id"`
		StartID            string `json:"start_id"`
		LaunchID           string `json:"launch_id"`
		PlanID             string `json:"plan_id"`
		PlanDigest         string `json:"plan_digest"`
		HQEpoch            string `json:"hq_epoch"`
		ExpiresAt          string `json:"expires_at"`
		RunnerAccount      string `json:"runner_account"`
		RunnerUID          uint32 `json:"runner_uid"`
		RunnerGID          uint32 `json:"runner_gid"`
		HQUID              uint32 `json:"hq_uid"`
		MachineUID         uint32 `json:"machine_uid"`
		PackageRoot        string `json:"package_root"`
		LaunchInputsRoot   string `json:"launch_inputs_root"`
		RuntimeRoot        string `json:"runtime_root"`
		NodePath           string `json:"node_path"`
		EntryPath          string `json:"entry_path"`
		StateRoot          string `json:"state_root"`
		StateRootMode      string `json:"state_root_mode"`
		PackageSHA256      string `json:"package_sha256"`
		SoulArtifactSHA256 string `json:"soul_artifact_sha256"`
	} `json:"assignment"`
	Endpoints struct {
		Admission json.RawMessage `json:"admission"`
		Member    json.RawMessage `json:"member"`
		Relay     json.RawMessage `json:"relay"`
	} `json:"endpoints"`
	MeasurementBinding json.RawMessage `json:"measurement_binding"`
	Provider           json.RawMessage `json:"qualification_provider"`
}

type cooperativeBridgePrivateV3 struct {
	Contract           string `json:"contract"`
	Kind               string `json:"kind"`
	SchemaVersion      int    `json:"schema_version"`
	HostID             string `json:"host_id"`
	InstallationID     string `json:"installation_id"`
	StartID            string `json:"start_id"`
	LaunchID           string `json:"launch_id"`
	PlanID             string `json:"plan_id"`
	PlanDigest         string `json:"plan_digest"`
	HQEpoch            string `json:"hq_epoch"`
	ExpiresAt          string `json:"expires_at"`
	ReservationSHA256  string `json:"reservation_sha256"`
	BridgeLaunchSHA256 string `json:"bridge_launch_sha256"`
	Bridge             struct {
		Account              string   `json:"account"`
		UID                  uint32   `json:"uid"`
		GID                  uint32   `json:"gid"`
		StateRoot            string   `json:"state_root"`
		StateRootMode        string   `json:"state_root_mode"`
		ExecutablePath       string   `json:"executable_path"`
		ExecutableSHA256     string   `json:"executable_sha256"`
		SandboxProfilePath   string   `json:"sandbox_profile_path"`
		SandboxProfileSHA256 string   `json:"sandbox_profile_sha256"`
		Argv                 []string `json:"argv"`
	} `json:"bridge"`
	Endpoints struct {
		Broker json.RawMessage `json:"broker"`
		Member json.RawMessage `json:"member"`
		Relay  json.RawMessage `json:"relay"`
	} `json:"endpoints"`
}

type cooperativeBridgeEndpointV3 struct {
	Directory         string `json:"directory"`
	SocketPath        string `json:"socket_path"`
	OwnerUID          uint32 `json:"owner_uid"`
	GroupGID          uint32 `json:"group_gid"`
	DirMode           uint32 `json:"dir_mode"`
	SocketMode        uint32 `json:"socket_mode"`
	ExpectedPeerUID   uint32 `json:"expected_peer_uid"`
	ParentDevice      string `json:"parent_device"`
	ParentInode       string `json:"parent_inode"`
	ParentBirthtimeNS string `json:"parent_birthtime_ns"`
}

func cooperativeBridgeSlotV3(prefix, input string) string {
	sum := sha256.Sum256([]byte(prefix + input))
	return hex.EncodeToString(sum[:10])
}

func cooperativeBridgeDecimalV3(value string) bool {
	n, err := strconv.ParseUint(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == value
}

func cooperativeBridgeEndpointShapeV3(raw []byte, directory, socket string,
	owner, group, peer uint32, parent bool) error {
	fields, err := canonicalBytes(raw, 4096)
	if err != nil {
		return ErrUnqualified
	}
	names := []string{"directory", "socket_path", "owner_uid", "group_gid",
		"dir_mode", "socket_mode", "expected_peer_uid"}
	if parent {
		names = append(names, "parent_device", "parent_inode", "parent_birthtime_ns")
	}
	if !hasFields(fields, names...) {
		return ErrUnqualified
	}
	var endpoint cooperativeBridgeEndpointV3
	if json.Unmarshal(raw, &endpoint) != nil || endpoint.Directory != directory ||
		endpoint.SocketPath != socket || path.Dir(socket) != directory || len(socket) > 103 ||
		endpoint.OwnerUID != owner || endpoint.GroupGID != group ||
		endpoint.ExpectedPeerUID != peer || endpoint.DirMode != 0o2750 ||
		endpoint.SocketMode != 0o660 ||
		(parent && (!cooperativeBridgeDecimalV3(endpoint.ParentDevice) ||
			!cooperativeBridgeDecimalV3(endpoint.ParentInode) ||
			!cooperativeBridgeDecimalV3(endpoint.ParentBirthtimeNS))) {
		return ErrUnqualified
	}
	return nil
}

// VerifyCooperativeBridgeAssignmentV3 verifies the B-specific signed chain
// independently of any report schema. The downstream report successor must
// bind these exact envelope digests and authenticate installed/physical bytes.
func VerifyCooperativeBridgeAssignmentV3(reservationEnvelope, bridgeEnvelope []byte,
	machineKey ed25519.PublicKey) (VerifiedCooperativeBridgeAssignmentV3, error) {
	var zero VerifiedCooperativeBridgeAssignmentV3
	primaryRaw, err := qSignedRecordV3(reservationEnvelope, cooperativeReservationPurposeV3, 3, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	privateRaw, err := qSignedRecordV3(bridgeEnvelope, cooperativeBridgeAssignmentPurposeV3, 3, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	primaryFields, err := canonicalBytes(primaryRaw, 48<<10)
	if err != nil {
		return zero, ErrUnqualified
	}
	names := []string{"contract", "kind", "schema_version", "host_id", "issued_at", "expires_at",
		"installed_plan_receipt_sha256", "assignment", "adapter_transport", "bridge_launch_sha256",
		"endpoints", "measurement_binding", "admission_challenge_sha256"}
	if _, ok := primaryFields["qualification_provider"]; ok {
		names = append(names, "qualification_provider")
	}
	if !hasFields(primaryFields, names...) {
		return zero, ErrUnqualified
	}
	privateFields, err := canonicalBytes(privateRaw, 48<<10)
	if err != nil || !hasFields(privateFields, "contract", "kind", "schema_version", "host_id",
		"installation_id", "start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch",
		"expires_at", "reservation_sha256", "bridge_launch_sha256", "bridge", "endpoints") {
		return zero, ErrUnqualified
	}
	assignmentFields, err := strictObject(primaryFields["assignment"], 48<<10)
	if err != nil || !hasFields(assignmentFields, "installation_id", "soul_id", "start_id", "launch_id",
		"plan_id", "plan_digest", "hq_epoch", "expires_at", "runner_account", "runner_uid", "runner_gid",
		"hq_uid", "machine_uid", "package_root", "launch_inputs_root", "runtime_root", "node_path",
		"entry_path", "state_root", "state_root_mode", "package_sha256", "soul_artifact_sha256") {
		return zero, ErrUnqualified
	}
	bridgeFields, err := strictObject(privateFields["bridge"], 48<<10)
	if err != nil || !hasFields(bridgeFields, "account", "uid", "gid", "state_root", "state_root_mode",
		"executable_path", "executable_sha256", "sandbox_profile_path", "sandbox_profile_sha256", "argv") {
		return zero, ErrUnqualified
	}
	primaryEndpoints, err := strictObject(primaryFields["endpoints"], 48<<10)
	if err != nil || !hasFields(primaryEndpoints, "admission", "member", "relay") {
		return zero, ErrUnqualified
	}
	privateEndpoints, err := strictObject(privateFields["endpoints"], 48<<10)
	if err != nil || !hasFields(privateEndpoints, "broker", "member", "relay") ||
		!bytes.Equal(primaryEndpoints["member"], privateEndpoints["member"]) ||
		!bytes.Equal(primaryEndpoints["relay"], privateEndpoints["relay"]) {
		return zero, ErrUnqualified
	}
	var primary cooperativeBridgePrimaryV3
	var private cooperativeBridgePrivateV3
	if json.Unmarshal(primaryRaw, &primary) != nil || json.Unmarshal(privateRaw, &private) != nil ||
		primary.Contract != "machine/v3" || primary.Kind != "soul-cooperative-reservation" ||
		primary.SchemaVersion != 3 || primary.AdapterTransport != "brokered-b" ||
		private.Contract != "machine/v3" || private.Kind != "soul-cooperative-bridge-assignment" ||
		private.SchemaVersion != 3 || private.ReservationSHA256 != digest(reservationEnvelope) ||
		!validSHA(primary.InstalledPlanReceiptSHA256) || !validSHA(primary.AdmissionChallengeSHA256) ||
		!validSHA(primary.BridgeLaunchSHA256) ||
		primary.BridgeLaunchSHA256 != private.BridgeLaunchSHA256 ||
		private.BridgeLaunchSHA256 != digest(privateFields["bridge"]) ||
		primary.HostID != private.HostID || primary.HostID == "" ||
		primary.Assignment.InstallationID != private.InstallationID ||
		primary.Assignment.StartID != private.StartID || primary.Assignment.LaunchID != private.LaunchID ||
		primary.Assignment.PlanID != private.PlanID || primary.Assignment.PlanDigest != private.PlanDigest ||
		primary.Assignment.HQEpoch != private.HQEpoch || primary.ExpiresAt != private.ExpiresAt ||
		primary.Assignment.ExpiresAt != primary.ExpiresAt {
		return zero, ErrUnqualified
	}
	issued, e1 := parseTime(primary.IssuedAt)
	expires, e2 := parseTime(primary.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return zero, ErrUnqualified
	}
	binding, err := parseCooperativeMeasurementBindingV3(primary.MeasurementBinding)
	if err != nil || binding.Base.ProfileInForce != "managed-cooperative" ||
		binding.Base.HostID != primary.HostID ||
		binding.Base.InstallationID != primary.Assignment.InstallationID ||
		binding.Base.SoulID != primary.Assignment.SoulID ||
		binding.Base.StartID != primary.Assignment.StartID ||
		binding.Base.LaunchID != primary.Assignment.LaunchID ||
		binding.Base.PlanID != primary.Assignment.PlanID ||
		binding.Base.InstalledPlanDigest != primary.Assignment.PlanDigest ||
		binding.Base.HQEpoch != primary.Assignment.HQEpoch ||
		binding.Base.PackageSHA256 != primary.Assignment.PackageSHA256 ||
		binding.Base.SoulArtifactSHA256 != primary.Assignment.SoulArtifactSHA256 ||
		binding.Base.Snapshots.Definition.RootPath != primary.Assignment.PackageRoot ||
		binding.Base.Snapshots.LaunchInputs.RootPath != primary.Assignment.LaunchInputsRoot ||
		binding.RInventory.Snapshot.Path != primary.Assignment.RuntimeRoot ||
		binding.RInventory.ReaderUID != primary.Assignment.RunnerUID ||
		binding.RInventory.ReaderGID != primary.Assignment.RunnerGID ||
		binding.RInventory.MachineUID != primary.Assignment.MachineUID ||
		primary.Assignment.NodePath != path.Join(primary.Assignment.RuntimeRoot, "bin/node") ||
		primary.Assignment.EntryPath != path.Join(primary.Assignment.RuntimeRoot, "bin/agent-bot-souls.mjs") ||
		primary.Assignment.StateRoot != "/private/var/agent-bot-soul-runner-"+primary.Assignment.RunnerAccount+"/state" ||
		primary.Assignment.StateRootMode != "0700" ||
		primary.Assignment.RunnerAccount != "_abm-sr-"+cooperativeBridgeSlotV3("", primary.Assignment.InstallationID) ||
		primary.Assignment.RunnerUID < 300 || primary.Assignment.RunnerUID > 399 ||
		primary.Assignment.RunnerGID != primary.Assignment.RunnerUID ||
		private.Bridge.UID < 300 || private.Bridge.UID > 399 ||
		private.Bridge.GID != private.Bridge.UID ||
		private.Bridge.UID == primary.Assignment.RunnerUID ||
		private.Bridge.UID == primary.Assignment.HQUID ||
		private.Bridge.UID == primary.Assignment.MachineUID ||
		primary.Assignment.HQUID == primary.Assignment.RunnerUID ||
		primary.Assignment.HQUID == primary.Assignment.MachineUID ||
		private.Bridge.Account != "_abm-br-"+cooperativeBridgeSlotV3("agent-bot-soul-bridge/v1\x00", primary.Assignment.InstallationID) ||
		private.Bridge.StateRoot != "/private/var/agent-bot-soul-bridge-"+private.Bridge.Account+"/state" ||
		private.Bridge.StateRootMode != "0700" ||
		private.Bridge.ExecutablePath != cooperativeRuntimeBaseV3+"/soul-bridge" ||
		private.Bridge.SandboxProfilePath != cooperativeRuntimeBaseV3+"/soul-bridge-egress.sb" ||
		!validSHA(private.Bridge.ExecutableSHA256) || !validSHA(private.Bridge.SandboxProfileSHA256) {
		return zero, ErrUnqualified
	}
	installationSlot := cooperativeBridgeSlotV3("agent-bot-soul-endpoint-installation/v1\x00", primary.Assignment.InstallationID)
	startSlot := cooperativeBridgeSlotV3("agent-bot-soul-endpoint-start/v1\x00",
		primary.Assignment.InstallationID+"\x00"+primary.Assignment.StartID) + ".sock"
	base := cooperativeRuntimeBaseV3
	pathFor := func(scope string) (string, string) {
		dir := path.Join(base, scope, installationSlot)
		return dir, path.Join(dir, startSlot)
	}
	aDir, aSocket := pathFor("r")
	mDir, mSocket := pathFor("m")
	rDir, rSocket := pathFor("s")
	bDir := path.Join(base, "ipc", private.Bridge.Account)
	bSocket := path.Join(bDir, "broker.sock")
	if cooperativeBridgeEndpointShapeV3(primary.Endpoints.Admission, aDir, aSocket,
		primary.Assignment.HQUID, primary.Assignment.RunnerGID, primary.Assignment.RunnerUID, false) != nil ||
		cooperativeBridgeEndpointShapeV3(primary.Endpoints.Member, mDir, mSocket,
			primary.Assignment.RunnerUID, private.Bridge.GID, private.Bridge.UID, true) != nil ||
		cooperativeBridgeEndpointShapeV3(primary.Endpoints.Relay, rDir, rSocket,
			private.Bridge.UID, primary.Assignment.RunnerGID, primary.Assignment.RunnerUID, true) != nil ||
		cooperativeBridgeEndpointShapeV3(private.Endpoints.Broker, bDir, bSocket,
			primary.Assignment.HQUID, private.Bridge.GID, private.Bridge.UID, true) != nil {
		return zero, ErrUnqualified
	}
	wantArgv := []string{"/usr/bin/sandbox-exec", "-D", "BROKER_SOCKET=" + bSocket,
		"-D", "MEMBER_SOCKET=" + mSocket, "-D", "RELAY_SOCKET=" + rSocket,
		"-f", private.Bridge.SandboxProfilePath, private.Bridge.ExecutablePath,
		"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"}
	if len(private.Bridge.Argv) != len(wantArgv) {
		return zero, ErrUnqualified
	}
	for i, arg := range wantArgv {
		if private.Bridge.Argv[i] != arg {
			return zero, ErrUnqualified
		}
	}
	providerDigest := ""
	if len(primary.Provider) != 0 {
		providerFields, err := canonicalBytes(primary.Provider, 48<<10)
		if err != nil || !hasFields(providerFields, "config_base64url", "config_sha256") {
			return zero, ErrUnqualified
		}
		var provider struct {
			ConfigBase64URL string `json:"config_base64url"`
			ConfigSHA256    string `json:"config_sha256"`
		}
		if json.Unmarshal(primary.Provider, &provider) != nil || !validSHA(provider.ConfigSHA256) {
			return zero, ErrUnqualified
		}
		config, err := decode(provider.ConfigBase64URL, 48<<10)
		if err != nil || digest(config) != provider.ConfigSHA256 {
			return zero, ErrUnqualified
		}
		configFields, err := canonicalBytes(config, 48<<10)
		if err != nil || !hasFields(configFields, "model", "request_sha256", "response_text") {
			return zero, ErrUnqualified
		}
		var value struct {
			Model         string `json:"model"`
			RequestSHA256 string `json:"request_sha256"`
			ResponseText  string `json:"response_text"`
		}
		if json.Unmarshal(config, &value) != nil || value.Model == "" ||
			!validSHA(value.RequestSHA256) || value.ResponseText == "" {
			return zero, ErrUnqualified
		}
		providerDigest = provider.ConfigSHA256
	}
	return VerifiedCooperativeBridgeAssignmentV3{
		verified: true, HostID: primary.HostID,
		InstallationID: primary.Assignment.InstallationID, SoulID: primary.Assignment.SoulID,
		StartID: primary.Assignment.StartID, LaunchID: primary.Assignment.LaunchID,
		PlanID: primary.Assignment.PlanID, PlanDigest: primary.Assignment.PlanDigest,
		HQEpoch:           primary.Assignment.HQEpoch,
		ReservationSHA256: digest(reservationEnvelope), AssignmentSHA256: digest(bridgeEnvelope),
		MeasurementBindingSHA256: digest(primary.MeasurementBinding),
		BridgeLaunchSHA256:       primary.BridgeLaunchSHA256,
		AdmissionChallengeSHA256: primary.AdmissionChallengeSHA256,
		ProviderConfigSHA256:     providerDigest, RunnerUID: primary.Assignment.RunnerUID,
		BridgeUID: private.Bridge.UID, IssuedAt: issued, ExpiresAt: expires,
	}, nil
}
