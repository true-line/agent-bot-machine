//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type soulCooperativeProviderConfigV3 struct {
	ConfigBase64URL string `json:"config_base64url"`
	ConfigSHA256    string `json:"config_sha256"`
}

type soulCooperativeComponentV3 struct {
	ComponentID           string  `json:"component_id"`
	SourceRepository      string  `json:"source_repository"`
	SourceCommit          string  `json:"source_commit"`
	SourceTag             *string `json:"source_tag,omitempty"`
	ReleaseArtifactSHA256 string  `json:"release_artifact_sha256"`
	ReleaseManifestSHA256 string  `json:"release_manifest_sha256"`
}

type soulCooperativeBindingV3 struct {
	Stage2aMeasurementBinding
	HDescriptorDigest string                       `json:"h_service_descriptor_digest"`
	RInventory        stage2aDomainInventoryRefV3  `json:"r_inventory"`
	RComponents       []soulCooperativeComponentV3 `json:"r_components"`
	HQBroker          soulCooperativeBrokerV3      `json:"hq_broker"`
	Adapter           soulCooperativeAdapterV3     `json:"adapter_release"`
}

type soulCooperativeAssignmentV3 struct {
	InstallationID     string `json:"installation_id"`
	SoulID             string `json:"soul_id"`
	StartID            string `json:"start_id"`
	LaunchID           string `json:"launch_id"`
	PlanID             string `json:"plan_id"`
	PlanDigest         string `json:"plan_digest"`
	HQEpoch            string `json:"hq_epoch"`
	ExpiresAt          string `json:"expires_at"`
	RunnerAccount      string `json:"runner_account"`
	RunnerUID          int    `json:"runner_uid"`
	RunnerGID          int    `json:"runner_gid"`
	HQUID              int    `json:"hq_uid"`
	MachineUID         int    `json:"machine_uid"`
	RuntimeRoot        string `json:"runtime_root"`
	PackageRoot        string `json:"package_root"`
	LaunchInputsRoot   string `json:"launch_inputs_root"`
	StateRoot          string `json:"state_root"`
	StateRootMode      string `json:"state_root_mode"`
	NodePath           string `json:"node_path"`
	EntryPath          string `json:"entry_path"`
	PackageSHA256      string `json:"package_sha256"`
	SoulArtifactSHA256 string `json:"soul_artifact_sha256"`
}

type soulCooperativeEndpointV3 struct {
	Directory       string `json:"directory"`
	SocketPath      string `json:"socket_path"`
	OwnerUID        int    `json:"owner_uid"`
	GroupGID        int    `json:"group_gid"`
	DirMode         int    `json:"dir_mode"`
	SocketMode      int    `json:"socket_mode"`
	ExpectedPeerUID int    `json:"expected_peer_uid"`
}

func soulCooperativeEndpointWire(e SoulCooperativeEndpoint) soulCooperativeEndpointV3 {
	return soulCooperativeEndpointV3{e.Directory, e.SocketPath, e.OwnerUID, e.GroupGID,
		e.DirMode, e.SocketMode, e.PeerUID}
}

type soulCooperativeEndpointsV3 struct {
	Admission soulCooperativeEndpointV3 `json:"admission"`
	Broker    soulCooperativeEndpointV3 `json:"broker"`
}

type soulCooperativeReservationPayloadV3 struct {
	Contract                   string                           `json:"contract"`
	Kind                       string                           `json:"kind"`
	SchemaVersion              int                              `json:"schema_version"`
	HostID                     string                           `json:"host_id"`
	IssuedAt                   string                           `json:"issued_at"`
	ExpiresAt                  string                           `json:"expires_at"`
	InstalledPlanReceiptSHA256 string                           `json:"installed_plan_receipt_sha256"`
	Assignment                 soulCooperativeAssignmentV3      `json:"assignment"`
	Endpoints                  soulCooperativeEndpointsV3       `json:"endpoints"`
	MeasurementBinding         soulCooperativeBindingV3         `json:"measurement_binding"`
	AdmissionChallengeSHA256   string                           `json:"admission_challenge_sha256"`
	AdapterTransport           string                           `json:"adapter_transport"`
	QualificationProvider      *soulCooperativeProviderConfigV3 `json:"qualification_provider,omitempty"`
}

type soulCooperativeVerifiedStartV3 struct {
	installed            soulCooperativeInstalledV3
	r                    stage2aVerifiedDomainRefV3
	h                    stage2aVerifiedDomainRefV3
	hDescriptorDigest    string
	hComponents          []soulCooperativeComponentV3
	hEntryPath           string
	hEntrySHA256         string
	qualificationDigests map[string]string
}

func cooperativeV3RComponents(spec stage2aRuntimeV3Install) []soulCooperativeComponentV3 {
	selected := make([]soulCooperativeComponentV3, 0, len(spec.Components))
	for _, c := range spec.Components {
		row := soulCooperativeComponentV3{ComponentID: c.ComponentID,
			SourceRepository: c.SourceRepository, SourceCommit: c.SourceCommit,
			ReleaseArtifactSHA256: c.ReleaseArtifactSHA256,
			ReleaseManifestSHA256: c.ReleaseManifestSHA256}
		if c.SourceTag != "" {
			tag := c.SourceTag
			row.SourceTag = &tag
		}
		selected = append(selected, row)
	}
	return selected
}

func cooperativeV3ComponentDigest(p SoulCooperativeLaunchPolicy, a soulCooperativeVerifiedStartV3,
	r stage2aDomainInventoryV3) bool {
	if !stage2aPrefixedDigest.MatchString(a.hEntrySHA256) ||
		p.LaunchInputs.ComponentDigests["hq"] != a.hEntrySHA256 ||
		p.LaunchInputs.ComponentDigests["adapter"] != p.AdapterRelease.ExecutableSHA256 ||
		p.LaunchInputs.ComponentDigests["comms_broker"] != p.HQBroker.ModuleSHA256 {
		return false
	}
	var hqRelease, soulsRelease bool
	for _, row := range a.hComponents {
		hqRelease = hqRelease || row.ComponentID == "hq"
	}
	for _, row := range cooperativeV3RComponents(*p.RuntimeV3) {
		soulsRelease = soulsRelease || row.ComponentID == "souls"
	}
	if !hqRelease || !soulsRelease {
		return false
	}
	var entryRow bool
	for _, row := range r.Files {
		entryRow = entryRow || path.Join(p.RuntimeRoot, row.Path) == path.Join(p.RuntimeRoot, p.Entry) &&
			row.SHA256 == p.LaunchInputs.ComponentDigests["souls"] && row.ComponentID == "souls"
	}
	manager, err := managerBytes()
	return entryRow && err == nil && p.LaunchInputs.ComponentDigests["machine"] == "sha256:"+harnessSHA(manager)
}

func cooperativeV3AdapterCodeMatches(p SoulCooperativeLaunchPolicy, inv stage2aDomainInventoryV3) bool {
	if p.AdapterRelease == nil || len(p.AdapterCodeInputs) != p.AdapterRelease.CodeInputCount {
		return false
	}
	files := make(map[string]stage2aDomainFileV3)
	for _, row := range inv.Files {
		if row.ComponentID == p.AdapterRelease.ComponentID {
			files[path.Join(p.RuntimeRoot, row.Path)] = row
		}
	}
	executable, exists := files[p.AdapterRelease.ExecutablePath]
	if !exists || executable.Mode != "0550" || executable.SHA256 != p.AdapterRelease.ExecutableSHA256 {
		return false
	}
	for i, path := range p.AdapterCodeInputs {
		if _, ok := files[path]; !ok || (i > 0 && path <= p.AdapterCodeInputs[i-1]) {
			return false
		}
	}
	raw, err := json.Marshal(slices.Clone(p.AdapterCodeInputs))
	if err != nil {
		return false
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(append([]byte("agent-bot/stage2a-adapter-code-inputs/v3\x00"), raw...))) == p.AdapterRelease.CodeInputsDigest
}

func cooperativeV3BrokerMatches(p SoulCooperativeLaunchPolicy, a soulCooperativeVerifiedStartV3) bool {
	if p.HQBroker == nil || !p.HQBroker.valid(p.HQInstallationID) {
		return false
	}
	if a.hEntryPath == "" || !stage2aPrefixedDigest.MatchString(a.hEntrySHA256) {
		return false
	}
	_, raw, err := stage2aV3SidecarAt(a.h.ref.Sidecar.Path,
		uint32(p.MachineUID), uint32(p.HQUID))
	if err != nil {
		return false
	}
	var inv stage2aDomainInventoryV3
	if json.Unmarshal(raw, &inv) != nil || inv.Domain != "H-code" ||
		inv.InstallationID != p.HQInstallationID {
		return false
	}
	var broker, entry bool
	for _, row := range inv.Files {
		full := path.Join(a.h.ref.Snapshot.Path, row.Path)
		if full == p.HQBroker.ModulePath {
			broker = row.Kind == "regular" && row.Mode == "0440" && row.SHA256 == p.HQBroker.ModuleSHA256
		}
		if full == a.hEntryPath {
			entry = row.Kind == "regular" && row.Mode == "0440" && row.SHA256 == a.hEntrySHA256
		}
	}
	return broker && entry
}

func cooperativeV3LaunchInputsMatch(p SoulCooperativeLaunchPolicy,
	admission, broker SoulCooperativeEndpoint) bool {
	input := p.LaunchInputs
	if input == nil || input.SelectedCommand != p.NodePath ||
		input.HostProjection.Installation["id"] != p.Runner.InstallationID ||
		len(input.Environment) != 3 || input.Environment["PATH"] != "/usr/bin:/bin" ||
		input.Environment["HOME"] != p.StateRoot ||
		input.Environment["AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH"] != "1" ||
		input.EffectiveConfig["profile"] != "managed-cooperative" {
		return false
	}
	want := []string{p.NodePath, path.Join(p.RuntimeRoot, p.Entry), "run",
		"--soul", p.Runner.PackageRoot,
		"--admission-socket", admission.SocketPath,
		"--broker-socket", broker.SocketPath,
		"--profile", "managed-cooperative", "--cooperative-start-fd", "3"}
	return slices.Equal(input.Argv, want)
}

// Build only from the A loader's installed receipt and separately rechecked H
// and R refs. The caller must hold current pairing and the installation lock.
func prepareSoulCooperativeReservationV3(a soulCooperativeVerifiedStartV3,
	q SoulCooperativeReserveRequest, issued time.Time) (soulCooperativeReservationPayloadV3, error) {
	var empty soulCooperativeReservationPayloadV3
	p := a.installed.Policy
	if p.Schema != soulCooperativeRuntimeInstallSchemaV3 || p.validate() != nil ||
		!q.valid() || !soulLaunchID.MatchString(q.LaunchID) ||
		!stage2aPrefixedDigest.MatchString(q.AdmissionChallengeSHA256) ||
		q.Profile != "managed-cooperative" || q.HostID != p.HostID ||
		q.InstallationID != p.Runner.InstallationID || q.HQEpoch != p.HQEpoch ||
		q.PlanDigest == "" || a.r.ref != a.installed.RuntimeV3 ||
		!a.r.verified || !a.h.verified ||
		stage2aRecheckVerifiedDomainV3(a.r) != nil ||
		stage2aRecheckVerifiedDomainV3(a.h) != nil ||
		a.h.ref.Domain != "H-code" || a.h.ref.InstallationID != p.HQInstallationID ||
		a.h.ref.OwnerPlanDigest != "sha256:"+p.HOwnerPlanDigest ||
		!stage2aPrefixedDigest.MatchString(a.hDescriptorDigest) ||
		len(a.hComponents) == 0 || !cooperativeV3BrokerMatches(p, a) ||
		q.PackagePath != p.SourcePackagePath || p.AdapterTransport != stage2aDirectComms {
		return empty, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(a.installed.RootReceipt, &receipt) != nil ||
		q.PlanDigest != receipt.PlanDigest || !ValidApproval(receipt.PlanID, receipt.PlanDigest) {
		return empty, errSoulCooperativeAuthority
	}
	_, raw, err := stage2aV3SidecarAt(a.r.ref.Sidecar.Path,
		uint32(p.MachineUID), uint32(p.Runner.GID))
	var inventory stage2aDomainInventoryV3
	if err != nil || json.Unmarshal(raw, &inventory) != nil ||
		!cooperativeRuntimeEntriesMatch(inventory, p) ||
		!cooperativeV3ComponentDigest(p, a, inventory) ||
		!cooperativeV3AdapterCodeMatches(p, inventory) {
		return empty, errSoulCooperativeAuthority
	}
	if _, harness := p.LaunchInputs.ComponentDigests["harness"]; harness {
		if a.qualificationDigests == nil ||
			a.qualificationDigests["harness"] != p.LaunchInputs.ComponentDigests["harness"] ||
			a.qualificationDigests["test_provider"] != p.LaunchInputs.ComponentDigests["test_provider"] {
			return empty, errSoulCooperativeAuthority
		}
	}
	admission, err := cooperativeEndpoint(p, q.StartID)
	if err != nil {
		return empty, err
	}
	broker, err := cooperativeBrokerEndpoint(p)
	if err != nil {
		return empty, err
	}
	if !cooperativeV3LaunchInputsMatch(p, admission, broker) {
		return empty, errSoulCooperativeAuthority
	}
	var providerConfig *soulCooperativeProviderConfigV3
	if p.QualificationProvider != nil {
		config, digest, configErr := stage2aProviderConfig(*p.QualificationProvider)
		if configErr != nil || p.LaunchInputs.EffectiveConfig["qualification_provider_config_sha256"] != "sha256:"+digest {
			return empty, errSoulCooperativeAuthority
		}
		providerConfig = &soulCooperativeProviderConfigV3{
			ConfigBase64URL: base64.RawURLEncoding.EncodeToString(config),
			ConfigSHA256:    "sha256:" + digest}
	}
	// ApprovedUntil authorized the reviewed installation. Current start
	// authority comes from its applied receipt, current paired epoch, measured
	// H/R bytes and this fresh one-use reservation, not that installation TTL.
	expires := issued.Add(30 * time.Second)
	expiresAt := expires.UTC().Format(time.RFC3339Nano)
	binding := Stage2aMeasurementBinding{Contract: "machine/v3", Kind: "stage2a-measurement-binding", SchemaVersion: 3,
		InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID,
		StartID: q.StartID, LaunchID: q.LaunchID, HostID: p.HostID, HQEpoch: p.HQEpoch,
		PlanID: receipt.PlanID, InstalledPlanDigest: receipt.PlanDigest,
		PackageSHA256: p.Runner.PackageSHA256, SoulArtifactSHA256: p.ArtifactSHA256,
		ProfileInForce: "managed-cooperative", ClaimedDefinitionDigest: "sha256:" + p.DefinitionSHA256,
		DefinitionMeasurement: p.DefinitionMeasurement, LaunchInputMeasurement: p.LaunchInputMeasurement,
		Snapshots: Stage2aBindingSnapshots{Definition: a.installed.DefinitionSnapshot,
			LaunchInputs: a.installed.LaunchInputsSnapshot}}
	return soulCooperativeReservationPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-reservation",
		SchemaVersion: 3, HostID: p.HostID, IssuedAt: issued.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                  expiresAt,
		InstalledPlanReceiptSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(a.installed.RootReceipt)),
		Assignment: soulCooperativeAssignmentV3{InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID,
			StartID: q.StartID, LaunchID: q.LaunchID, PlanID: receipt.PlanID, PlanDigest: receipt.PlanDigest,
			HQEpoch: p.HQEpoch, ExpiresAt: expiresAt, RunnerAccount: p.Runner.Account,
			RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID, HQUID: p.HQUID, MachineUID: p.MachineUID,
			RuntimeRoot: p.RuntimeRoot, PackageRoot: p.Runner.PackageRoot,
			LaunchInputsRoot: a.installed.LaunchInputsSnapshot.RootPath,
			StateRoot:        p.StateRoot, StateRootMode: "0700", NodePath: p.NodePath,
			EntryPath: path.Join(p.RuntimeRoot, p.Entry), PackageSHA256: p.Runner.PackageSHA256,
			SoulArtifactSHA256: p.ArtifactSHA256},
		Endpoints: soulCooperativeEndpointsV3{soulCooperativeEndpointWire(admission), soulCooperativeEndpointWire(broker)},
		MeasurementBinding: soulCooperativeBindingV3{Stage2aMeasurementBinding: binding,
			HDescriptorDigest: a.hDescriptorDigest, RInventory: a.r.ref,
			RComponents: cooperativeV3RComponents(*p.RuntimeV3),
			HQBroker:    *p.HQBroker, Adapter: *p.AdapterRelease},
		AdmissionChallengeSHA256: q.AdmissionChallengeSHA256,
		AdapterTransport:         p.AdapterTransport,
		QualificationProvider:    providerConfig}, nil
}

func signSoulCooperativeReservationV3(a soulCooperativeVerifiedStartV3,
	q SoulCooperativeReserveRequest, issued time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	payload, err := prepareSoulCooperativeReservationV3(a, q, issued)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 36<<10 {
		return nil, "", errSoulCooperativeAuthority
	}
	envelope, digest, err := signSoulCooperativeEnvelopeV3(canonical, key, sign)
	if err != nil || len(envelope) > 48<<10 {
		return nil, "", errSoulCooperativeAuthority
	}
	verified, actual, err := verifySoulCooperativeEnvelopeV3(envelope, key)
	if err != nil || actual != digest || !bytes.Equal(verified, canonical) {
		return nil, "", errSoulCooperativeAuthority
	}
	return envelope, digest, nil
}
