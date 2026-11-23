//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

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

type soulCooperativeEndpointsV3 struct {
	Admission soulCooperativeEndpointV3  `json:"admission"`
	Member    soulCooperativeBEndpointV3 `json:"member"`
	Relay     soulCooperativeBEndpointV3 `json:"relay"`
}

type soulCooperativeEndpointV3 struct {
	Directory       string `json:"directory"`
	SocketPath      string `json:"socket_path"`
	OwnerUID        int    `json:"owner_uid"`
	GroupGID        int    `json:"group_gid"`
	DirMode         uint32 `json:"dir_mode"`
	SocketMode      uint32 `json:"socket_mode"`
	ExpectedPeerUID int    `json:"expected_peer_uid"`
}

func soulCooperativeEndpointWire(e SoulEndpoint, peer int) soulCooperativeEndpointV3 {
	return soulCooperativeEndpointV3{Directory: e.Directory, SocketPath: e.SocketPath,
		OwnerUID: e.OwnerUID, GroupGID: e.GroupGID, DirMode: e.DirMode,
		SocketMode: e.SocketMode, ExpectedPeerUID: peer}
}

type soulCooperativeReservationPayloadV3 struct {
	Contract                   string                      `json:"contract"`
	Kind                       string                      `json:"kind"`
	SchemaVersion              int                         `json:"schema_version"`
	HostID                     string                      `json:"host_id"`
	IssuedAt                   string                      `json:"issued_at"`
	ExpiresAt                  string                      `json:"expires_at"`
	InstalledPlanReceiptSHA256 string                      `json:"installed_plan_receipt_sha256"`
	Assignment                 soulCooperativeAssignmentV3 `json:"assignment"`
	Endpoints                  soulCooperativeEndpointsV3  `json:"endpoints"`
	MeasurementBinding         soulCooperativeBindingV3    `json:"measurement_binding"`
	AdmissionChallengeSHA256   string                      `json:"admission_challenge_sha256"`
	AdapterTransport           string                      `json:"adapter_transport"`
	BridgeLaunchSHA256         string                      `json:"bridge_launch_sha256"`
}

type soulCooperativeVerifiedStartV3 struct {
	installed         soulCooperativeInstalledV3
	r                 stage2aVerifiedDomainRefV3
	h                 stage2aVerifiedDomainRefV3
	hDescriptorDigest string
	hComponents       []soulCooperativeComponentV3
	hEntryPath        string
	hEntrySHA256      string
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
		p.LaunchInputs.ComponentDigests["bridge"] != "sha256:"+p.BridgeExecutable.SHA256 {
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
	return entryRow && err == nil &&
		p.LaunchInputs.ComponentDigests["machine"] == "sha256:"+harnessSHA(manager)
}

// The paired caller holds the current H pair and installation lock. Every
// endpoint comes from an A-retained, rechecked parent identity.
func prepareSoulCooperativeReservationV3(a soulCooperativeVerifiedStartV3,
	q SoulCooperativeReserveRequest, issued time.Time) (soulCooperativeReservationPayloadV3, error) {
	var empty soulCooperativeReservationPayloadV3
	p := a.installed.Policy
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 || p.validate() != nil ||
		!q.valid() || !soulLaunchID.MatchString(q.LaunchID) ||
		!stage2aPrefixedDigest.MatchString(q.AdmissionChallengeSHA256) ||
		q.Profile != "managed-cooperative" || q.HostID != p.HostID ||
		q.InstallationID != p.Runner.InstallationID || q.HQEpoch != p.HQEpoch ||
		q.StartID != p.ReviewedStartID || q.PackagePath != p.SourcePackagePath ||
		a.r.ref != a.installed.RuntimeV3 || !a.r.verified || !a.h.verified ||
		stage2aRecheckVerifiedDomainV3(a.r) != nil || stage2aRecheckVerifiedDomainV3(a.h) != nil ||
		a.h.ref.Domain != "H-code" || a.h.ref.InstallationID != p.HQInstallationID ||
		a.h.ref.OwnerPlanDigest != p.HOwnerPlanDigest ||
		!stage2aPrefixedDigest.MatchString(a.hDescriptorDigest) || len(a.hComponents) == 0 ||
		p.LaunchInputs == nil || p.LaunchInputs.AdapterTransport != "brokered-b" {
		return empty, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(a.installed.RootReceipt, &receipt) != nil ||
		!ValidApproval(receipt.PlanID, receipt.PlanDigest) || q.PlanDigest != receipt.PlanDigest {
		return empty, errSoulCooperativeAuthority
	}
	_, raw, err := stage2aV3SidecarAt(a.r.ref.Sidecar.Path, uint32(p.MachineUID), uint32(p.Runner.GID))
	var inventory stage2aDomainInventoryV3
	if err != nil || json.Unmarshal(raw, &inventory) != nil ||
		!cooperativeRuntimeEntriesMatch(inventory, p) || !cooperativeV3ComponentDigest(p, a, inventory) {
		return empty, errSoulCooperativeAuthority
	}
	parents := soulCooperativeBParentsV3{Broker: a.installed.BrokerDirectory,
		Member: a.installed.MemberDirectory, Relay: a.installed.RelayDirectory}
	_, bEnds, bridgeDigest, err := soulCooperativeBLaunchIntentV3(p, q.StartID, parents)
	if err != nil || bridgeDigest != p.LaunchInputs.BridgeLaunchSHA256 {
		return empty, errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, q.StartID)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	if !soulCooperativeRecheckBParentV3(a.installed.AdmissionDirectory,
		ends.Admission.OwnerUID, ends.Admission.GroupGID) {
		return empty, errSoulCooperativeAuthority
	}
	admission := soulCooperativeEndpointWire(ends.Admission, p.Runner.UID)
	// The owner-reviewed argv must enter the cooperative FD3 path and must not
	// expose the H broker directly to R.
	argv := p.LaunchInputs.Argv
	if len(argv) < 4 || argv[0] != p.NodePath || argv[1] != path.Join(p.RuntimeRoot, p.Entry) ||
		!slices.Contains(argv, "--cooperative-start-fd") || slices.Contains(argv, "--broker-socket") {
		return empty, errSoulCooperativeAuthority
	}
	expires := issued.Add(30 * time.Second)
	binding := Stage2aMeasurementBinding{Contract: "machine/v3", Kind: "stage2a-measurement-binding",
		SchemaVersion: 3, InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID,
		StartID: q.StartID, LaunchID: q.LaunchID, HostID: p.HostID, HQEpoch: p.HQEpoch,
		PlanID: receipt.PlanID, InstalledPlanDigest: receipt.PlanDigest,
		PackageSHA256: p.Runner.PackageSHA256, SoulArtifactSHA256: p.ArtifactSHA256,
		ProfileInForce: "managed-cooperative", ClaimedDefinitionDigest: "sha256:" + p.DefinitionSHA256,
		DefinitionMeasurement: p.DefinitionMeasurement, LaunchInputMeasurement: p.LaunchInputMeasurement,
		Snapshots: Stage2aBindingSnapshots{Definition: a.installed.DefinitionSnapshot,
			LaunchInputs: a.installed.LaunchInputsSnapshot}}
	return soulCooperativeReservationPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-reservation",
		SchemaVersion: 3, HostID: p.HostID, IssuedAt: issued.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                  expires.UTC().Format(time.RFC3339Nano),
		InstalledPlanReceiptSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(a.installed.RootReceipt)),
		Assignment: soulCooperativeAssignmentV3{InstallationID: p.Runner.InstallationID,
			SoulID: p.Runner.SoulID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: receipt.PlanID, PlanDigest: receipt.PlanDigest, HQEpoch: p.HQEpoch,
			ExpiresAt: expires.UTC().Format(time.RFC3339Nano), RunnerAccount: p.Runner.Account,
			RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID, HQUID: p.HQUID, MachineUID: p.MachineUID,
			RuntimeRoot: p.RuntimeRoot, PackageRoot: p.Runner.PackageRoot,
			LaunchInputsRoot: a.installed.LaunchInputsSnapshot.RootPath,
			StateRoot:        p.StateRoot, StateRootMode: "0700", NodePath: p.NodePath,
			EntryPath: path.Join(p.RuntimeRoot, p.Entry), PackageSHA256: p.Runner.PackageSHA256,
			SoulArtifactSHA256: p.ArtifactSHA256},
		Endpoints: soulCooperativeEndpointsV3{Admission: admission,
			Member: bEnds.Member, Relay: bEnds.Relay},
		MeasurementBinding: soulCooperativeBindingV3{Stage2aMeasurementBinding: binding,
			HDescriptorDigest: a.hDescriptorDigest, RInventory: a.r.ref,
			RComponents: cooperativeV3RComponents(*p.RuntimeV3)},
		AdmissionChallengeSHA256: q.AdmissionChallengeSHA256,
		AdapterTransport:         "brokered-b", BridgeLaunchSHA256: bridgeDigest}, nil
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
	if err != nil || len(canonical) > 48<<10 {
		return nil, "", errSoulCooperativeAuthority
	}
	envelope, digest, err := signSoulCooperativeEnvelopeV3(canonical, key, sign)
	if err != nil || len(envelope) > 64<<10 {
		return nil, "", errSoulCooperativeAuthority
	}
	verified, actual, err := verifySoulCooperativeEnvelopeV3(envelope, key)
	if err != nil || actual != digest || !bytes.Equal(verified, canonical) {
		return nil, "", errSoulCooperativeAuthority
	}
	return envelope, digest, nil
}
