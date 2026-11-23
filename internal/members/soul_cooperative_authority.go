package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// This is a separate authority from soul-protected-launch-install. A
// cooperative request cannot select, reuse, or weaken a protected policy.
const SoulCooperativeLaunchInstallPurpose = "soul-cooperative-launch-install"
const soulCooperativeInstallSchema = "agent-bot-machine/soul-cooperative-launch-install/v1"
const soulCooperativeTwoMemberInstallSchemaV3 = "agent-bot-machine/soul-cooperative-launch-install/v3"
const soulCooperativeReservationPurpose = "agent-bot/soul-cooperative-reservation/v1"

var errSoulCooperativeAuthority = errors.New("cooperative Soul launch authority unavailable or mismatched")
var soulCooperativeMessagesQuery = regexp.MustCompile(`^[a-zA-Z0-9._=&%-]{0,128}$`)

// SoulCooperativeLaunchPolicy is the exact owner-reviewable input for one
// cooperative installation. The installed receipt, frozen byte observations,
// live pairing, and durable spent claim must be supplied by A at use time;
// this structure alone grants no launch permission.
type SoulCooperativeLaunchPolicy struct {
	Schema            string     `json:"schema"`
	Purpose           string     `json:"purpose"`
	Profile           string     `json:"profile_in_force"`
	HostID            string     `json:"host_id"`
	HQUID             int        `json:"hq_uid"`
	HQEpoch           string     `json:"hq_epoch"`
	MachinePublicKey  string     `json:"machine_public_key_base64url"`
	SourcePackagePath string     `json:"source_package_path"`
	Runner            SoulRunner `json:"runner"`
	ArtifactSHA256    string     `json:"soul_artifact_sha256"`
	DefinitionSHA256  string     `json:"definition_sha256"`
	NodePath          string     `json:"node_path"`
	NodeSHA256        string     `json:"node_sha256"`
	Entry             string     `json:"entry"`
	LauncherPath      string     `json:"launcher_path"`
	LauncherSHA256    string     `json:"launcher_sha256"`
	ApprovedUntil     string     `json:"approved_until"`
	// V3 is a separately reviewed cooperative installation. These fields are
	// forbidden on the legacy one-member policy.
	MachineUID                 int                                  `json:"machine_uid,omitempty"`
	MachineGID                 int                                  `json:"machine_gid,omitempty"`
	HQInstallationID           string                               `json:"hq_installation_id,omitempty"`
	HOwnerPlanDigest           string                               `json:"h_owner_plan_digest,omitempty"`
	ReviewedStartID            string                               `json:"reviewed_start_id,omitempty"`
	Bridge                     *SoulBridge                          `json:"bridge,omitempty"`
	BridgeExecutable           *HarnessArtifact                     `json:"bridge_executable,omitempty"`
	OwnerPlanMemberSetSHA256   string                               `json:"owner_plan_member_set_sha256,omitempty"`
	ReviewedQPlanSHA256        string                               `json:"reviewed_q_plan_sha256,omitempty"`
	Definition                 []Stage2aDefinitionRecord            `json:"definition,omitempty"`
	LaunchInputs               *Stage2aLaunchInputRecords           `json:"launch_inputs,omitempty"`
	DefinitionMeasurement      string                               `json:"definition_measurement,omitempty"`
	LaunchInputMeasurement     string                               `json:"launch_input_measurement,omitempty"`
	RuntimeV3                  *stage2aRuntimeV3Install             `json:"runtime_v3,omitempty"`
	BridgeQualification        *Stage2aBridgeQualification          `json:"bridge_qualification,omitempty"`
	MemberBridgeQualifications []SoulCooperativeMemberQualification `json:"member_bridge_qualifications,omitempty"`
}

// The owner reviews one qualification row for each frozen Soul member.
type SoulCooperativeMemberQualification struct {
	MemberID      string                     `json:"member_id"`
	Qualification Stage2aBridgeQualification `json:"qualification"`
}

// ParseSoulCooperativeLaunchPolicy accepts one bounded JSON object, refusing
// duplicate, unknown and missing fields before an owner may review it.
func ParseSoulCooperativeLaunchPolicy(raw []byte) (SoulCooperativeLaunchPolicy, error) {
	var policy SoulCooperativeLaunchPolicy
	if len(raw) == 0 || len(raw) > 2<<20 ||
		stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil || strictCooperativeObject(raw) != nil {
		return policy, errSoulCooperativeAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF || policy.validate() != nil {
		return SoulCooperativeLaunchPolicy{}, errSoulCooperativeAuthority
	}
	return policy, nil
}

func strictCooperativeObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errSoulCooperativeAuthority
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errSoulCooperativeAuthority
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errSoulCooperativeAuthority
		}
		// The nested runner must also refuse duplicate JSON keys.
		if name == "runner" && strictCooperativeRunner(value) != nil {
			return errSoulCooperativeAuthority
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errSoulCooperativeAuthority
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errSoulCooperativeAuthority
	}
	return nil
}

func strictCooperativeRunner(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errSoulCooperativeAuthority
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return errSoulCooperativeAuthority
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errSoulCooperativeAuthority
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errSoulCooperativeAuthority
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errSoulCooperativeAuthority
	}
	return nil
}

func cooperativeAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p &&
		len(p) <= 1024 && !strings.ContainsAny(p, "\x00\n\r")
}

func (p SoulCooperativeLaunchPolicy) validate() error {
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	expiry, timeErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	legacy := p.Schema == soulCooperativeInstallSchema
	v3 := p.Schema == soulCooperativeTwoMemberInstallSchemaV3
	if (!legacy && !v3) || p.Purpose != SoulCooperativeLaunchInstallPurpose ||
		p.Profile != "managed-cooperative" || !soulInstallationID.MatchString(p.HostID) ||
		p.HQUID < 300 || p.HQUID > 399 || !soulHQEpoch.MatchString(p.HQEpoch) ||
		err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != p.MachinePublicKey ||
		!soulIdentity.MatchString(p.Runner.SoulID) || !soulInstallationID.MatchString(p.Runner.InstallationID) ||
		p.Runner.Account != soulRunnerName(p.Runner.InstallationID) || p.Runner.UID < 300 || p.Runner.UID > 399 ||
		p.Runner.GID != p.Runner.UID || p.Runner.UID == p.HQUID ||
		!cooperativeAbsolute(p.SourcePackagePath) || p.SourcePackagePath == p.Runner.PackageRoot ||
		!cooperativeAbsolute(p.Runner.PackageRoot) || !cooperativeReviewedPackageRoot(p) ||
		!soulDigest.MatchString(p.Runner.PackageSHA256) ||
		!soulDigest.MatchString(p.ArtifactSHA256) || !soulDigest.MatchString(p.DefinitionSHA256) ||
		!cooperativeAbsolute(p.NodePath) || !soulDigest.MatchString(p.NodeSHA256) ||
		p.Entry == "" || p.Entry == "." || len(p.Entry) > 1024 || strings.HasPrefix(p.Entry, "/") || path.Clean(p.Entry) != p.Entry ||
		strings.HasPrefix(p.Entry, "../") || p.Entry == ".." || strings.ContainsAny(p.Entry, "\x00\n\r") ||
		!cooperativeAbsolute(p.LauncherPath) || !soulDigest.MatchString(p.LauncherSHA256) ||
		timeErr != nil || expiry.IsZero() {
		return errSoulCooperativeAuthority
	}
	if legacy {
		if p.MachineUID != 0 || p.MachineGID != 0 || p.HQInstallationID != "" ||
			p.HOwnerPlanDigest != "" || p.ReviewedStartID != "" || p.Bridge != nil || p.BridgeExecutable != nil ||
			p.OwnerPlanMemberSetSHA256 != "" || p.ReviewedQPlanSHA256 != "" || p.Definition != nil || p.LaunchInputs != nil ||
			p.DefinitionMeasurement != "" || p.LaunchInputMeasurement != "" || p.RuntimeV3 != nil ||
			p.BridgeQualification != nil || p.MemberBridgeQualifications != nil {
			return errSoulCooperativeAuthority
		}
		return nil
	}
	if p.MachineUID <= 399 || p.MachineGID <= 0 || p.MachineUID == p.HQUID ||
		p.MachineUID == p.Runner.UID || !stage2aBindingID.MatchString(p.HQInstallationID) ||
		!stage2aPrefixedDigest.MatchString(p.HOwnerPlanDigest) ||
		!soulStartID.MatchString(p.ReviewedStartID) ||
		!stage2aPrefixedDigest.MatchString(p.OwnerPlanMemberSetSHA256) ||
		!stage2aPrefixedDigest.MatchString(p.ReviewedQPlanSHA256) ||
		p.Bridge == nil || ValidateSoulBridges([]SoulRunner{p.Runner}, []SoulBridge{*p.Bridge}, p.HQUID, nil) != nil ||
		p.BridgeExecutable == nil || p.BridgeExecutable.Path != SoulBridgeBinary ||
		!soulDigest.MatchString(p.BridgeExecutable.SHA256) ||
		!cooperativeRuntimePinsShapeV3(p.RuntimeV3) ||
		p.LaunchInputs == nil || p.BridgeQualification == nil || len(p.Definition) == 0 ||
		len(p.MemberBridgeQualifications) != 2 ||
		p.MemberBridgeQualifications[0].MemberID != "m_lead" ||
		p.MemberBridgeQualifications[1].MemberID != "m_spec" ||
		p.MemberBridgeQualifications[0].MemberID >= p.MemberBridgeQualifications[1].MemberID ||
		!stage2aBindingID.MatchString(p.MemberBridgeQualifications[0].MemberID) ||
		!stage2aBindingID.MatchString(p.MemberBridgeQualifications[1].MemberID) ||
		p.MemberBridgeQualifications[0].Qualification != *p.BridgeQualification ||
		p.MemberBridgeQualifications[1].Qualification != *p.BridgeQualification ||
		!cooperativeQualificationValid(*p.BridgeQualification) ||
		!stage2aPrefixedDigest.MatchString(p.DefinitionMeasurement) ||
		!stage2aPrefixedDigest.MatchString(p.LaunchInputMeasurement) ||
		p.LaunchInputs.EffectiveConfig["profile"] != "managed-cooperative" ||
		p.LaunchInputs.AdapterTransport != "brokered-b" ||
		p.LaunchInputs.ComponentDigests["bridge"] != "sha256:"+p.BridgeExecutable.SHA256 {
		return errSoulCooperativeAuthority
	}
	runtimeNamespace, runtimeSnapshot, _, runtimeErr := stage2aDomainNamesV3("R-runtime", p.Runner.InstallationID)
	if runtimeErr != nil || p.NodePath != path.Join(runtimeNamespace, runtimeSnapshot, "bin/node") ||
		p.Entry != "bin/agent-bot-souls.mjs" || p.LauncherPath != SoulLauncher {
		return errSoulCooperativeAuthority
	}
	if _, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID); err != nil {
		return errSoulCooperativeAuthority
	}
	definitionDigest, _, definitionErr := Stage2aDefinitionDigest(p.Definition)
	launchDigest, _, launchErr := Stage2aLaunchInputDigest(*p.LaunchInputs)
	if definitionErr != nil || launchErr != nil || definitionDigest != p.DefinitionMeasurement ||
		launchDigest != p.LaunchInputMeasurement ||
		!reflect.DeepEqual(p.LaunchInputs.HostProjection.Installation["id"], p.Runner.InstallationID) {
		return errSoulCooperativeAuthority
	}
	if p.LaunchInputs.SelectedCommand != p.NodePath ||
		!cooperativeReviewedDefinitionFiles(p.Definition) {
		return errSoulCooperativeAuthority
	}
	return nil
}

func cooperativeReviewedDefinitionFiles(records []Stage2aDefinitionRecord) bool {
	foundInfo, foundManifest := false, false
	for _, row := range records {
		if row.Path == "Contents/SoulInfo.json" {
			foundInfo = row.Kind == "regular" && soulDigest.MatchString(row.SHA256)
		}
		if row.Path == "Contents/opt/stock-claude.json" {
			foundManifest = row.Kind == "regular" && soulDigest.MatchString(row.SHA256)
		}
	}
	return foundInfo && foundManifest
}

func cooperativeQualificationValid(q Stage2aBridgeQualification) bool {
	return stage2aBindingID.MatchString(q.Model) && stage2aBindingID.MatchString(q.HTTPHost) &&
		stage2aPrefixedDigest.MatchString(q.RequestSHA256) &&
		stage2aPrefixedDigest.MatchString(q.HeadersSHA256) &&
		q.ClientKeySHA256 == stage2aFixtureClientKeySHA256 &&
		soulCooperativeMessagesQuery.MatchString(q.MessagesQuery) && len(q.ResponseText) > 0 &&
		len(q.ResponseText) <= 2048 && utf8.ValidString(q.ResponseText)
}

func cooperativeRuntimePinsShapeV3(spec *stage2aRuntimeV3Install) bool {
	if spec == nil || !stage2aPrefixedDigest.MatchString(spec.InventoryDigest) ||
		!stage2aAbsolutePath(spec.InventorySource) || len(spec.Components) == 0 ||
		len(spec.Components) > 32 || len(spec.SourceRoots) != len(spec.Components) {
		return false
	}
	previous := ""
	for _, row := range spec.Components {
		if !stage2aBindingID.MatchString(row.ComponentID) || row.ComponentID <= previous ||
			!stage2aRuntimeV3SourceRepository.MatchString(row.SourceRepository) ||
			!stage2aRuntimeV3SourceCommit.MatchString(row.SourceCommit) ||
			(row.SourceTag != "" && !stage2aRuntimeV3SourceTag.MatchString(row.SourceTag)) ||
			(row.ArtifactFormat != "tar" && row.ArtifactFormat != "raw" && row.ArtifactFormat != "zip") ||
			!stage2aAbsolutePath(row.ArtifactSource) || !stage2aAbsolutePath(row.ManifestSource) ||
			!stage2aAbsolutePath(spec.SourceRoots[row.ComponentID]) ||
			!stage2aPrefixedDigest.MatchString(row.ReleaseArtifactSHA256) ||
			!stage2aPrefixedDigest.MatchString(row.ReleaseManifestSHA256) {
			return false
		}
		previous = row.ComponentID
	}
	return true
}

func cooperativeReviewedPackageRoot(p SoulCooperativeLaunchPolicy) bool {
	if p.Schema == soulCooperativeInstallSchema {
		return p.Runner.PackageRoot == cooperativeArtifactPath(p.Runner.InstallationID)
	}
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 {
		return false
	}
	namespace := path.Join(stage2aDomainSnapshotParentV3, soulEndpointInstallationSlot(p.Runner.InstallationID))
	sum := sha256.Sum256([]byte("agent-bot-machine/stage2a-install-snapshot/v1\x00definition\x00" + p.Runner.InstallationID))
	return p.Runner.PackageRoot == path.Join(namespace, fmt.Sprintf("snap_%x", sum[:12]))
}

func cooperativeReviewedInputsRoot(installationID string) string {
	if !soulInstallationID.MatchString(installationID) {
		return ""
	}
	namespace := path.Join(stage2aDomainSnapshotParentV3, soulEndpointInstallationSlot(installationID))
	sum := sha256.Sum256([]byte("agent-bot-machine/stage2a-install-snapshot/v1\x00inputs\x00" + installationID))
	return path.Join(namespace, fmt.Sprintf("snap_%x", sum[:12]))
}

func cooperativeReviewedMembers(got []string, p SoulCooperativeLaunchPolicy) bool {
	if p.Schema == soulCooperativeInstallSchema {
		return len(got) == 1 && got[0] == p.Runner.Account
	}
	return p.Schema == soulCooperativeTwoMemberInstallSchemaV3 && p.Bridge != nil &&
		len(got) == 2 && got[0] == p.Runner.Account && got[1] == p.Bridge.Account
}

// SoulCooperativeReserveRequest carries selectors only. It cannot supply an
// executable, UID, argument, profile downgrade, or package replacement.
type SoulCooperativeReserveRequest struct {
	Profile        string `json:"profile"`
	HostID         string `json:"host_id"`
	PlanDigest     string `json:"plan_digest"`
	InstallationID string `json:"installation_id"`
	StartID        string `json:"start_id"`
	HQEpoch        string `json:"hq_epoch"`
	PackagePath    string `json:"package_path"`
}

func (q SoulCooperativeReserveRequest) valid() bool {
	return q.Profile == "managed-cooperative" && soulInstallationID.MatchString(q.HostID) &&
		cooperativeAbsolute(q.PackagePath) &&
		(SoulRunRequest{PlanDigest: q.PlanDigest, InstallationID: q.InstallationID,
			StartID: q.StartID, HQEpoch: q.HQEpoch}).valid()
}

func ParseSoulCooperativeReserveRequest(raw []byte) (SoulCooperativeReserveRequest, error) {
	var q SoulCooperativeReserveRequest
	if len(raw) == 0 || len(raw) > 2048 || strictCooperativeObject(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&q) != nil || decoder.Decode(new(any)) != io.EOF || !q.valid() {
		return SoulCooperativeReserveRequest{}, errSoulCooperativeAuthority
	}
	return q, nil
}

// v1 binds the frozen R package only. It does not attest to H's selected
// HQ/Comms/contracts code. Production needs a new purpose/version carrying
// A's exact H descriptor, checked against HQ startup and remeasured by A at
// launch; the R package digest must never stand in for that descriptor.
type SoulCooperativeReservation struct {
	Purpose                string                  `json:"purpose"`
	Profile                string                  `json:"profile_in_force"`
	HostID                 string                  `json:"host_id"`
	PlanID                 string                  `json:"plan_id"`
	PlanDigest             string                  `json:"plan_digest"`
	InstalledReceiptSHA256 string                  `json:"installed_receipt_sha256"`
	InstallationID         string                  `json:"installation_id"`
	SoulID                 string                  `json:"soul_id"`
	StartID                string                  `json:"start_id"`
	HQEpoch                string                  `json:"hq_epoch"`
	RunnerUID              int                     `json:"runner_uid"`
	RunnerGID              int                     `json:"runner_gid"`
	SourcePackagePath      string                  `json:"source_package_path"`
	PackageRoot            string                  `json:"package_root"`
	PackageSHA256          string                  `json:"package_sha256"`
	SoulArtifactSHA256     string                  `json:"soul_artifact_sha256"`
	DefinitionSHA256       string                  `json:"definition_sha256"`
	NodePath               string                  `json:"node_path"`
	NodeSHA256             string                  `json:"node_sha256"`
	Entry                  string                  `json:"entry"`
	LauncherPath           string                  `json:"launcher_path"`
	LauncherSHA256         string                  `json:"launcher_sha256"`
	Endpoint               SoulCooperativeEndpoint `json:"endpoint"`
	IssuedAt               string                  `json:"issued_at"`
	ExpiresAt              string                  `json:"expires_at"`
}

type SoulCooperativeEndpoint struct {
	Directory  string `json:"directory"`
	SocketPath string `json:"socket_path"`
	OwnerUID   int    `json:"owner_uid"`
	GroupGID   int    `json:"group_gid"`
	DirMode    int    `json:"dir_mode"`
	SocketMode int    `json:"socket_mode"`
	PeerUID    int    `json:"peer_uid"`
}

func cooperativeEndpoint(p SoulCooperativeLaunchPolicy, startID string) (SoulCooperativeEndpoint, error) {
	directory := path.Join(launchRuntimeDir, "c", soulEndpointInstallationSlot(p.Runner.InstallationID))
	socket := path.Join(directory, soulEndpointStartSlot(p.Runner.InstallationID, startID)+".sock")
	if len(socket) > 103 {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return SoulCooperativeEndpoint{Directory: directory, SocketPath: socket,
		OwnerUID: p.HQUID, GroupGID: p.Runner.GID, DirMode: 02750, SocketMode: 0660,
		PeerUID: p.Runner.UID}, nil
}

type SoulCooperativeSignedReservation struct {
	Purpose            string `json:"purpose"`
	PayloadBase64URL   string `json:"payload_base64url"`
	PayloadSHA256      string `json:"payload_sha256"`
	SignatureBase64URL string `json:"signature_base64url"`
}

// SoulCooperativeInstalledAuthority is produced only by an A-side loader
// after comparing the policy with the applied root receipt and approved plan.
// It is deliberately a different type from the owner-reviewable request.
type SoulCooperativeInstalledAuthority struct {
	Policy                    SoulCooperativeLaunchPolicy
	InstallationOwner         string
	PlanID                    string
	PlanDigest                string
	ReceiptSHA256             string
	CanonicalPlan             []byte
	RootReceipt               []byte
	ObservedPackageSHA256     string
	ObservedArtifactSHA256    string
	ObservedDefinitionSHA256  string
	ObservedNodeSHA256        string
	ObservedLauncherSHA256    string
	ObservedHDescriptorSHA256 string
	ObservedRInventorySHA256  string
}

// The caller must obtain the plan from A-owned installed policy and the
// receipt from root-held storage through checked descriptors. This check
// binds their exact bytes before any one-use start can be spent. It cannot
// replace those descriptor and custody checks.
func (in SoulCooperativeInstalledAuthority) matchesInstalledRecord() bool {
	if len(in.CanonicalPlan) == 0 || len(in.CanonicalPlan) > 2<<20 ||
		len(in.RootReceipt) == 0 || len(in.RootReceipt) > 256<<10 ||
		!ValidApproval(in.PlanID, in.PlanDigest) ||
		fmt.Sprintf("%x", sha256.Sum256(in.CanonicalPlan)) != in.PlanDigest ||
		fmt.Sprintf("%x", sha256.Sum256(in.RootReceipt)) != in.ReceiptSHA256 ||
		strictCooperativeObject(in.RootReceipt) != nil {
		return false
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(in.CanonicalPlan))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF ||
		plan.Purpose != SoulCooperativeLaunchInstallPurpose ||
		plan.SoulCooperativeLaunch == nil || !reflect.DeepEqual(*plan.SoulCooperativeLaunch, in.Policy) ||
		plan.SoulProtectedLaunch != nil || plan.SoulProtectedRetire != nil ||
		plan.HQAccount != DarwinHQAccount || plan.Dir != DarwinDir ||
		!cooperativeReviewedMembers(plan.Members, in.Policy) ||
		len(plan.Steps) != 1 || plan.Steps[0].Kind != "soul-cooperative-launch" ||
		plan.Steps[0].Target != in.Policy.Runner.InstallationID ||
		plan.Steps[0].Action != ActionWrite || plan.Steps[0].UID != 0 {
		return false
	}
	canonical, err := plan.Canonical()
	if err != nil || !bytes.Equal(canonical, in.CanonicalPlan) {
		return false
	}
	var receipt Receipt
	decoder = json.NewDecoder(bytes.NewReader(in.RootReceipt))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF ||
		receipt.HarnessApproval != nil || receipt.Upgrade != nil ||
		receipt.PlanID != in.PlanID || receipt.PlanDigest != in.PlanDigest ||
		!accountName.MatchString(in.InstallationOwner) || receipt.Owner != in.InstallationOwner ||
		receipt.HQAccount != DarwinHQAccount || receipt.Dir != DarwinDir ||
		!cooperativeReviewedMembers(receipt.Members, in.Policy) ||
		receipt.Changes != plan.Changes() || receipt.StartedAt == "" || receipt.FinishedAt == "" ||
		receipt.Result != "applied" || receipt.FailedAt != "" ||
		!bytes.Equal(encodeReceipt(receipt), in.RootReceipt) {
		return false
	}
	return true
}

// PrepareSoulCooperativeReservation is the narrow A-side signing boundary.
// Its caller must independently load an applied owner-approved policy and
// receipt, check frozen bytes and live paired epoch, and pass a durable spend
// operation. A successful spend is terminal even if delivery is lost.
func PrepareSoulCooperativeReservation(in SoulCooperativeInstalledAuthority, q SoulCooperativeReserveRequest,
	now time.Time, sign func([]byte) ([]byte, error), spend func(string, string) error,
) (SoulCooperativeSignedReservation, error) {
	var empty SoulCooperativeSignedReservation
	p := in.Policy
	if p.Schema != soulCooperativeInstallSchema || p.validate() != nil ||
		!in.matchesInstalledRecord() || !q.valid() || q.HostID != p.HostID ||
		q.PlanDigest != in.PlanDigest || !ValidApproval(in.PlanID, in.PlanDigest) ||
		q.InstallationID != p.Runner.InstallationID || q.HQEpoch != p.HQEpoch ||
		q.PackagePath != p.SourcePackagePath ||
		in.ObservedPackageSHA256 != p.Runner.PackageSHA256 ||
		in.ObservedArtifactSHA256 != p.ArtifactSHA256 ||
		in.ObservedDefinitionSHA256 != p.DefinitionSHA256 ||
		in.ObservedNodeSHA256 != p.NodeSHA256 ||
		in.ObservedLauncherSHA256 != p.LauncherSHA256 ||
		!soulStartID.MatchString(q.StartID) || !soulDigest.MatchString(in.ReceiptSHA256) ||
		sign == nil || spend == nil {
		return empty, errSoulCooperativeAuthority
	}
	expiry, _ := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if !now.Before(expiry) {
		return empty, errSoulCooperativeAuthority
	}
	lease := now.Add(30 * time.Second)
	if expiry.Before(lease) {
		lease = expiry
	}
	endpoint, err := cooperativeEndpoint(p, q.StartID)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	reserved := SoulCooperativeReservation{
		Purpose: soulCooperativeReservationPurpose, Profile: "managed-cooperative", HostID: p.HostID,
		PlanID: in.PlanID, PlanDigest: in.PlanDigest, InstalledReceiptSHA256: in.ReceiptSHA256,
		InstallationID: p.Runner.InstallationID, SoulID: p.Runner.SoulID, StartID: q.StartID, HQEpoch: q.HQEpoch,
		RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
		SourcePackagePath: p.SourcePackagePath, PackageRoot: p.Runner.PackageRoot,
		PackageSHA256: p.Runner.PackageSHA256, SoulArtifactSHA256: p.ArtifactSHA256,
		DefinitionSHA256: p.DefinitionSHA256, NodePath: p.NodePath, NodeSHA256: p.NodeSHA256,
		Entry: p.Entry, LauncherPath: p.LauncherPath, LauncherSHA256: p.LauncherSHA256,
		Endpoint: endpoint,
		IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: lease.UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.Marshal(reserved)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	preimage := append([]byte(soulCooperativeReservationPurpose+"\x00"), canonical...)
	signature, err := sign(preimage)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	if err != nil || keyErr != nil || !ed25519.Verify(key, preimage, signature) {
		return empty, errSoulCooperativeAuthority
	}
	if err := spend(q.InstallationID, q.StartID); err != nil {
		return empty, errSoulCooperativeAuthority
	}
	sum := sha256.Sum256(canonical)
	return SoulCooperativeSignedReservation{
		Purpose: soulCooperativeReservationPurpose, PayloadBase64URL: base64.RawURLEncoding.EncodeToString(canonical),
		PayloadSHA256: fmt.Sprintf("%x", sum), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
