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
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// This is a separate authority from soul-protected-launch-install. A
// cooperative request cannot select, reuse, or weaken a protected policy.
const SoulCooperativeLaunchInstallPurpose = "soul-cooperative-launch-install"
const soulCooperativeInstallSchema = "agent-bot-machine/soul-cooperative-launch-install/v1"
const soulCooperativeRuntimeInstallSchemaV3 = "agent-bot-machine/soul-cooperative-launch-install/v3"
const soulCooperativeReservationPurpose = "agent-bot/soul-cooperative-reservation/v1"

var errSoulCooperativeAuthority = errors.New("cooperative Soul launch authority unavailable or mismatched")

type soulCooperativeAdapterV3 struct {
	ComponentID              string `json:"component_id"`
	PackageSHA256            string `json:"package_sha256"`
	ReleaseAttestationSHA256 string `json:"release_attestation_sha256"`
	ReleaseManifestSHA256    string `json:"release_manifest_sha256"`
	ExecutablePath           string `json:"executable_path"`
	ExecutableSHA256         string `json:"executable_sha256"`
	CodeInputsDigest         string `json:"code_inputs_digest"`
	CodeInputCount           int    `json:"code_input_count"`
}

func (a soulCooperativeAdapterV3) valid(runtimeRoot string, spec *stage2aRuntimeV3Install) bool {
	if spec == nil || !stage2aBindingID.MatchString(a.ComponentID) ||
		!strings.HasPrefix(a.ExecutablePath, runtimeRoot+"/") ||
		!stage2aPrefixedDigest.MatchString(a.PackageSHA256) ||
		!stage2aPrefixedDigest.MatchString(a.ReleaseManifestSHA256) ||
		!stage2aPrefixedDigest.MatchString(a.ReleaseAttestationSHA256) ||
		!stage2aPrefixedDigest.MatchString(a.ExecutableSHA256) ||
		!stage2aPrefixedDigest.MatchString(a.CodeInputsDigest) ||
		a.CodeInputCount < 1 || a.CodeInputCount > 512 {
		return false
	}
	for _, component := range spec.Components {
		if component.ComponentID == a.ComponentID &&
			component.ReleaseArtifactSHA256 == a.PackageSHA256 &&
			component.ReleaseManifestSHA256 == a.ReleaseManifestSHA256 {
			return true
		}
	}
	return false
}

type soulCooperativeBrokerV3 struct {
	ModulePath   string `json:"module_path"`
	ModuleSHA256 string `json:"module_sha256"`
}

func (b soulCooperativeBrokerV3) valid(hqInstallationID string) bool {
	namespace, snapshot, _, err := stage2aDomainNamesV3("H-code", hqInstallationID)
	return err == nil && strings.HasPrefix(b.ModulePath, path.Join(namespace, snapshot)+"/") &&
		stage2aPrefixedDigest.MatchString(b.ModuleSHA256)
}

// SoulCooperativeLaunchPolicy is the exact owner-reviewable input for one
// cooperative installation. The installed receipt, frozen byte observations,
// live pairing, and durable spent claim must be supplied by A at use time;
// this structure alone grants no launch permission.
type SoulCooperativeLaunchPolicy struct {
	Schema                 string                      `json:"schema"`
	Purpose                string                      `json:"purpose"`
	Profile                string                      `json:"profile_in_force"`
	HostID                 string                      `json:"host_id"`
	HQInstallationID       string                      `json:"hq_installation_id,omitempty"`
	HOwnerPlanDigest       string                      `json:"h_owner_plan_digest,omitempty"`
	HQUID                  int                         `json:"hq_uid"`
	MachineUID             int                         `json:"machine_uid,omitempty"`
	MachineGID             int                         `json:"machine_gid,omitempty"`
	HQEpoch                string                      `json:"hq_epoch"`
	MachinePublicKey       string                      `json:"machine_public_key_base64url"`
	SourcePackagePath      string                      `json:"source_package_path"`
	DefinitionSource       string                      `json:"definition_source,omitempty"`
	LaunchInputsSource     string                      `json:"launch_inputs_source,omitempty"`
	Definition             []Stage2aDefinitionRecord   `json:"definition,omitempty"`
	LaunchInputs           *Stage2aLaunchInputRecords  `json:"launch_inputs,omitempty"`
	DefinitionMeasurement  string                      `json:"definition_measurement,omitempty"`
	LaunchInputMeasurement string                      `json:"launch_input_measurement,omitempty"`
	StateRoot              string                      `json:"state_root,omitempty"`
	RuntimeRoot            string                      `json:"runtime_root,omitempty"`
	Runner                 SoulRunner                  `json:"runner"`
	ArtifactSHA256         string                      `json:"soul_artifact_sha256"`
	DefinitionSHA256       string                      `json:"definition_sha256"`
	NodePath               string                      `json:"node_path"`
	NodeSHA256             string                      `json:"node_sha256"`
	Entry                  string                      `json:"entry"`
	LauncherPath           string                      `json:"launcher_path"`
	LauncherSHA256         string                      `json:"launcher_sha256"`
	ApprovedUntil          string                      `json:"approved_until"`
	RuntimeV3              *stage2aRuntimeV3Install    `json:"runtime_v3,omitempty"`
	AdapterRelease         *soulCooperativeAdapterV3   `json:"adapter_release,omitempty"`
	HQBroker               *soulCooperativeBrokerV3    `json:"hq_broker,omitempty"`
	AdapterTransport       string                      `json:"adapter_transport,omitempty"`
	ReviewedStartID        string                      `json:"reviewed_start_id,omitempty"`
	QualificationProvider  *Stage2aBridgeQualification `json:"qualification_provider,omitempty"`
	AdapterCodeInputs      []string                    `json:"adapter_code_inputs,omitempty"`
}

// ParseSoulCooperativeLaunchPolicy accepts one bounded JSON object, refusing
// duplicate, unknown and missing fields before an owner may review it.
func ParseSoulCooperativeLaunchPolicy(raw []byte) (SoulCooperativeLaunchPolicy, error) {
	var policy SoulCooperativeLaunchPolicy
	if len(raw) == 0 || len(raw) > 2<<20 ||
		stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil ||
		strictCooperativeObject(raw) != nil {
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

func cooperativePackageRoot(p SoulCooperativeLaunchPolicy) bool {
	if p.Schema == soulCooperativeInstallSchema {
		return p.Runner.PackageRoot == cooperativeArtifactPath(p.Runner.InstallationID)
	}
	namespace, snapshot, _, err := stage2aDomainNamesV3("R-runtime", p.Runner.InstallationID)
	definitionNamespace, nameErr := cooperativeFrozenNamespace(p.Runner.InstallationID)
	return err == nil && nameErr == nil && p.RuntimeRoot == path.Join(namespace, snapshot) &&
		p.Runner.PackageRoot == path.Join(definitionNamespace,
			cooperativeSnapshotName(p.Runner.InstallationID, "definition"))
}

func cooperativeLaunchInputsRoot(installationID string) string {
	namespace, err := cooperativeFrozenNamespace(installationID)
	if err != nil {
		return ""
	}
	return path.Join(namespace, cooperativeSnapshotName(installationID, "inputs"))
}

func cooperativeFrozenNamespace(installationID string) (string, error) {
	if !soulInstallationID.MatchString(installationID) {
		return "", errSoulCooperativeAuthority
	}
	return path.Join(stage2aDomainSnapshotParentV3, soulEndpointInstallationSlot(installationID)), nil
}

func cooperativeSnapshotName(installationID, kind string) string {
	sum := sha256.Sum256([]byte("agent-bot-machine/stage2a-install-snapshot/v1\x00" + kind + "\x00" + installationID))
	return fmt.Sprintf("snap_%x", sum[:12])
}

func (p SoulCooperativeLaunchPolicy) validate() error {
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	expiry, timeErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if p.Schema == soulCooperativeRuntimeInstallSchemaV3 {
		if p.RuntimeV3 == nil || p.AdapterRelease == nil || p.HQBroker == nil ||
			p.AdapterTransport != stage2aDirectComms {
			return errSoulCooperativeAuthority
		}
		definitionDigest, _, definitionErr := Stage2aDefinitionDigest(p.Definition)
		if p.LaunchInputs == nil || definitionErr != nil ||
			definitionDigest != p.DefinitionMeasurement ||
			!cooperativeAbsolute(p.DefinitionSource) ||
			p.DefinitionSource != p.SourcePackagePath ||
			!cooperativeAbsolute(p.LaunchInputsSource) ||
			!cooperativeAbsolute(p.StateRoot) ||
			p.StateRoot != path.Join("/private/var", "agent-bot-soul-runner-"+p.Runner.Account, "state") {
			return errSoulCooperativeAuthority
		}
		if _, err := cooperativeReviewedAdmission(p); err != nil {
			return errSoulCooperativeAuthority
		}
		launchDigest, _, launchErr := Stage2aLaunchInputDigest(*p.LaunchInputs)
		if launchErr != nil || launchDigest != p.LaunchInputMeasurement ||
			p.RuntimeV3.QualificationOnly != stage2aLaunchNeedsQualification(p.LaunchInputs.Files) ||
			(p.RuntimeV3.QualificationOnly &&
				(p.QualificationProvider == nil || !soulStartID.MatchString(p.ReviewedStartID))) ||
			p.LaunchInputs.AdapterTransport != p.AdapterTransport ||
			!p.AdapterRelease.valid(p.RuntimeRoot, p.RuntimeV3) ||
			!p.HQBroker.valid(p.HQInstallationID) ||
			len(p.AdapterCodeInputs) != p.AdapterRelease.CodeInputCount {
			return errSoulCooperativeAuthority
		}
		if cooperativeProviderConfigMatchesLaunchInputs(p.QualificationProvider, p.LaunchInputs) != nil {
			return errSoulCooperativeAuthority
		}
		_, qualification := p.LaunchInputs.ComponentDigests["harness"]
		if qualification != (p.QualificationProvider != nil) {
			return errSoulCooperativeAuthority
		}
	}
	if (p.Schema != soulCooperativeInstallSchema && p.Schema != soulCooperativeRuntimeInstallSchemaV3) ||
		(p.Schema == soulCooperativeInstallSchema && (p.RuntimeV3 != nil || p.ReviewedStartID != "")) ||
		(p.Schema == soulCooperativeRuntimeInstallSchemaV3 && (p.RuntimeV3 == nil ||
			!stage2aPrefixedDigest.MatchString(p.RuntimeV3.InventoryDigest) ||
			p.AdapterRelease == nil || p.HQBroker == nil ||
			!stage2aBindingID.MatchString(p.HQInstallationID) ||
			!digestPattern.MatchString(p.HOwnerPlanDigest) ||
			p.MachineUID < 400 || p.MachineGID < 1 ||
			p.MachineUID == p.HQUID || p.MachineUID == p.Runner.UID ||
			p.NodePath != path.Join(p.RuntimeRoot, "bin/node") ||
			p.Entry != "bin/agent-bot-souls.mjs" ||
			p.LauncherPath != SoulLauncher)) ||
		p.Purpose != SoulCooperativeLaunchInstallPurpose ||
		p.Profile != "managed-cooperative" || !soulInstallationID.MatchString(p.HostID) ||
		p.HQUID < 300 || p.HQUID > 399 || !soulHQEpoch.MatchString(p.HQEpoch) ||
		err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != p.MachinePublicKey ||
		!soulIdentity.MatchString(p.Runner.SoulID) || !soulInstallationID.MatchString(p.Runner.InstallationID) ||
		p.Runner.Account != soulRunnerName(p.Runner.InstallationID) || p.Runner.UID < 300 || p.Runner.UID > 399 ||
		p.Runner.GID != p.Runner.UID || p.Runner.UID == p.HQUID ||
		!cooperativeAbsolute(p.SourcePackagePath) || p.SourcePackagePath == p.Runner.PackageRoot ||
		!cooperativeAbsolute(p.Runner.PackageRoot) || !cooperativePackageRoot(p) ||
		!soulDigest.MatchString(p.Runner.PackageSHA256) ||
		!soulDigest.MatchString(p.ArtifactSHA256) || !soulDigest.MatchString(p.DefinitionSHA256) ||
		!cooperativeAbsolute(p.NodePath) || !soulDigest.MatchString(p.NodeSHA256) ||
		p.Entry == "" || p.Entry == "." || len(p.Entry) > 1024 || strings.HasPrefix(p.Entry, "/") || path.Clean(p.Entry) != p.Entry ||
		strings.HasPrefix(p.Entry, "../") || p.Entry == ".." || strings.ContainsAny(p.Entry, "\x00\n\r") ||
		!cooperativeAbsolute(p.LauncherPath) || !soulDigest.MatchString(p.LauncherSHA256) ||
		timeErr != nil || expiry.IsZero() {
		return errSoulCooperativeAuthority
	}
	return nil
}

// The inline Machine provider uses owner-frozen response configuration.
// Bind its exact bytes separately from the Q component evidence in the
// measured launch inputs and later in the signed one-use reservation.
func cooperativeProviderConfigMatchesLaunchInputs(provider *Stage2aBridgeQualification,
	inputs *Stage2aLaunchInputRecords) error {
	if inputs == nil {
		return errSoulCooperativeAuthority
	}
	value, present := inputs.EffectiveConfig["qualification_provider_config_sha256"]
	if provider == nil {
		if present {
			return errSoulCooperativeAuthority
		}
		return nil
	}
	_, digest, err := stage2aProviderConfig(*provider)
	if err != nil || !present || value != "sha256:"+digest {
		return errSoulCooperativeAuthority
	}
	return nil
}

// SoulCooperativeReserveRequest carries selectors only. It cannot supply an
// executable, UID, argument, profile downgrade, or package replacement.
type SoulCooperativeReserveRequest struct {
	Profile                  string `json:"profile"`
	HostID                   string `json:"host_id"`
	PlanDigest               string `json:"plan_digest"`
	InstallationID           string `json:"installation_id"`
	StartID                  string `json:"start_id"`
	LaunchID                 string `json:"launch_id,omitempty"`
	AdmissionChallengeSHA256 string `json:"admission_challenge_sha256,omitempty"`
	HQEpoch                  string `json:"hq_epoch"`
	PackagePath              string `json:"package_path"`
}

func (q SoulCooperativeReserveRequest) valid() bool {
	return q.Profile == "managed-cooperative" && soulInstallationID.MatchString(q.HostID) &&
		(q.LaunchID == "" || soulLaunchID.MatchString(q.LaunchID)) &&
		(q.AdmissionChallengeSHA256 == "" || stage2aPrefixedDigest.MatchString(q.AdmissionChallengeSHA256)) &&
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

type SoulCooperativeStartRequestV3 struct {
	SoulCooperativeReserveRequest
	AdmissionChallengeBase64URL string `json:"admission_challenge_base64url"`
}

func ParseSoulCooperativeStartRequestV3(raw []byte) (SoulCooperativeStartRequestV3, error) {
	var q SoulCooperativeStartRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !q.SoulCooperativeReserveRequest.valid() ||
		q.LaunchID == "" || q.AdmissionChallengeSHA256 == "" {
		return SoulCooperativeStartRequestV3{}, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != q.AdmissionChallengeBase64URL ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != q.AdmissionChallengeSHA256 {
		return SoulCooperativeStartRequestV3{}, errSoulCooperativeAuthority
	}
	return q, nil
}

type SoulCooperativeAttachRequestV3 struct {
	ReservationSHA256           string `json:"reservation_sha256"`
	InstallationID              string `json:"installation_id"`
	StartID                     string `json:"start_id"`
	LaunchID                    string `json:"launch_id"`
	AdmissionChallengeBase64URL string `json:"admission_challenge_base64url"`
	RunnerPID                   int    `json:"runner_pid"`
}

func ParseSoulCooperativeAttachRequestV3(raw []byte) (SoulCooperativeAttachRequestV3, error) {
	var q SoulCooperativeAttachRequestV3
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errSoulCooperativeAuthority
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF ||
		!stage2aPrefixedDigest.MatchString(q.ReservationSHA256) ||
		!soulInstallationID.MatchString(q.InstallationID) || !soulStartID.MatchString(q.StartID) ||
		!soulLaunchID.MatchString(q.LaunchID) || q.RunnerPID <= 1 || q.RunnerPID > 1<<31-1 {
		return SoulCooperativeAttachRequestV3{}, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(q.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != q.AdmissionChallengeBase64URL {
		return SoulCooperativeAttachRequestV3{}, errSoulCooperativeAuthority
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

// cooperativeReviewedAdmission binds the socket in the frozen argv to the
// one start ID reviewed as part of the installed direct-comms plan.
func cooperativeReviewedAdmission(p SoulCooperativeLaunchPolicy) (SoulCooperativeEndpoint, error) {
	if !soulStartID.MatchString(p.ReviewedStartID) || p.LaunchInputs == nil {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	admission, err := cooperativeEndpoint(p, p.ReviewedStartID)
	argv := p.LaunchInputs.Argv
	if err != nil || len(argv) < 7 || argv[5] != "--admission-socket" || argv[6] != admission.SocketPath {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return admission, nil
}

func cooperativeBrokerEndpoint(p SoulCooperativeLaunchPolicy) (SoulCooperativeEndpoint, error) {
	directory := path.Join(DarwinBrokerDir, p.Runner.Account)
	socket := path.Join(directory, "broker.sock")
	if len(socket) > 103 || p.validate() != nil {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return SoulCooperativeEndpoint{Directory: directory, SocketPath: socket,
		OwnerUID: p.HQUID, GroupGID: p.Runner.GID, DirMode: 02750,
		SocketMode: 0660, PeerUID: p.Runner.UID}, nil
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
	Policy                   SoulCooperativeLaunchPolicy
	InstallationOwner        string
	PlanID                   string
	PlanDigest               string
	ReceiptSHA256            string
	CanonicalPlan            []byte
	RootReceipt              []byte
	ObservedPackageSHA256    string
	ObservedArtifactSHA256   string
	ObservedDefinitionSHA256 string
	ObservedNodeSHA256       string
	ObservedLauncherSHA256   string
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
		len(plan.Members) != 1 || plan.Members[0] != in.Policy.Runner.Account ||
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
		len(receipt.Members) != 1 || receipt.Members[0] != in.Policy.Runner.Account ||
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
	if p.validate() != nil || !in.matchesInstalledRecord() || !q.valid() || q.HostID != p.HostID ||
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
