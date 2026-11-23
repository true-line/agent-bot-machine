package members

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
)

const hqStage2aCutoverRefusal = "protected Stage 2a HQ requires owner-approved limits, sealed H and R, the approved release mapping, and a verified runtime guard"

const (
	hqStage2aMetadataDir        = launchRuntimeDir + "/h-v3"
	hqStage2aPublicKey          = SoulAuthorityPin
	hqStage2aDescriptor         = hqStage2aMetadataDir + "/descriptor.json"
	hqStage2aNode               = "bin/node"
	hqStage2aHelper             = "helpers/darwin-owner.rb"
	hqStage2aEntry              = "hq/main.mjs"
	hqStage2aGuard              = "hq/stage2a-selected-code.mjs"
	hqStage2aPreloader          = "hq/stage2a-h-preloader.mjs"
	hqStage2aCooperativeMachine = "hq/stage2a-cooperative-machine.mjs"
	hqStage2aCooperativeProof   = "hq/stage2a-cooperative-proof.mjs"
	hqStage2aCooperativeStart   = "hq/stage2a-cooperative-start.mjs"
	hqStage2aCooperativeBridge  = "hq/stage2a-cooperative-bridge.mjs"
)

// hqStage2aService is an explicit request carried by the existing paired
// service upgrade. The approved digest includes the reviewed inventory and
// authority, including the inputs to the post-approval A measurement.
type hqStage2aService struct {
	HostID                 string                         `json:"host_id"`
	RuntimeInstallationID  string                         `json:"runtime_installation_id,omitempty"`
	CooperativeOnly        bool                           `json:"cooperative_only,omitempty"`
	InstallationID         string                         `json:"installation_id"`
	MachineAccount         string                         `json:"machine_account"`
	MachineUID             int                            `json:"machine_uid"`
	MachineGID             int                            `json:"machine_gid"`
	ReaderUID              int                            `json:"reader_uid"`
	ReaderGID              int                            `json:"reader_gid"`
	AuthorityKeySHA256     string                         `json:"authority_key_sha256"`
	GuardModuleSHA256      string                         `json:"guard_module_sha256"`
	PreloaderPath          string                         `json:"preloader_path"`
	InventorySource        string                         `json:"inventory_source"`
	InventoryDigest        string                         `json:"inventory_digest"`
	InventoryLimits        stage2aDomainInventoryLimitsV3 `json:"inventory_limits"`
	ExcludedHQReleasePaths []string                       `json:"excluded_hq_release_paths,omitempty"`
	ContractsSource        hqStage2aContractsSource       `json:"contracts_source"`
	Components             []stage2aReleaseComponent      `json:"components"`
}

// These exact Contracts pins come from the reviewed owner plan. The raw HQ
// artifact must carry the same governance pin and both full and H-selected
// Contracts digests before root stages any H file.
type hqStage2aContractsSource struct {
	Tag           string `json:"tag"`
	Commit        string `json:"commit"`
	FullDigest    string `json:"full_digest"`
	FullFiles     int    `json:"full_files"`
	RuntimeDigest string `json:"runtime_digest"`
	RuntimeFiles  int    `json:"runtime_files"`
}

func (s *hqStage2aService) UnmarshalJSON(raw []byte) error {
	type service hqStage2aService
	var fields map[string]json.RawMessage
	if stage2aStrictJSON(raw) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("invalid Stage 2a HQ service")
	}
	var decoded service
	if err := stage2aDecodeExact(raw, &decoded); err != nil {
		return err
	}
	if _, supplied := fields["runtime_installation_id"]; decoded.CooperativeOnly && supplied {
		return errors.New("cooperative-only Stage 2a HQ service cannot name a runtime installation")
	}
	*s = hqStage2aService(decoded)
	return nil
}

type stage2aReleaseComponent struct {
	ComponentID      string `json:"component_id"`
	SourceRepository string `json:"source_repository"`
	SourceCommit     string `json:"source_commit"`
	SourceTag        string `json:"source_tag,omitempty"`
	ArtifactSource   string `json:"artifact_source"`
	ArtifactSHA256   string `json:"release_artifact_sha256"`
	ManifestSource   string `json:"manifest_source"`
	ManifestSHA256   string `json:"release_manifest_sha256"`
}

// Only the reviewed versioned Contracts fixture sets may be omitted
// from H. Runtime schemas and every other manifest row remain selected.
var hqStage2aContractsFixturePaths = [...]string{
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-signed-reservation.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-binding.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-invalid-bytes.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-synthetic.json",
}

var hqStage2aContractsFixturePathsV010 = [...]string{
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.bridge-claim.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.missing-broker.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-signed-reservation.wrong-purpose.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-signed-reservation.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-binding.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-invalid-bytes.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json",
}

// v0.10.1 keeps every runtime schema and excludes only reviewed conformance fixtures.
var hqStage2aContractsFixturePathsV0101 = [...]string{
	"vendor/soul-contracts/fixtures/negative/domain-inventory.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/h-service-descriptor-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/h-service-descriptor-signed.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/inventory-ref.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/measurement-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-bridge-assignment-payload.missing-reservation.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-bridge-signed-assignment.wrong-purpose.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.bridge-claim.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.missing-broker.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-signed-reservation.wrong-purpose.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-signed-reservation.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-bridge-assignment-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-bridge-signed-assignment.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-binding.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-invalid-bytes.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-launch-inputs.brokered-b.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json",
}

// v0.10.2 keeps all Q schemas and excludes only explicit conformance fixtures.
var hqStage2aContractsFixturePathsV0102 = [...]string{
	"vendor/soul-contracts/fixtures/negative/domain-inventory.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/h-service-descriptor-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/h-service-descriptor-signed.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/inventory-ref.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/measurement-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-bridge-assignment-payload.missing-reservation.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-bridge-signed-assignment.wrong-purpose.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.bridge-claim.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-reservation-payload.missing-broker.json",
	"vendor/soul-contracts/fixtures/negative/soul-cooperative-signed-reservation.wrong-purpose.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-begin.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-clean-eof.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-framed-wire.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-pre-sign-index.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-ready.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-signed-eof.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-q-signed-index.synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-binding.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-qualification-candidate-signed-reservation.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-reservation-payload.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/negative/stage2a-signed-reservation.v3-synthetic.bad.json",
	"vendor/soul-contracts/fixtures/positive/domain-inventory.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/h-service-descriptor-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/h-service-descriptor-signed.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/inventory-ref.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/measurement-binding.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-bridge-assignment-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-bridge-signed-assignment.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/soul-cooperative-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-begin.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-clean-eof.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-framed-wire.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-pre-sign-index.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-ready.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-signed-eof.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-q-signed-index.synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-binding.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-qualification-candidate-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-reservation-payload.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/positive/stage2a-signed-reservation.v3-synthetic.json",
	"vendor/soul-contracts/fixtures/qualification/v3/q-presign-argv-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-invalid-bytes.json",
	"vendor/soul-contracts/fixtures/reservation/v3/machine-qualification-candidate-synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-launch-inputs.brokered-b.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json",
	"vendor/soul-contracts/fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json",
}

func hqStage2aValidExclusions(paths []string) bool {
	return len(paths) == 0 || slices.Equal(paths, hqStage2aContractsFixturePaths[:]) ||
		slices.Equal(paths, hqStage2aContractsFixturePathsV010[:]) ||
		slices.Equal(paths, hqStage2aContractsFixturePathsV0101[:]) ||
		slices.Equal(paths, hqStage2aContractsFixturePathsV0102[:])
}

var hqStage2aSourceRepository = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
var hqStage2aSourceTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$`)

type hqStage2aLaunch struct {
	Namespace       string   `json:"namespace"`
	Root            string   `json:"root"`
	InventoryPath   string   `json:"inventory_path"`
	PublicKeyPath   string   `json:"public_key_path"`
	DescriptorPath  string   `json:"descriptor_path"`
	RubySHA256      string   `json:"ruby_sha256"`
	GuardModulePath string   `json:"guard_module_path"`
	LauncherSHA256  string   `json:"launcher_sha256"`
	RuntimeArgv     []string `json:"runtime_argv"`
	OuterArgv       []string `json:"outer_argv"`
}

func (s hqStage2aService) validate() error {
	if !stage2aBindingID.MatchString(s.HostID) || !soulInstallationID.MatchString(s.InstallationID) || !accountName.MatchString(s.MachineAccount) ||
		s.MachineUID < 400 || s.MachineGID <= 0 || s.ReaderUID < 300 || s.ReaderUID > 399 ||
		s.ReaderGID != s.ReaderUID || s.MachineGID == s.ReaderGID ||
		!stage2aPrefixedDigest.MatchString(s.AuthorityKeySHA256) || !stage2aPrefixedDigest.MatchString(s.GuardModuleSHA256) ||
		s.PreloaderPath != hqStage2aPreloader ||
		!stage2aAbsolutePath(s.InventorySource) || !stage2aPrefixedDigest.MatchString(s.InventoryDigest) ||
		s.InventoryLimits.MaxFiles < 9 || s.InventoryLimits.MaxFiles > 512 ||
		s.InventoryLimits.MaxFileBytes == 0 || s.InventoryLimits.MaxFileBytes > 384<<20 ||
		s.InventoryLimits.MaxTotalBytes < s.InventoryLimits.MaxFileBytes || s.InventoryLimits.MaxTotalBytes > 1<<30 || !hqStage2aValidExclusions(s.ExcludedHQReleasePaths) ||
		len(s.Components) != 2 || s.Components[0].ComponentID != "hq" || s.Components[1].ComponentID != "node" ||
		!stage2aHSourceTagV3.MatchString(s.ContractsSource.Tag) ||
		!stage2aHSourceCommitV3.MatchString(s.ContractsSource.Commit) ||
		!stage2aPrefixedDigest.MatchString(s.ContractsSource.FullDigest) ||
		!stage2aPrefixedDigest.MatchString(s.ContractsSource.RuntimeDigest) ||
		s.ContractsSource.FullFiles < 1 || s.ContractsSource.FullFiles > 1024 ||
		s.ContractsSource.RuntimeFiles < 1 ||
		s.ContractsSource.RuntimeFiles != s.ContractsSource.FullFiles-len(s.ExcludedHQReleasePaths) {
		return errors.New("invalid Stage 2a HQ installation, authority, or selected inventory")
	}
	if s.CooperativeOnly && s.RuntimeInstallationID != "" ||
		!s.CooperativeOnly && !soulInstallationID.MatchString(s.RuntimeInstallationID) {
		return errors.New("invalid Stage 2a HQ service mode and runtime installation")
	}
	for _, c := range s.Components {
		if !c.valid() {
			return errors.New("invalid Stage 2a HQ release evidence digests")
		}
	}
	return nil
}

func (s hqStage2aService) launch(owner, rubyDigest string) (*hqStage2aLaunch, error) {
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("H-code", s.InstallationID)
	if err != nil {
		return nil, err
	}
	root := path.Join(namespace, snapshot)
	argv := []string{path.Join(root, hqStage2aNode), "--no-addons", "--disallow-code-generation-from-strings", "--import",
		path.Join(root, s.PreloaderPath), path.Join(root, hqStage2aEntry), "run", "--home", launchState, "--owner-account", owner}
	return &hqStage2aLaunch{Namespace: namespace, Root: root, InventoryPath: path.Join(namespace, sidecar),
		PublicKeyPath: hqStage2aPublicKey, DescriptorPath: hqStage2aDescriptor, RubySHA256: rubyDigest, GuardModulePath: path.Join(root, hqStage2aGuard),
		RuntimeArgv: argv, OuterArgv: append([]string{"/usr/bin/ruby", "--disable-gems", path.Join(root, hqStage2aHelper), "launch"}, argv...)}, nil
}

func (c *stage2aReleaseComponent) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if stage2aStrictJSON(raw) != nil || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("invalid Stage 2a release component")
	}
	if value, present := fields["source_tag"]; present {
		var tag string
		if json.Unmarshal(value, &tag) != nil || !hqStage2aSourceTag.MatchString(tag) || strings.Contains(tag, "..") {
			return errors.New("invalid Stage 2a release source tag")
		}
	}
	type component stage2aReleaseComponent
	return stage2aDecodeExact(raw, (*component)(c))
}

func (c stage2aReleaseComponent) valid() bool {
	return stage2aBindingID.MatchString(c.ComponentID) && hqStage2aSourceRepository.MatchString(c.SourceRepository) &&
		stage2aCDHash.MatchString(c.SourceCommit) && (c.SourceTag == "" || hqStage2aSourceTag.MatchString(c.SourceTag) && !strings.Contains(c.SourceTag, "..")) &&
		stage2aAbsolutePath(c.ArtifactSource) && stage2aAbsolutePath(c.ManifestSource) &&
		stage2aPrefixedDigest.MatchString(c.ArtifactSHA256) && stage2aPrefixedDigest.MatchString(c.ManifestSHA256)
}
