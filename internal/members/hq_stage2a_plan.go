package members

import (
	"errors"
	"path"
	"path/filepath"
)

const hqStage2aCutoverRefusal = "protected Stage 2a HQ requires owner-approved limits, sealed H and R, authenticated release mapping, and a verified runtime guard"

const (
	hqStage2aMetadataDir = launchRuntimeDir + "/h-v3"
	hqStage2aPublicKey   = SoulAuthorityPin
	hqStage2aDescriptor  = hqStage2aMetadataDir + "/descriptor.json"
	hqStage2aNode        = "bin/node"
	hqStage2aHelper      = "helpers/darwin-owner.rb"
	hqStage2aEntry       = "hq/main.mjs"
	hqStage2aGuard       = "hq/stage2a-selected-code.mjs"
)

// hqStage2aService is an explicit request carried by the existing paired
// service upgrade. The approved digest includes the reviewed inventory and
// authority, including the inputs to the post-approval A measurement.
type hqStage2aService struct {
	HostID             string                         `json:"host_id"`
	InstallationID     string                         `json:"installation_id"`
	MachineAccount     string                         `json:"machine_account"`
	MachineUID         int                            `json:"machine_uid"`
	MachineGID         int                            `json:"machine_gid"`
	ReaderUID          int                            `json:"reader_uid"`
	ReaderGID          int                            `json:"reader_gid"`
	AuthorityKeySHA256 string                         `json:"authority_key_sha256"`
	GuardModuleSHA256  string                         `json:"guard_module_sha256"`
	PreloaderPath      string                         `json:"preloader_path"`
	InventorySource    string                         `json:"inventory_source"`
	InventoryDigest    string                         `json:"inventory_digest"`
	InventoryLimits    stage2aDomainInventoryLimitsV3 `json:"inventory_limits"`
	Components         []hqStage2aComponent           `json:"components"`
}

type hqStage2aComponent struct {
	ComponentID       string `json:"component_id"`
	ArtifactSHA256    string `json:"release_artifact_sha256"`
	AttestationSHA256 string `json:"release_attestation_sha256"`
	ManifestSHA256    string `json:"release_manifest_sha256"`
}

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
		!systemdPath.MatchString("/"+s.PreloaderPath) || filepath.Clean(s.PreloaderPath) != s.PreloaderPath ||
		filepath.Dir(s.PreloaderPath) != "hq" || filepath.Ext(s.PreloaderPath) != ".mjs" || s.PreloaderPath == hqStage2aEntry || s.PreloaderPath == hqStage2aGuard ||
		!stage2aAbsolutePath(s.InventorySource) || !stage2aPrefixedDigest.MatchString(s.InventoryDigest) ||
		s.InventoryLimits.MaxFiles < 5 || s.InventoryLimits.MaxFiles > 512 ||
		s.InventoryLimits.MaxFileBytes == 0 || s.InventoryLimits.MaxFileBytes > 384<<20 ||
		s.InventoryLimits.MaxTotalBytes < s.InventoryLimits.MaxFileBytes || s.InventoryLimits.MaxTotalBytes > 1<<30 ||
		len(s.Components) != 2 || s.Components[0].ComponentID != "hq" || s.Components[1].ComponentID != "node" {
		return errors.New("invalid Stage 2a HQ installation, authority, or selected inventory")
	}
	for _, c := range s.Components {
		if !stage2aPrefixedDigest.MatchString(c.ArtifactSHA256) || !stage2aPrefixedDigest.MatchString(c.AttestationSHA256) ||
			!stage2aPrefixedDigest.MatchString(c.ManifestSHA256) {
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
