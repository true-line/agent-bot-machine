//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

var (
	stage2aV3SourceRepository = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	stage2aV3SourceCommit     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	stage2aV3SourceTag        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$`)
)

type stage2aHReleaseComponentV3 struct {
	ComponentID           string  `json:"component_id"`
	SourceRepository      string  `json:"source_repository"`
	SourceCommit          string  `json:"source_commit"`
	SourceTag             *string `json:"source_tag,omitempty"`
	ReleaseArtifactSHA256 string  `json:"release_artifact_sha256"`
	ReleaseManifestSHA256 string  `json:"release_manifest_sha256"`
}

type stage2aHOuterLaunchV3 struct {
	RubyPath     string   `json:"ruby_path"`
	RubySHA256   string   `json:"ruby_sha256"`
	HelperPath   string   `json:"helper_path"`
	HelperSHA256 string   `json:"helper_sha256"`
	Argv         []string `json:"argv"`
}

type stage2aHRuntimeV3 struct {
	NodePath          string   `json:"node_path"`
	NodeSHA256        string   `json:"node_sha256"`
	PreloaderPath     string   `json:"preloader_path"`
	PreloaderSHA256   string   `json:"preloader_sha256"`
	EntryPath         string   `json:"entry_path"`
	EntrySHA256       string   `json:"entry_sha256"`
	GuardModulePath   string   `json:"guard_module_path"`
	GuardModuleSHA256 string   `json:"guard_module_sha256"`
	Argv              []string `json:"argv"`
}

type stage2aHServiceDescriptorPayloadV3 struct {
	Contract         string                       `json:"contract"`
	Kind             string                       `json:"kind"`
	SchemaVersion    int                          `json:"schema_version"`
	HostID           string                       `json:"host_id"`
	HQInstallationID string                       `json:"hq_installation_id"`
	OwnerPlanDigest  string                       `json:"owner_plan_digest"`
	HInventory       stage2aDomainInventoryRefV3  `json:"h_inventory"`
	Components       []stage2aHReleaseComponentV3 `json:"components"`
	OuterLaunch      stage2aHOuterLaunchV3        `json:"outer_launch"`
	Runtime          stage2aHRuntimeV3            `json:"runtime"`
}

// Only the owner-plan installer may construct this package-private proof after
// checking the owner's signature, release attestations, selected manifest
// closure, account IDs, and the exact launchd record. Its descriptor is
// assembled only after A observes the final H ref; inode and birthtime cannot
// appear in a preinstall owner plan. This type is never decoded from an HQ
// request. The descriptor signer rechecks its inputs.
type stage2aVerifiedHInstallPlanV3 struct {
	verified           bool
	descriptor         stage2aHServiceDescriptorPayloadV3
	authorityKeySHA256 string
	machineGID         uint32
}

// stage2aHDescriptorTagsV3 preserves the contract distinction between an
// omitted optional source tag and an explicit JSON null. Go pointer decoding
// otherwise maps both forms to nil.
func stage2aHDescriptorTagsV3(raw []byte) error {
	var value struct {
		Components []map[string]json.RawMessage `json:"components"`
	}
	if json.Unmarshal(raw, &value) != nil || len(value.Components) == 0 {
		return errStage2aReservationAuthority
	}
	for _, component := range value.Components {
		if tag, present := component["source_tag"]; present && bytes.Equal(tag, []byte("null")) {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func stage2aValidateHDescriptorV3(p stage2aHServiceDescriptorPayloadV3,
	h stage2aDomainInventoryRefV3, plan stage2aVerifiedHInstallPlanV3,
	inv stage2aDomainInventoryV3, enrolledKey ed25519.PublicKey) error {
	invalid := errStage2aReservationAuthority
	namespace, snapshot, sidecar, nameErr := stage2aDomainNamesV3("H-code", p.HQInstallationID)
	if !plan.verified || p.Contract != "machine/v3" || p.Kind != "stage2a-h-service-descriptor" ||
		p.SchemaVersion != 3 || !stage2aBindingID.MatchString(p.HostID) ||
		!stage2aBindingID.MatchString(p.HQInstallationID) ||
		!stage2aPrefixedDigest.MatchString(p.OwnerPlanDigest) ||
		p.HInventory != h || h.Domain != "H-code" ||
		h.InstallationID != p.HQInstallationID || h.OwnerPlanDigest != p.OwnerPlanDigest ||
		h.InventoryDigest != h.ReviewedSourceInventoryDigest ||
		nameErr != nil || h.Snapshot.Path != filepath.Join(namespace, snapshot) ||
		h.Sidecar.Path != filepath.Join(namespace, sidecar) ||
		h.MachineUID < 400 || h.ReaderUID == 0 || h.ReaderUID == h.MachineUID ||
		h.ReaderGID == 0 || plan.machineGID == 0 ||
		len(enrolledKey) != ed25519.PublicKeySize ||
		plan.authorityKeySHA256 != fmt.Sprintf("sha256:%x", sha256.Sum256(enrolledKey)) ||
		!reflect.DeepEqual(p, plan.descriptor) ||
		inv.Domain != "H-code" || inv.InstallationID != h.InstallationID ||
		len(p.Components) == 0 || len(p.Components) > 32 {
		return invalid
	}
	componentIDs := make(map[string]bool, len(p.Components))
	componentRows := make(map[string]int, len(p.Components))
	previous := ""
	for _, c := range p.Components {
		if !stage2aBindingID.MatchString(c.ComponentID) || c.ComponentID <= previous ||
			!stage2aV3SourceRepository.MatchString(c.SourceRepository) ||
			!stage2aV3SourceCommit.MatchString(c.SourceCommit) ||
			(c.SourceTag != nil && !stage2aV3SourceTag.MatchString(*c.SourceTag)) ||
			!stage2aPrefixedDigest.MatchString(c.ReleaseArtifactSHA256) ||
			!stage2aPrefixedDigest.MatchString(c.ReleaseManifestSHA256) {
			return invalid
		}
		componentIDs[c.ComponentID] = true
		componentRows[c.ComponentID] = 0
		previous = c.ComponentID
	}
	files := make(map[string]stage2aDomainFileV3, len(inv.Files))
	for _, f := range inv.Files {
		if !componentIDs[f.ComponentID] {
			return invalid
		}
		componentRows[f.ComponentID]++
		files[filepath.Join(h.Snapshot.Path, filepath.FromSlash(f.Path))] = f
	}
	for _, count := range componentRows {
		if count == 0 {
			return invalid
		}
	}
	matchFile := func(path, digest string) bool {
		if !stage2aAbsolutePath(path) || !strings.HasPrefix(path, h.Snapshot.Path+string(filepath.Separator)) ||
			!stage2aPrefixedDigest.MatchString(digest) {
			return false
		}
		f, ok := files[path]
		return ok && f.SHA256 == digest
	}
	r := p.Runtime
	o := p.OuterLaunch
	selectedPaths := map[string]bool{}
	for _, path := range []string{r.NodePath, r.PreloaderPath, r.EntryPath, r.GuardModulePath, o.HelperPath} {
		if selectedPaths[path] {
			return invalid
		}
		selectedPaths[path] = true
	}
	if !matchFile(r.NodePath, r.NodeSHA256) || !matchFile(r.PreloaderPath, r.PreloaderSHA256) ||
		!matchFile(r.EntryPath, r.EntrySHA256) || !matchFile(r.GuardModulePath, r.GuardModuleSHA256) ||
		!matchFile(o.HelperPath, o.HelperSHA256) ||
		o.RubyPath != "/usr/bin/ruby" || !stage2aPrefixedDigest.MatchString(o.RubySHA256) ||
		len(r.Argv) < 7 || len(r.Argv) > 32 || len(o.Argv) != len(r.Argv)+4 ||
		len(o.Argv) > 36 || r.Argv[0] != r.NodePath ||
		r.Argv[1] != "--no-addons" || r.Argv[2] != "--disallow-code-generation-from-strings" ||
		r.Argv[3] != "--import" || r.Argv[4] != r.PreloaderPath ||
		r.Argv[5] != r.EntryPath || r.Argv[6] != "run" ||
		o.Argv[0] != o.RubyPath || o.Argv[1] != "--disable-gems" ||
		o.Argv[2] != o.HelperPath || o.Argv[3] != "launch" ||
		!reflect.DeepEqual(o.Argv[4:], r.Argv) {
		return invalid
	}
	return nil
}

// signStage2aHServiceDescriptorV3 runs under A with keyd's service key. The
// caller must publish the returned envelope atomically at HQ's fixed path;
// obtaining an envelope never by itself changes the protected-start gate.
func signStage2aHServiceDescriptorV3(payload []byte, h stage2aVerifiedDomainRefV3,
	plan stage2aVerifiedHInstallPlanV3, enrolledKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	if !h.verified || !plan.verified || stage2aRecheckVerifiedDomainV3(h) != nil ||
		stage2aV3CanonicalPayload(payload, stage2aHDescriptorPurposeV3) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	var p stage2aHServiceDescriptorPayloadV3
	if stage2aDecodeExact(payload, &p) != nil || stage2aHDescriptorTagsV3(payload) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	_, raw, err := stage2aV3SidecarAt(h.ref.Sidecar.Path, h.ref.MachineUID, h.ref.ReaderGID)
	if err != nil {
		return nil, "", errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != h.ref.InventoryDigest ||
		stage2aValidateHDescriptorV3(p, h.ref, plan, inv, enrolledKey) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	pin, err := stage2aReadRootFile(SoulAuthorityPin, ed25519.PublicKeySize, 0444)
	if err != nil || !bytes.Equal(pin, enrolledKey) ||
		uint32(os.Getuid()) != h.ref.MachineUID || uint32(os.Geteuid()) != h.ref.MachineUID ||
		stage2aRecheckVerifiedDomainV3(h) != nil {
		return nil, "", errStage2aReservationAuthority
	}
	return signStage2aVerifiedEnvelopeV3(stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aHDescriptorPurposeV3, payload: payload,
		machineUID: h.ref.MachineUID, machineGID: plan.machineGID,
	}, enrolledKey, sign)
}

func stage2aDecodeHDescriptorV3(raw []byte, enrolledKey ed25519.PublicKey) (stage2aHServiceDescriptorPayloadV3, string, error) {
	var p stage2aHServiceDescriptorPayloadV3
	payload, digest, err := verifyStage2aV3Envelope(raw, stage2aHDescriptorPurposeV3, enrolledKey)
	if err != nil || stage2aDecodeExact(payload, &p) != nil || stage2aHDescriptorTagsV3(payload) != nil {
		return p, "", errStage2aReservationAuthority
	}
	return p, digest, nil
}
