package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var (
	stage2aHSourceCommitV3 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	stage2aHSourceTagV3    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
)

// These raw release files are reviewed as non-installed build, platform,
// documentation, or SDK entry files. Every other file in these source trees
// must appear in the H source manifest and selected inventory. A new HQ or
// plugin module therefore fails closed until its H inclusion is reviewed.
var stage2aHSourceNonInstalledV3 = map[string]bool{
	"governance/darwin-broker.json":                   true,
	"helpers/linux-owner-peer.py":                     true,
	"helpers/macos-enclave/MachineInstallation.swift": true,
	"helpers/macos-enclave/RoleStore.swift":           true,
	"helpers/macos-enclave/Signer.swift":              true,
	"helpers/macos-enclave/Standalone.swift":          true,
	"helpers/macos-enclave/main.swift":                true,
	"helpers/tpm2-signer.mjs":                         true,
	"hq/README.md":                                    true,
	"hq/cooperative-reservation.mjs":                  true,
	"scripts/build-interim-release.mjs":               true,
	"scripts/build-macos-standalone-signer.sh":        true,
	"scripts/check-macos-enclave.swift":               true,
	"scripts/ci-build-darwin-artifact.sh":             true,
	"scripts/darwin-broker.mjs":                       true,
	"sdk/README.md":                                   true,
	"sdk/conformance.mjs":                             true,
	"sdk/index.mjs":                                   true,
	"sdk/local-socket-client.mjs":                     true,
	"sdk/local-socket-lines.mjs":                      true,
	"sdk/member-client.mjs":                           true,
	"sdk/member-query-conformance.mjs":                true,
	"sdk/member-query.mjs":                            true,
	"sdk/member-session.mjs":                          true,
	"sdk/package.json":                                true,
	"sdk/test-host.mjs":                               true,
	"sdk/wire/index.mjs":                              true,
}

func stage2aHSourceRuntimeTreeV3(path string) bool {
	return strings.HasPrefix(path, "governance/") || strings.HasPrefix(path, "helpers/") ||
		strings.HasPrefix(path, "hq/") || strings.HasPrefix(path, "scripts/") ||
		strings.HasPrefix(path, "sdk/") || strings.HasPrefix(path, "vendor/plugins/")
}

// Pins here are byte expectations, not proof of who approved them. The owner
// plan installer must authenticate their origin before calling this verifier.
type stage2aHSourceReleasePinsV3 struct {
	InstallationID         string
	InventoryDigest        string
	Limits                 stage2aDomainInventoryLimitsV3
	HQCommit               string
	HQArtifactSHA256       string
	NodeArtifactSHA256     string
	SourceManifestSHA256   string
	ContractsTag           string
	ContractsCommit        string
	ContractsFullDigest    string
	ContractsFullFiles     int
	ContractsRuntimeDigest string
	ContractsRuntimeFiles  int
	Excluded               []string
}

type stage2aHSourceContractRowV3 struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

type stage2aHSourcePinFileV3 struct {
	SchemaVersion   int      `json:"schema_version"`
	Repository      string   `json:"repository"`
	Tag             string   `json:"tag"`
	Commit          string   `json:"commit"`
	Paths           []string `json:"paths"`
	DigestAlgorithm string   `json:"digest_algorithm"`
	Digest          string   `json:"digest"`
	Files           int      `json:"files"`
}

type stage2aHSourceReleaseMetadataV3 struct {
	SchemaVersion          int    `json:"schema_version"`
	HQCommit               string `json:"hq_commit"`
	ContractsCommit        string `json:"contracts_commit"`
	ContractsDigest        string `json:"contracts_digest"`
	TargetPlatform         string `json:"target_platform"`
	OwnerControlCapability string `json:"owner_control_capability"`
	ContractsRuntime       struct {
		DigestAlgorithm        string   `json:"digest_algorithm"`
		Digest                 string   `json:"digest"`
		Files                  int      `json:"files"`
		ExcludedHQReleasePaths []string `json:"excluded_hq_release_paths"`
	} `json:"contracts_runtime"`
}

func stage2aHSourceManifestDigestV3(rows map[string]stage2aHSourceContractRowV3) (string, error) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("sha256:%x", sum), nil
}

func stage2aHSourceHashV3(reader io.ReaderAt, size int64) (string, error) {
	if reader == nil || size < 1 || size > 2<<30 {
		return "", errors.New("invalid Stage 2a H source artifact size")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(reader, 0, size))
	if err != nil || n != size {
		return "", errors.New("short Stage 2a H source artifact")
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// stage2aVerifyHSourceBytesV3 authenticates the exact raw artifact bytes
// against caller-supplied pins, then proves that the source manifest is
// selected+excluded closure over the H inventory. It does not extract or
// install any archive member and does not authorize A or the descriptor signer.
func stage2aVerifyHSourceBytesV3(invRaw, sourceManifest []byte,
	hq io.ReaderAt, hqSize int64, node io.ReaderAt, nodeSize int64,
	pins stage2aHSourceReleasePinsV3) error {
	invalid := errors.New("Stage 2a H release bytes differ from reviewed pins")
	inv, inventoryDigest, err := stage2aDomainInventoryDigestV3(invRaw)
	if err != nil || inv.InstallationID != pins.InstallationID ||
		inv.Limits != pins.Limits || inventoryDigest != pins.InventoryDigest ||
		!stage2aPrefixedDigest.MatchString(pins.HQArtifactSHA256) ||
		!stage2aHSourceCommitV3.MatchString(pins.HQCommit) ||
		!stage2aPrefixedDigest.MatchString(pins.NodeArtifactSHA256) ||
		!stage2aPrefixedDigest.MatchString(pins.SourceManifestSHA256) ||
		!stage2aPrefixedDigest.MatchString(pins.ContractsFullDigest) ||
		!stage2aPrefixedDigest.MatchString(pins.ContractsRuntimeDigest) ||
		!stage2aHSourceTagV3.MatchString(pins.ContractsTag) ||
		!stage2aHSourceCommitV3.MatchString(pins.ContractsCommit) ||
		pins.ContractsFullFiles < 1 || pins.ContractsFullFiles > 1024 ||
		pins.ContractsRuntimeFiles < 1 || pins.ContractsRuntimeFiles > pins.ContractsFullFiles ||
		stage2aValidateHSourceSelectionV3(inv, sourceManifest,
			pins.SourceManifestSHA256, pins.Excluded, pins.NodeArtifactSHA256) != nil {
		return invalid
	}
	if nodeSize < 1 || nodeSize > stage2aV3MaxInventoryFileBytes ||
		hqSize < 1 || hqSize > 2<<30 {
		return invalid
	}
	for _, file := range inv.Files {
		if file.ComponentID == "node" && file.SizeBytes != uint64(nodeSize) {
			return invalid
		}
	}
	hqDigest, err := stage2aHSourceHashV3(hq, hqSize)
	if err != nil || hqDigest != pins.HQArtifactSHA256 {
		return invalid
	}
	nodeDigest, err := stage2aHSourceHashV3(node, nodeSize)
	if err != nil || nodeDigest != pins.NodeArtifactSHA256 {
		return invalid
	}
	var sourceRows []stage2aHSourceManifestRowV3
	if json.Unmarshal(sourceManifest, &sourceRows) != nil {
		return invalid
	}
	want := make(map[string]string, len(sourceRows))
	for _, row := range sourceRows {
		want[row.Path] = row.SHA256
	}
	selected := make(map[string]stage2aDomainFileV3, len(inv.Files))
	for _, file := range inv.Files {
		if file.ComponentID == "hq" {
			selected[file.ReleasePath] = file
		}
	}
	seenRaw := make(map[string]bool)
	seenSource := make(map[string]bool, len(want))
	contracts := make(map[string]stage2aHSourceContractRowV3, pins.ContractsFullFiles)
	var releaseMetadata, contractsPinBytes []byte
	reader := io.NewSectionReader(hq, 0, hqSize)
	archive := tar.NewReader(reader)
	var members int
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || header.Format != tar.FormatUSTAR ||
			header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" ||
			!header.ModTime.Equal(time.Unix(0, 0)) ||
			header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return invalid
		}
		members++
		if members > 4096 || !strings.HasPrefix(header.Name, "hq/") {
			return invalid
		}
		path := strings.TrimPrefix(header.Name, "hq/")
		if header.Typeflag == tar.TypeDir {
			if !strings.HasSuffix(header.Name, "/") {
				return invalid
			}
			path = strings.TrimSuffix(path, "/")
			if header.Mode != 0755 || header.Size != 0 ||
				(header.Name != "hq/" && !stage2aV3InventoryRecordPath(path)) {
				return invalid
			}
		} else if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			if !stage2aV3InventoryRecordPath(path) || header.Size < 0 ||
				header.Size > stage2aV3MaxInventoryFileBytes ||
				(header.Mode != 0644 && header.Mode != 0755) {
				return invalid
			}
		} else {
			return invalid
		}
		folded := strings.ToLower(path)
		if seenRaw[folded] {
			return invalid
		}
		seenRaw[folded] = true
		if header.Typeflag == tar.TypeDir {
			continue
		}
		hash := sha256.New()
		if path == "governance/interim-release.json" || path == "governance/soul-contracts.json" {
			if header.Size > 65536 {
				return invalid
			}
			var metadata bytes.Buffer
			if _, err := io.CopyN(io.MultiWriter(hash, &metadata), archive, header.Size); err != nil {
				return invalid
			}
			if path == "governance/interim-release.json" {
				releaseMetadata = metadata.Bytes()
			} else {
				contractsPinBytes = metadata.Bytes()
			}
		} else if _, err := io.CopyN(hash, archive, header.Size); err != nil {
			return invalid
		}
		digest := fmt.Sprintf("sha256:%x", hash.Sum(nil))
		if expected, ok := want[path]; ok {
			if expected != digest || seenSource[path] {
				return invalid
			}
			seenSource[path] = true
		}
		if stage2aHSourceRuntimeTreeV3(path) && !stage2aHSourceNonInstalledV3[path] {
			if _, installed := selected[path]; !installed || !seenSource[path] {
				return invalid
			}
		}
		if file, ok := selected[path]; ok {
			mode := "0440"
			if header.Mode == 0755 {
				mode = "0550"
			}
			if file.SHA256 != digest || file.SizeBytes != uint64(header.Size) || file.Mode != mode {
				return invalid
			}
		}
		if strings.HasPrefix(path, "vendor/soul-contracts/") {
			relative := strings.TrimPrefix(path, "vendor/soul-contracts/")
			mode := "100644"
			if header.Mode == 0755 {
				mode = "100755"
			}
			contracts[relative] = stage2aHSourceContractRowV3{
				SHA256: strings.TrimPrefix(digest, "sha256:"), Size: header.Size, Mode: mode}
		}
	}
	// The full Contracts digest proves the raw archive, but every nonexcluded
	// Contracts file must also be in H's selected rows. Otherwise an owner-plan
	// inventory could omit a runtime schema while keeping the full digest valid.
	for path := range contracts {
		releasePath := "vendor/soul-contracts/" + path
		_, selectedRuntime := selected[releasePath]
		if !seenSource[releasePath] ||
			selectedRuntime == containsHSourceOmissionV3(pins.Excluded, releasePath) {
			return invalid
		}
	}
	if len(seenSource) != len(want) || len(contracts) != pins.ContractsFullFiles ||
		stage2aStrictJSONBounded(releaseMetadata, 65536, stage2aV3MaxJSONNodes) != nil ||
		len(contractsPinBytes) == 0 {
		return invalid
	}
	if stage2aStrictJSONBounded(contractsPinBytes, 65536, stage2aV3MaxJSONNodes) != nil {
		return invalid
	}
	var contractsPin stage2aHSourcePinFileV3
	decoder := json.NewDecoder(bytes.NewReader(contractsPinBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&contractsPin) != nil || decoder.Decode(new(any)) != io.EOF ||
		contractsPin.SchemaVersion != 1 ||
		contractsPin.Repository != "https://github.com/true-line/soul-contracts.git" ||
		contractsPin.Tag != pins.ContractsTag || contractsPin.Commit != pins.ContractsCommit ||
		len(contractsPin.Paths) != 3 || contractsPin.Paths[0] != "errors" ||
		contractsPin.Paths[1] != "fixtures" || contractsPin.Paths[2] != "schemas" ||
		contractsPin.DigestAlgorithm != "sha256-manifest-v1" ||
		contractsPin.Digest != pins.ContractsFullDigest || contractsPin.Files != pins.ContractsFullFiles {
		return invalid
	}
	var padding [32 << 10]byte
	for {
		n, err := reader.Read(padding[:])
		for _, b := range padding[:n] {
			if b != 0 {
				return invalid
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return invalid
		}
	}
	fullDigest, err := stage2aHSourceManifestDigestV3(contracts)
	if err != nil || fullDigest != pins.ContractsFullDigest {
		return invalid
	}
	// Derive the runtime digest from rows actually selected for H. The raw
	// archive hash and per-row checks above bind these bytes to that inventory.
	runtime := make(map[string]stage2aHSourceContractRowV3, len(selected))
	for path, row := range contracts {
		if _, installed := selected["vendor/soul-contracts/"+path]; installed {
			runtime[path] = row
		}
	}
	runtimeDigest, err := stage2aHSourceManifestDigestV3(runtime)
	if err != nil || len(runtime) != pins.ContractsRuntimeFiles ||
		runtimeDigest != pins.ContractsRuntimeDigest {
		return invalid
	}
	var metadata stage2aHSourceReleaseMetadataV3
	if json.Unmarshal(releaseMetadata, &metadata) != nil || metadata.SchemaVersion != 1 ||
		metadata.HQCommit != pins.HQCommit ||
		metadata.ContractsCommit != pins.ContractsCommit ||
		metadata.ContractsDigest != pins.ContractsFullDigest ||
		metadata.TargetPlatform != "darwin" ||
		metadata.OwnerControlCapability != "darwin-owner-control/v2" ||
		metadata.ContractsRuntime.DigestAlgorithm != "sha256-manifest-v1" ||
		metadata.ContractsRuntime.Digest != pins.ContractsRuntimeDigest ||
		metadata.ContractsRuntime.Files != pins.ContractsRuntimeFiles ||
		!equalHSourceOmissionsV3(metadata.ContractsRuntime.ExcludedHQReleasePaths, pins.Excluded) {
		return invalid
	}
	return nil
}

func containsHSourceOmissionV3(paths []string, path string) bool {
	for _, candidate := range paths {
		if candidate == path {
			return true
		}
	}
	return false
}

func equalHSourceOmissionsV3(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
