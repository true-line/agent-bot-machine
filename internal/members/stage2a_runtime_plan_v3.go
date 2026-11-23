package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var (
	stage2aRuntimeV3SourceRepository = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	stage2aRuntimeV3SourceCommit     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	stage2aRuntimeV3SourceTag        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$`)
)

// These are reviewed source and release pins, not installed authority. The
// applied R reference is produced only after root stages the exact rows and A
// seals and reopens them. The selected adapter has its additional release
// attestation gate in the later v3 reservation consumer.
type stage2aRuntimeV3ComponentPin struct {
	ComponentID           string `json:"component_id"`
	SourceRepository      string `json:"source_repository"`
	SourceCommit          string `json:"source_commit"`
	SourceTag             string `json:"source_tag,omitempty"`
	ArtifactFormat        string `json:"artifact_format"`
	ArtifactSource        string `json:"artifact_source"`
	ReleaseArtifactSHA256 string `json:"release_artifact_sha256"`
	ManifestSource        string `json:"manifest_source"`
	ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
}

type stage2aRuntimeV3Install struct {
	InventorySource string                         `json:"inventory_source"`
	InventoryDigest string                         `json:"inventory_digest"`
	Limits          stage2aDomainInventoryLimitsV3 `json:"limits"`
	Components      []stage2aRuntimeV3ComponentPin `json:"components"`
	SourceRoots     map[string]string              `json:"source_roots"`
}

type stage2aRuntimeV3ManifestRow struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func stage2aRuntimeSourcesMatchInventory(inv stage2aDomainInventoryV3, roots map[string]string) bool {
	used := make(map[string]bool, len(roots))
	paths := make(map[string]bool, len(roots))
	for _, row := range inv.Files {
		root := roots[row.ComponentID]
		if !stage2aAbsolutePath(root) || root == stage2aDomainSnapshotParentV3 ||
			strings.HasPrefix(root, stage2aDomainSnapshotParentV3+"/") {
			return false
		}
		used[row.ComponentID] = true
		paths[root] = true
	}
	return len(used) == len(roots) && len(paths) == len(roots)
}

func stage2aValidateRuntimeV3Plan(spec stage2aRuntimeV3Install, inv stage2aDomainInventoryV3,
	digest string, manifests map[string][]byte) error {
	invalid := errors.New("Stage 2a v3 R plan does not pin exact source and release manifests")
	if inv.Domain != "R-runtime" || digest != spec.InventoryDigest ||
		inv.Limits != spec.Limits || !stage2aAbsolutePath(spec.InventorySource) ||
		len(spec.Components) == 0 || len(spec.Components) > 32 ||
		len(spec.SourceRoots) != len(spec.Components) || len(manifests) != len(spec.Components) ||
		!stage2aRuntimeSourcesMatchInventory(inv, spec.SourceRoots) {
		return invalid
	}
	previous := ""
	for _, component := range spec.Components {
		if !stage2aBindingID.MatchString(component.ComponentID) ||
			component.ComponentID <= previous ||
			(component.ArtifactFormat != "tar" && component.ArtifactFormat != "raw") ||
			!stage2aRuntimeV3SourceRepository.MatchString(component.SourceRepository) ||
			!stage2aRuntimeV3SourceCommit.MatchString(component.SourceCommit) ||
			component.SourceTag != "" && !stage2aRuntimeV3SourceTag.MatchString(component.SourceTag) ||
			!stage2aAbsolutePath(component.ArtifactSource) ||
			!stage2aAbsolutePath(component.ManifestSource) ||
			!stage2aPrefixedDigest.MatchString(component.ReleaseArtifactSHA256) ||
			!stage2aPrefixedDigest.MatchString(component.ReleaseManifestSHA256) {
			return invalid
		}
		previous = component.ComponentID
		manifest := manifests[component.ComponentID]
		sum := sha256.Sum256(manifest)
		if fmt.Sprintf("sha256:%x", sum) != component.ReleaseManifestSHA256 ||
			stage2aRuntimeManifestMatchesV3(manifest, component.ComponentID, inv) != nil {
			return invalid
		}
	}
	return nil
}

// Each independently pinned component manifest must be an exact canonical
// array containing all and only the corresponding installed inventory rows.
// In particular, an archive hash without this mapping is insufficient.
func stage2aRuntimeManifestMatchesV3(raw []byte, componentID string, inv stage2aDomainInventoryV3) error {
	invalid := errors.New("Stage 2a v3 component manifest differs from installed inventory")
	if stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return invalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return invalid
	}
	var rows []stage2aRuntimeV3ManifestRow
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&rows) != nil || decoder.Decode(new(any)) != io.EOF || len(rows) == 0 {
		return invalid
	}
	want := make(map[string]string)
	for _, file := range inv.Files {
		if file.ComponentID == componentID {
			want[file.ReleasePath] = file.SHA256
		}
	}
	if len(rows) != len(want) {
		return invalid
	}
	previous := ""
	seenFolded := make(map[string]bool, len(rows))
	for _, row := range rows {
		folded := strings.ToLower(row.Path)
		if !stage2aV3InventoryRecordPath(row.Path) || row.Path <= previous ||
			seenFolded[folded] || !stage2aPrefixedDigest.MatchString(row.SHA256) ||
			want[row.Path] != row.SHA256 {
			return invalid
		}
		previous = row.Path
		seenFolded[folded] = true
	}
	return nil
}
