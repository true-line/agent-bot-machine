package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type stage2aHSourceManifestRowV3 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// stage2aValidateHSourceSelectionV3 checks the reviewed H source projection.
// The full HQ archive and Node binary have separate release pins. A caller must
// authenticate those pins and the owner plan before treating this selection as
// install authority. In particular, these bytes never authorize A to seal.
func stage2aValidateHSourceSelectionV3(inv stage2aDomainInventoryV3,
	sourceManifest []byte, sourceManifestDigest string, excluded []string,
	nodeArtifactDigest string) error {
	invalid := errors.New("Stage 2a H source selection differs from reviewed release")
	if inv.Domain != "H-code" || !stage2aPrefixedDigest.MatchString(sourceManifestDigest) ||
		!stage2aPrefixedDigest.MatchString(nodeArtifactDigest) ||
		len(sourceManifest) == 0 || len(sourceManifest) > 2<<20 ||
		stage2aStrictJSONBounded(sourceManifest, 2<<20, stage2aV3MaxJSONNodes) != nil ||
		(len(excluded) > 128 && !hqStage2aV0103FixtureFreeExclusions(excluded)) {
		return invalid
	}
	sum := sha256.Sum256(sourceManifest)
	if sourceManifestDigest != fmt.Sprintf("sha256:%x", sum) {
		return invalid
	}
	canonical, err := jsoncanonicalizer.Transform(sourceManifest)
	if err != nil || !bytes.Equal(sourceManifest, canonical) {
		return invalid
	}
	var rows []stage2aHSourceManifestRowV3
	decoder := json.NewDecoder(bytes.NewReader(sourceManifest))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&rows) != nil || decoder.Decode(new(any)) != io.EOF ||
		len(rows) == 0 || len(rows) > 1024 {
		return invalid
	}
	omitted := make(map[string]bool, len(excluded))
	previous := ""
	for _, path := range excluded {
		if path <= previous || !stage2aV3InventoryRecordPath(path) ||
			!strings.HasPrefix(path, "vendor/soul-contracts/fixtures/") {
			return invalid
		}
		omitted[path] = true
		previous = path
	}
	selected := make(map[string]stage2aDomainFileV3, len(inv.Files))
	nodeCount := 0
	for _, file := range inv.Files {
		switch file.ComponentID {
		case "hq":
			if file.Path != file.ReleasePath || omitted[file.ReleasePath] {
				return invalid
			}
			selected[file.ReleasePath] = file
		case "node":
			if file.Path != "bin/node" || file.ReleasePath != "bin/node" ||
				file.Mode != "0550" || file.SHA256 != nodeArtifactDigest {
				return invalid
			}
			nodeCount++
		default:
			return invalid
		}
	}
	if nodeCount != 1 || len(selected)+len(omitted) != len(rows) {
		return invalid
	}
	seen := make(map[string]bool, len(rows))
	previous = ""
	selectedCount, omittedCount := 0, 0
	for _, row := range rows {
		folded := strings.ToLower(row.Path)
		if !stage2aV3InventoryRecordPath(row.Path) || row.Path <= previous ||
			seen[folded] || !stage2aPrefixedDigest.MatchString(row.SHA256) {
			return invalid
		}
		seen[folded] = true
		previous = row.Path
		if omitted[row.Path] {
			omittedCount++
			continue
		}
		file, ok := selected[row.Path]
		if !ok || file.SHA256 != row.SHA256 {
			return invalid
		}
		selectedCount++
	}
	if selectedCount != len(selected) || omittedCount != len(omitted) ||
		selected["governance/interim-release.json"].Path == "" ||
		selected["governance/soul-contracts.json"].Path == "" {
		return invalid
	}
	return nil
}
