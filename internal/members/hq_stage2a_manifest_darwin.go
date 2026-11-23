package members

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type hqStage2aManifestRow struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// The owner-signed plan supplies the artifact and canonical manifest pins.
// Reopen each immutable source and verify its exact selected closure offline.
func checkHQStage2aApprovedReleaseSources(service HQService, inv stage2aDomainInventoryV3) error {
	s := service.Stage2a
	if s == nil || !hqStage2aValidExclusions(s.ExcludedHQReleasePaths) {
		return errStage2aReservationAuthority
	}
	return checkStage2aReleaseSourcePartition(s.Components, inv, service.ReleaseDir, s.ExcludedHQReleasePaths)
}

func checkStage2aApprovedReleaseSources(components []stage2aReleaseComponent, inv stage2aDomainInventoryV3) error {
	return checkStage2aReleaseSourcePartition(components, inv, "", nil)
}

func checkStage2aReleaseSourcePartition(components []stage2aReleaseComponent, inv stage2aDomainInventoryV3, releaseDir string, exclusions []string) error {
	files := make(map[string]map[string]string, len(components))
	for _, row := range inv.Files {
		if files[row.ComponentID] == nil {
			files[row.ComponentID] = map[string]string{}
		}
		files[row.ComponentID][row.ReleasePath] = row.SHA256
	}
	if len(files) != len(components) {
		return errStage2aReservationAuthority
	}
	for _, c := range components {
		if !c.valid() {
			return errStage2aReservationAuthority
		}
		if err := trustedPath(OSHost{}, c.ArtifactSource, false); err != nil {
			return err
		}
		if err := checkDarwinACLs(pathAncestry(c.ArtifactSource)); err != nil {
			return err
		}
		artifact, err := openPinnedFileLimit(c.ArtifactSource, strings.TrimPrefix(c.ArtifactSHA256, "sha256:"), 384<<20)
		if err != nil {
			return err
		}
		if err := artifact.Close(); err != nil {
			return err
		}
		manifest, err := stage2aReadRootFile(c.ManifestSource, 1<<20, 0444, 0644)
		if err != nil {
			return err
		}
		var excluded []string
		if c.ComponentID == "hq" {
			excluded = exclusions
		}
		omitted, err := checkHQStage2aManifestPartition(manifest, c.ManifestSHA256, files[c.ComponentID], excluded)
		if err != nil {
			return err
		}
		for _, row := range omitted {
			raw, err := stage2aReadRootFile(filepath.Join(releaseDir, row.Path), 2<<20, 0444, 0644)
			if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != row.SHA256 {
				return errStage2aReservationAuthority
			}
		}
		delete(files, c.ComponentID)
	}
	return nil
}

func checkHQStage2aManifestRows(raw []byte, expectedDigest string, selected map[string]string) error {
	_, err := checkHQStage2aManifestPartition(raw, expectedDigest, selected, nil)
	return err
}

func checkHQStage2aManifestPartition(raw []byte, expectedDigest string, selected map[string]string, excluded []string) ([]hqStage2aManifestRow, error) {
	if !hqStage2aValidExclusions(excluded) {
		return nil, errStage2aReservationAuthority
	}
	if len(selected) == 0 || stage2aStrictJSONBounded(raw, 1<<20, 8192) != nil ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != expectedDigest {
		return nil, errStage2aReservationAuthority
	}
	var manifest []hqStage2aManifestRow
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) || stage2aDecodeExact(raw, &manifest) != nil || len(manifest) != len(selected)+len(excluded) {
		return nil, errStage2aReservationAuthority
	}
	wantOmitted := make(map[string]bool, len(excluded))
	for _, path := range excluded {
		if _, overlaps := selected[path]; overlaps {
			return nil, errStage2aReservationAuthority
		}
		wantOmitted[path] = true
	}
	var omitted []hqStage2aManifestRow
	seen := make(map[string]bool, len(manifest))
	for _, row := range manifest {
		if seen[row.Path] || !stage2aPrefixedDigest.MatchString(row.SHA256) {
			return nil, errStage2aReservationAuthority
		}
		seen[row.Path] = true
		if wantOmitted[row.Path] {
			omitted = append(omitted, row)
		} else if selected[row.Path] != row.SHA256 {
			return nil, errStage2aReservationAuthority
		}
	}
	return omitted, nil
}
