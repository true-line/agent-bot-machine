package members

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
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
		if len(omitted) != 0 {
			// appendLaunchDaemon has just matched this entire root-owned release
			// tree to its pinned archive and checked all of its ACLs. Recheck the
			// exact omitted paths in bounded batches, then inspect each opened
			// file descriptor. Rewalking every ancestor with a fresh /bin/ls for
			// each row made the owner challenge exceed its request deadline.
			paths := make([]string, len(omitted))
			for i, row := range omitted {
				paths[i] = filepath.Join(releaseDir, row.Path)
			}
			if err := checkDarwinACLs(paths); err != nil {
				return err
			}
		}
		for _, row := range omitted {
			raw, err := readVerifiedHQOmittedFile(filepath.Join(releaseDir, row.Path))
			if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != row.SHA256 {
				return errStage2aReservationAuthority
			}
		}
		delete(files, c.ComponentID)
	}
	return nil
}

// Only the omitted-H branch above calls this after the complete release tree
// and the batched per-file ACL check. Root owns that verified tree, so the
// administrator cannot change an ancestor between the two checks. Keep the
// leaf opened without symlink following and compare its full metadata after
// reading; a changed node or content still refuses the reviewed plan.
func readVerifiedHQOmittedFile(path string) ([]byte, error) {
	const limit = 2 << 20
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Gid != 0 || before.Nlink != 1 ||
		before.Mode&unix.S_IFMT != unix.S_IFREG ||
		(before.Mode&07777 != 0444 && before.Mode&07777 != 0644) ||
		before.Size < 1 || before.Size > limit {
		return nil, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
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
