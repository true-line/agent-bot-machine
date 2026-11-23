//go:build darwin

package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// stage2aObserveDomainV3At independently opens and measures every node named
// by a canonical reviewed H-code or R-runtime inventory. The caller still
// has to verify the owner plan, release manifests, A custody and signed
// descriptor. Observation alone never authorizes a protected start.
func stage2aObserveDomainV3At(rootPath string, ownerUID, readerGID uint32, raw []byte) (Stage2aSnapshotIdentity, string, error) {
	return stage2aObserveDomainV3AtMode(rootPath, ownerUID, readerGID, raw, false)
}

func stage2aObserveDomainV3AtMode(rootPath string, ownerUID, readerGID uint32, raw []byte,
	privateRoot bool) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || ownerUID < 400 || readerGID == 0 || !stage2aAbsolutePath(rootPath) {
		return empty, "", errors.New("invalid Stage 2a v3 domain observation")
	}
	rootFD, err := unix.Open(rootPath, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(rootFD)
	identity, before, err := stage2aSnapshotIdentityForSource(rootFD, ownerUID, readerGID, privateRoot)
	wantRootMode := "0555"
	if privateRoot {
		wantRootMode = "0700"
	}
	if err != nil || identity.RootPath != rootPath || identity.Mode != wantRootMode ||
		checkDarwinACLs([]string{rootPath}) != nil {
		return empty, "", errors.New("unsafe Stage 2a v3 domain root")
	}
	files := make(map[string]stage2aDomainFileV3, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Path] = file
	}
	dirs := make(map[string]stage2aDomainDirectoryV3, len(inv.Directories))
	for _, dir := range inv.Directories {
		dirs[dir.Path] = dir
	}
	seenFiles, seenDirs := 0, 0
	var total uint64
	aclPaths := make([]string, 0, len(inv.Files)+len(inv.Directories))
	var walk func(int, string, int) error
	walk = func(parentFD int, relative string, depth int) error {
		if depth > 16 {
			return errors.New("Stage 2a v3 domain depth exceeds bound")
		}
		listingFD, err := unix.Dup(parentFD)
		if err != nil {
			return err
		}
		listing := os.NewFile(uintptr(listingFD), filepath.Join(rootPath, relative))
		children, err := stage2aReadBoundedDir(listing, 1536)
		listing.Close()
		if err != nil {
			return err
		}
		for _, child := range children {
			name := child.Name()
			path := name
			if relative != "" {
				path = relative + "/" + name
			}
			if !stage2aV3InventoryRecordPath(path) {
				return errors.New("unreviewed Stage 2a v3 domain path")
			}
			fd, err := unix.Openat(parentFD, name, stage2aFileOpenFlags, 0)
			if err != nil {
				return err
			}
			absolute := filepath.Join(rootPath, filepath.FromSlash(path))
			var before unix.Stat_t
			statErr := unix.Fstat(fd, &before)
			if statErr != nil || before.Uid != ownerUID || before.Gid != readerGID ||
				before.Mode&07000 != 0 {
				unix.Close(fd)
				return errors.New("unsafe Stage 2a v3 domain node")
			}
			aclPaths = append(aclPaths, absolute)
			switch before.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				want, ok := dirs[path]
				if !ok || fmt.Sprintf("%04o", before.Mode&07777) != want.Mode ||
					seenDirs >= len(inv.Directories) {
					unix.Close(fd)
					return errors.New("Stage 2a v3 domain directory differs from inventory")
				}
				seenDirs++
				err = walk(fd, path, depth+1)
			case unix.S_IFREG:
				want, ok := files[path]
				if !ok || fmt.Sprintf("%04o", before.Mode&07777) != want.Mode ||
					before.Nlink != 1 || before.Size < 0 || uint64(before.Size) != want.SizeBytes ||
					seenFiles >= len(inv.Files) || want.SizeBytes > inv.Limits.MaxTotalBytes ||
					total > inv.Limits.MaxTotalBytes-want.SizeBytes {
					unix.Close(fd)
					return errors.New("Stage 2a v3 domain file differs from inventory")
				}
				seenFiles++
				total += want.SizeBytes
				opened := os.NewFile(uintptr(fd), absolute)
				hash := sha256.New()
				_, err = io.CopyN(hash, opened, int64(want.SizeBytes))
				var extra [1]byte
				n, extraErr := opened.Read(extra[:])
				var after unix.Stat_t
				statErr = unix.Fstat(fd, &after)
				opened.Close()
				if err != nil || n != 0 || extraErr != io.EOF || statErr != nil ||
					!stage2aSameNode(before, after) ||
					"sha256:"+fmt.Sprintf("%x", hash.Sum(nil)) != want.SHA256 {
					return errors.New("Stage 2a v3 domain bytes differ from inventory")
				}
				continue
			default:
				unix.Close(fd)
				return errors.New("unsupported Stage 2a v3 domain node")
			}
			var after unix.Stat_t
			statErr = unix.Fstat(fd, &after)
			unix.Close(fd)
			if err != nil || statErr != nil || !stage2aSameNode(before, after) {
				return errors.New("Stage 2a v3 domain directory changed during measurement")
			}
		}
		return nil
	}
	if err := walk(rootFD, "", 0); err != nil || seenFiles != len(inv.Files) ||
		seenDirs != len(inv.Directories) || total != inv.TotalBytes {
		return empty, "", errors.New("Stage 2a v3 domain closure differs from inventory")
	}
	if err := checkDarwinACLs(aclPaths); err != nil {
		return empty, "", err
	}
	var after unix.Stat_t
	if unix.Fstat(rootFD, &after) != nil || !stage2aSameNode(before, after) {
		return empty, "", errors.New("Stage 2a v3 domain root changed during measurement")
	}
	return identity, digest, nil
}
