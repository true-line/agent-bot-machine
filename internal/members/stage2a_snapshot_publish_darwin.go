//go:build darwin

package members

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const stage2aFrozenSnapshotParent = "/private/var/db/managed-machine/soul-snapshots"

var stage2aSnapshotName = regexp.MustCompile(`^snap_[0-9a-f]{24}$`)

// The published tree preserves approved modes. Every node the runner must
// traverse or read therefore needs access through its dedicated primary group.
func stage2aRunnerReadableInventory(approved []Stage2aDefinitionRecord) error {
	for _, record := range approved {
		mode, err := strconv.ParseUint(record.Mode, 8, 32)
		if err != nil {
			return errors.New("invalid Stage 2a inventory mode")
		}
		group := (mode >> 3) & 7
		if record.Kind == "directory" && group&5 != 5 ||
			record.Kind == "regular" && group&4 != 4 {
			return fmt.Errorf("Stage 2a runner cannot read approved entry %q", record.Path)
		}
	}
	return nil
}

func stage2aFrozenNamespace(installationID string) (string, error) {
	if !soulInstallationID.MatchString(installationID) {
		return "", errors.New("invalid Stage 2a snapshot installation")
	}
	return filepath.Join(stage2aFrozenSnapshotParent, soulEndpointInstallationSlot(installationID)), nil
}

func stage2aCommonSnapshotParent(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0711 {
		return errors.New("Stage 2a common snapshot parent has unsafe custody")
	}
	return nil
}

func stage2aPrivateSnapshotParent(fd int, uid, gid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
		st.Uid != uid || st.Gid != gid || st.Mode&07777 != 0750 {
		return errors.New("Stage 2a snapshot namespace is not limited to its runner group")
	}
	return nil
}

func stage2aChownNew(fd int, uid, gid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uid {
		return errors.New("Stage 2a staging owner differs from custody UID")
	}
	if st.Gid != gid {
		if err := unix.Fchown(fd, -1, int(gid)); err != nil {
			return err
		}
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Uid != uid || st.Gid != gid {
			return errors.New("Stage 2a staging group differs from assigned GID")
		}
	}
	return nil
}

func stage2aOpenSourceFile(rootFD int, relative string, uid, gid uint32,
	approved Stage2aDefinitionRecord) (*os.File, unix.Stat_t, error) {
	var zero unix.Stat_t
	fd, err := unix.Dup(rootFD)
	if err != nil {
		return nil, zero, err
	}
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		flags := stage2aDirectoryOpenFlags
		if i == len(parts)-1 {
			flags = stage2aFileOpenFlags
		}
		child, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, zero, openErr
		}
		fd = child
		st, checkErr := stage2aCheckedNode(fd, uid, gid)
		if checkErr != nil {
			unix.Close(fd)
			return nil, zero, checkErr
		}
		if i < len(parts)-1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return nil, zero, errors.New("Stage 2a source parent is not a directory")
		}
	}
	st, err := stage2aCheckedNode(fd, uid, gid)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || approved.Size == nil ||
		uint64(st.Size) != *approved.Size || fmt.Sprintf("%04o", st.Mode&07777) != approved.Mode {
		unix.Close(fd)
		return nil, zero, errors.New("Stage 2a source file differs from approved metadata")
	}
	return os.NewFile(uintptr(fd), relative), st, nil
}

func stage2aCopyApprovedFile(sourceRootFD int, targetDir *os.File, record Stage2aDefinitionRecord,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32) error {
	source, before, err := stage2aOpenSourceFile(sourceRootFD, record.Path, sourceUID, sourceGID, record)
	if err != nil {
		return err
	}
	defer source.Close()
	fd, err := unix.Openat(int(targetDir.Fd()), filepath.Base(record.Path),
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	target := os.NewFile(uintptr(fd), record.Path)
	defer target.Close()
	if err := stage2aChownNew(fd, snapshotUID, snapshotGID); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(target, hash), source, int64(*record.Size)); err != nil {
		return err
	}
	var extra [1]byte
	n, extraErr := source.Read(extra[:])
	var after unix.Stat_t
	statErr := unix.Fstat(int(source.Fd()), &after)
	if n != 0 || extraErr != io.EOF || statErr != nil || !stage2aSameNode(before, after) ||
		fmt.Sprintf("%x", hash.Sum(nil)) != record.SHA256 {
		return errors.New("Stage 2a source bytes changed while staging")
	}
	mode, _ := strconv.ParseUint(record.Mode, 8, 32)
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(mode)); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func stage2aCleanPrivateStage(path string) {
	_ = filepath.WalkDir(path, func(name string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(name, 0700)
		}
		return nil
	})
	_ = os.RemoveAll(path)
}

func publishStage2aFrozenAt(sourceRoot, destinationParent, name string,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32,
	approved []Stage2aDefinitionRecord) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if !stage2aSnapshotName.MatchString(name) || !stage2aAbsolutePath(sourceRoot) ||
		!stage2aAbsolutePath(destinationParent) {
		return empty, "", errors.New("invalid Stage 2a snapshot request")
	}
	if err := stage2aRunnerReadableInventory(approved); err != nil {
		return empty, "", err
	}
	sourceIdentity, approvedDigest, err := observeStage2aFrozenAt(sourceRoot, sourceUID, sourceGID, approved)
	if err != nil {
		return empty, "", err
	}
	sourceRootFD, err := unix.Open(sourceRoot, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(sourceRootFD)
	openedSourceIdentity, sourceRootStat, err := stage2aSnapshotIdentity(sourceRootFD, sourceUID, sourceGID)
	if err != nil || openedSourceIdentity != sourceIdentity {
		return empty, "", errors.New("Stage 2a source root changed before copy")
	}
	parentFD, err := unix.Open(destinationParent, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(parentFD)
	if err := stage2aPrivateSnapshotParent(parentFD, snapshotUID, snapshotGID); err != nil {
		return empty, "", err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, "", err
	}
	tempName := ".stage2a-" + hex.EncodeToString(nonce[:])
	if err := unix.Mkdirat(parentFD, tempName, 0700); err != nil {
		return empty, "", err
	}
	wrapperPath := filepath.Join(destinationParent, tempName)
	defer stage2aCleanPrivateStage(wrapperPath)
	wrapperFD, err := unix.Openat(parentFD, tempName, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(wrapperFD)
	var wrapper unix.Stat_t
	if err := unix.Fstat(wrapperFD, &wrapper); err != nil || wrapper.Uid != snapshotUID ||
		wrapper.Mode != unix.S_IFDIR|0700 {
		return empty, "", errors.New("Stage 2a staging wrapper is not private")
	}
	if err := checkDarwinACLs([]string{wrapperPath}); err != nil {
		return empty, "", err
	}
	const contentName = "snapshot"
	if err := unix.Mkdirat(wrapperFD, contentName, 0700); err != nil {
		return empty, "", err
	}
	tempPath := filepath.Join(wrapperPath, contentName)
	stageFD, err := unix.Openat(wrapperFD, contentName, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	stageRoot := os.NewFile(uintptr(stageFD), tempPath)
	if err := stage2aChownNew(stageFD, snapshotUID, snapshotGID); err != nil {
		stageRoot.Close()
		return empty, "", err
	}
	openDirs := map[string]*os.File{"": stageRoot}
	closeDirs := func() {
		for _, dir := range openDirs {
			_ = dir.Close()
		}
	}
	defer closeDirs()
	for _, record := range approved {
		parent := filepath.Dir(record.Path)
		if parent == "." {
			parent = ""
		}
		parentDir := openDirs[parent]
		if parentDir == nil {
			return empty, "", errors.New("Stage 2a snapshot parent is not in inventory")
		}
		if record.Kind == "directory" {
			name := filepath.Base(record.Path)
			if err := unix.Mkdirat(int(parentDir.Fd()), name, 0700); err != nil {
				return empty, "", err
			}
			fd, err := unix.Openat(int(parentDir.Fd()), name, stage2aDirectoryOpenFlags, 0)
			if err != nil {
				return empty, "", err
			}
			child := os.NewFile(uintptr(fd), filepath.Join(parentDir.Name(), name))
			if err := stage2aChownNew(fd, snapshotUID, snapshotGID); err != nil {
				child.Close()
				return empty, "", err
			}
			openDirs[record.Path] = child
			continue
		}
		if err := stage2aCopyApprovedFile(sourceRootFD, parentDir, record,
			sourceUID, sourceGID, snapshotUID, snapshotGID); err != nil {
			return empty, "", err
		}
	}
	for i := len(approved) - 1; i >= 0; i-- {
		record := approved[i]
		if record.Kind != "directory" {
			continue
		}
		dir := openDirs[record.Path]
		mode, _ := strconv.ParseUint(record.Mode, 8, 32)
		if err := unix.Fchmod(int(dir.Fd()), uint32(mode)); err != nil {
			return empty, "", err
		}
		if err := unix.Fsync(int(dir.Fd())); err != nil {
			return empty, "", err
		}
	}
	// Darwin requires owner write permission on a directory moved across
	// parents. Keep the root A-private until the rename, then seal the same
	// descriptor before any observer can accept the result.
	if err := unix.Fchmod(stageFD, 0700); err != nil {
		return empty, "", err
	}
	if err := unix.Fsync(stageFD); err != nil {
		return empty, "", err
	}
	var afterSourceRoot unix.Stat_t
	if err := unix.Fstat(sourceRootFD, &afterSourceRoot); err != nil ||
		!stage2aSameNode(sourceRootStat, afterSourceRoot) {
		return empty, "", errors.New("Stage 2a source root changed while copying")
	}
	afterIdentity, afterDigest, err := observeStage2aFrozenAt(sourceRoot, sourceUID, sourceGID, approved)
	if err != nil || afterIdentity != sourceIdentity || afterDigest != approvedDigest {
		return empty, "", errors.New("Stage 2a source changed during snapshot publication")
	}
	if err := unix.Fsync(wrapperFD); err != nil {
		return empty, "", err
	}
	if err := unix.RenameatxNp(wrapperFD, contentName, parentFD, name, unix.RENAME_EXCL); err != nil {
		return empty, "", err
	}
	// An uncertain chmod, sync or recheck leaves the destination occupied.
	if err := unix.Fchmod(stageFD, 0555); err != nil {
		return empty, "", err
	}
	if err := unix.Fsync(stageFD); err != nil {
		return empty, "", err
	}
	if err := unix.Fsync(wrapperFD); err != nil {
		return empty, "", errors.New("Stage 2a staging directory sync uncertain")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return empty, "", errors.New("Stage 2a snapshot publication sync uncertain")
	}
	pinned, _, err := stage2aSnapshotIdentity(stageFD, snapshotUID, snapshotGID)
	if err != nil {
		return empty, "", err
	}
	identity, digest, err := observeStage2aFrozenAt(filepath.Join(destinationParent, name), snapshotUID, snapshotGID, approved)
	if err != nil || identity != pinned || digest != approvedDigest {
		return empty, "", errors.New("Stage 2a published snapshot does not match approved bytes")
	}
	return identity, digest, nil
}

// PublishStage2aFrozenSnapshot copies one exact, already-approved root-owned
// frozen source into an installation-specific root:runner-group namespace and
// publishes it with an exclusive rename. The common parent is traverse-only;
// the namespace grants no access to sibling Soul groups. No CLI or protected
// start uses this operation yet. A future paired installer must pin the
// reviewed runner, source, inventory, name and receipt before calling it.
func PublishStage2aFrozenSnapshot(sourceRoot string, runner SoulRunner, name string,
	approved []Stage2aDefinitionRecord) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return empty, "", errors.New("Stage 2a snapshot publication requires Machine root custody")
	}
	if runner.UID < 300 || runner.UID > 399 || runner.GID != runner.UID ||
		runner.Account != soulRunnerName(runner.InstallationID) ||
		!soulIdentity.MatchString(runner.SoulID) {
		return empty, "", errors.New("invalid reviewed Stage 2a runner for snapshot")
	}
	namespace, err := stage2aFrozenNamespace(runner.InstallationID)
	if err != nil {
		return empty, "", err
	}
	for _, path := range []string{sourceRoot, stage2aFrozenSnapshotParent, namespace} {
		if err := trustedPath(OSHost{}, path, true); err != nil {
			return empty, "", err
		}
		if err := checkDarwinACLs(pathAncestry(path)); err != nil {
			return empty, "", err
		}
	}
	commonFD, err := unix.Open(stage2aFrozenSnapshotParent, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(commonFD)
	if err := stage2aCommonSnapshotParent(commonFD); err != nil {
		return empty, "", err
	}
	return publishStage2aFrozenAt(sourceRoot, namespace, name,
		0, 0, 0, uint32(runner.GID), approved)
}
