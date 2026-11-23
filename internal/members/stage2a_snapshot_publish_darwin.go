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
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const stage2aFrozenSnapshotParent = stage2aDomainSnapshotParentV3

var stage2aSnapshotName = regexp.MustCompile(`^snap_[0-9a-f]{24}$`)

// A root install may prepare only fresh private A-owned nodes. The final
// no-follow remeasurement, rename and seal must run under A's effective UID.
type stage2aPreparedSnapshot struct {
	WrapperPath string
	Wrapper     Stage2aSnapshotIdentity
	Stage       Stage2aSnapshotIdentity
	Digest      string
}

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
		// Root apply creates the private staging descriptors before handing
		// them to the nonroot A account. Only a new, root-owned descriptor in
		// its creation mode can cross that boundary; never repair an existing
		// descriptor or take ownership from another nonroot account.
		private := st.Mode == unix.S_IFDIR|0700 || st.Mode == unix.S_IFREG|0600
		if os.Getuid() != 0 || os.Geteuid() != 0 || st.Uid != 0 || !private {
			return errors.New("Stage 2a staging owner differs from custody UID")
		}
	}
	if st.Uid != uid || st.Gid != gid {
		owner := -1
		if st.Uid != uid {
			owner = int(uid)
		}
		if err := unix.Fchown(fd, owner, int(gid)); err != nil {
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
	approved Stage2aDefinitionRecord, mutable bool) (*os.File, unix.Stat_t, error) {
	var zero unix.Stat_t
	if relative != approved.Path {
		return nil, zero, errors.New("Stage 2a source path differs from approved record")
	}
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
		maxFileBytes := uint64(stage2aMaxFileBytes)
		if i == len(parts)-1 && stage2aQualifiedStockCLIRecord(approved) {
			maxFileBytes = stage2aStockCLIMaxBytes
		}
		st, checkErr := stage2aCheckedSourceNodeWithLimit(fd, uid, gid, mutable, maxFileBytes)
		if checkErr != nil {
			unix.Close(fd)
			return nil, zero, checkErr
		}
		if i < len(parts)-1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			unix.Close(fd)
			return nil, zero, errors.New("Stage 2a source parent is not a directory")
		}
	}
	maxFileBytes := uint64(stage2aMaxFileBytes)
	if stage2aQualifiedStockCLIRecord(approved) {
		maxFileBytes = stage2aStockCLIMaxBytes
	}
	st, err := stage2aCheckedSourceNodeWithLimit(fd, uid, gid, mutable, maxFileBytes)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || approved.Size == nil ||
		uint64(st.Size) != *approved.Size || stage2aRecordMode(st.Mode, mutable) != approved.Mode {
		unix.Close(fd)
		return nil, zero, errors.New("Stage 2a source file differs from approved metadata")
	}
	return os.NewFile(uintptr(fd), relative), st, nil
}

func stage2aCopyApprovedFile(sourceRootFD int, targetDir *os.File, record Stage2aDefinitionRecord,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32, mutable bool) error {
	source, before, err := stage2aOpenSourceFile(sourceRootFD, record.Path, sourceUID, sourceGID, record, mutable)
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
	return publishStage2aSourceAt(sourceRoot, destinationParent, name, sourceUID, sourceGID, snapshotUID, snapshotGID, approved, false)
}

func publishStage2aSourceAt(sourceRoot, destinationParent, name string,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32,
	approved []Stage2aDefinitionRecord, mutable bool) (Stage2aSnapshotIdentity, string, error) {
	return publishStage2aSnapshotAt(sourceRoot, destinationParent, name, sourceUID,
		sourceGID, snapshotUID, snapshotGID, approved, mutable, false, nil)
}

func stage2aExpandedRuntimeRecords(files []Stage2aDefinitionRecord) ([]Stage2aDefinitionRecord, error) {
	if _, err := stage2aLaunchFiles(files); err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	for _, file := range files {
		for parent := filepath.Dir(file.Path); parent != "."; parent = filepath.Dir(parent) {
			dirs[parent] = true
		}
	}
	records := make([]Stage2aDefinitionRecord, 0, len(files)+len(dirs))
	for dir := range dirs {
		records = append(records, Stage2aDefinitionRecord{Path: dir, Kind: "directory", Mode: "0555"})
	}
	records = append(records, files...)
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return records, nil
}

func publishStage2aRuntimeAt(sourceRoot, destinationParent, name string,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32,
	files []Stage2aDefinitionRecord, mutable bool) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	records, err := stage2aExpandedRuntimeRecords(files)
	if err != nil {
		return empty, "", err
	}
	return publishStage2aSnapshotAt(sourceRoot, destinationParent, name, sourceUID,
		sourceGID, snapshotUID, snapshotGID, records, mutable, true, nil)
}

func prepareStage2aInstallSnapshotAt(sourceRoot, destinationParent, name string,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32,
	approved []Stage2aDefinitionRecord, runtime bool) (stage2aPreparedSnapshot, error) {
	var prepared stage2aPreparedSnapshot
	if runtime {
		var err error
		approved, err = stage2aExpandedRuntimeRecords(approved)
		if err != nil {
			return prepared, err
		}
	}
	_, _, err := publishStage2aSnapshotAt(sourceRoot, destinationParent, name,
		sourceUID, sourceGID, snapshotUID, snapshotGID, approved, true, runtime, &prepared)
	return prepared, err
}

func publishStage2aSnapshotAt(sourceRoot, destinationParent, name string,
	sourceUID, sourceGID, snapshotUID, snapshotGID uint32,
	approved []Stage2aDefinitionRecord, mutable, runtime bool,
	prepare *stage2aPreparedSnapshot) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if !stage2aSnapshotName.MatchString(name) || !stage2aAbsolutePath(sourceRoot) ||
		!stage2aAbsolutePath(destinationParent) {
		return empty, "", errors.New("invalid Stage 2a snapshot request")
	}
	if err := stage2aRunnerReadableInventory(approved); err != nil {
		return empty, "", err
	}
	observe := observeStage2aSourceAt
	if runtime {
		observe = observeStage2aRuntimeAt
	}
	sourceIdentity, approvedDigest, err := observe(sourceRoot, sourceUID, sourceGID, approved, mutable)
	if err != nil {
		return empty, "", err
	}
	sourceRootFD, err := unix.Open(sourceRoot, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(sourceRootFD)
	openedSourceIdentity, sourceRootStat, err := stage2aSnapshotIdentityForSource(sourceRootFD, sourceUID, sourceGID, mutable)
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
	retainPrepared := false
	defer func() {
		if !retainPrepared {
			stage2aCleanPrivateStage(wrapperPath)
		}
	}()
	wrapperFD, err := unix.Openat(parentFD, tempName, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(wrapperFD)
	if err := checkDarwinACLs([]string{wrapperPath}); err != nil {
		return empty, "", err
	}
	if err := stage2aChownNew(wrapperFD, snapshotUID, snapshotGID); err != nil {
		return empty, "", err
	}
	var wrapper unix.Stat_t
	if err := unix.Fstat(wrapperFD, &wrapper); err != nil || wrapper.Uid != snapshotUID ||
		wrapper.Gid != snapshotGID || wrapper.Mode != unix.S_IFDIR|0700 {
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
			sourceUID, sourceGID, snapshotUID, snapshotGID, mutable); err != nil {
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
	afterIdentity, afterDigest, err := observe(sourceRoot, sourceUID, sourceGID, approved, mutable)
	if err != nil || afterIdentity != sourceIdentity || afterDigest != approvedDigest {
		return empty, "", errors.New("Stage 2a source changed during snapshot publication")
	}
	if err := unix.Fsync(wrapperFD); err != nil {
		return empty, "", err
	}
	if prepare != nil {
		stage, digest, err := observe(tempPath, snapshotUID, snapshotGID, approved, true)
		if err != nil || digest != approvedDigest {
			return empty, "", errors.New("Stage 2a prepared bytes differ from approved source")
		}
		wrapper, _, err := stage2aSnapshotIdentityForSource(wrapperFD, snapshotUID, snapshotGID, true)
		if err != nil {
			return empty, "", err
		}
		*prepare = stage2aPreparedSnapshot{WrapperPath: wrapperPath,
			Wrapper: wrapper, Stage: stage, Digest: digest}
		retainPrepared = true
		return stage, digest, nil
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
	identity, digest, err := observe(filepath.Join(destinationParent, name), snapshotUID, snapshotGID, approved, false)
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
