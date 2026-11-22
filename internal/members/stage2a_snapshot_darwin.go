//go:build darwin

package members

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const stage2aDirectoryOpenFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
const stage2aFileOpenFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

type stage2aObservedEntry struct {
	record Stage2aDefinitionRecord
	stat   unix.Stat_t
}

func stage2aReadBoundedDir(dir *os.File, limit int) ([]os.DirEntry, error) {
	entries := make([]os.DirEntry, 0, min(limit, 64))
	for {
		batch, err := dir.ReadDir(min(64, limit+1-len(entries)))
		entries = append(entries, batch...)
		if len(entries) > limit {
			return nil, errors.New("Stage 2a directory exceeds entry limit")
		}
		if err == io.EOF {
			return entries, nil
		}
		if err != nil || len(batch) == 0 {
			return nil, errors.New("cannot enumerate complete Stage 2a directory")
		}
	}
}

func stage2aSameNode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Gen == b.Gen &&
		a.Btim == b.Btim && a.Mtim == b.Mtim && a.Ctim == b.Ctim &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode &&
		a.Nlink == b.Nlink && a.Size == b.Size && a.Flags == b.Flags
}

func stage2aCheckedNode(fd int, ownerUID, ownerGID uint32) (unix.Stat_t, error) {
	return stage2aCheckedSourceNode(fd, ownerUID, ownerGID, false)
}

func stage2aCheckedSourceNode(fd int, ownerUID, ownerGID uint32, mutable bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, err
	}
	mode := st.Mode & 07777
	if mutable {
		if mode&0022 != 0 {
			return st, errors.New("writable Stage 2a source has group or other write access")
		}
		mode &^= 0200
	}
	if st.Uid != ownerUID || st.Gid != ownerGID || !stage2aReadOnlyMode(fmt.Sprintf("%04o", mode)) ||
		(st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Mode&unix.S_IFMT != unix.S_IFREG) ||
		(st.Mode&unix.S_IFMT == unix.S_IFREG && (st.Nlink != 1 || st.Size < 0 || st.Size > stage2aMaxFileBytes)) {
		return st, errors.New("unsafe Stage 2a frozen node custody")
	}
	return st, nil
}

func stage2aRecordMode(native uint16, mutable bool) string {
	mode := native & 07777
	if mutable {
		mode &^= 0200
	}
	return fmt.Sprintf("%04o", mode)
}

func stage2aFDPath(fd int) (string, error) {
	var raw [unix.PathMax]byte
	var pinned runtime.Pinner
	pinned.Pin(&raw[0])
	defer pinned.Unpin()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&raw[0])))); err != nil {
		return "", err
	}
	end := bytes.IndexByte(raw[:], 0)
	if end < 2 || !stage2aAbsolutePath(string(raw[:end])) {
		return "", errors.New("Stage 2a snapshot descriptor has no canonical path")
	}
	return string(raw[:end]), nil
}

func stage2aSnapshotIdentity(fd int, ownerUID, ownerGID uint32) (Stage2aSnapshotIdentity, unix.Stat_t, error) {
	return stage2aSnapshotIdentityForSource(fd, ownerUID, ownerGID, false)
}

func stage2aSnapshotIdentityForSource(fd int, ownerUID, ownerGID uint32, mutable bool) (Stage2aSnapshotIdentity, unix.Stat_t, error) {
	var empty Stage2aSnapshotIdentity
	st, err := stage2aCheckedSourceNode(fd, ownerUID, ownerGID, mutable)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Btim.Sec < 0 ||
		st.Btim.Nsec < 0 || st.Btim.Nsec >= 1_000_000_000 ||
		st.Btim.Sec > (1<<63-1-st.Btim.Nsec)/1_000_000_000 {
		return empty, st, errors.New("invalid Stage 2a snapshot root")
	}
	actualPath, err := stage2aFDPath(fd)
	if err != nil {
		return empty, st, err
	}
	birth := st.Btim.Sec*1_000_000_000 + st.Btim.Nsec
	return Stage2aSnapshotIdentity{
		RootPath: actualPath, Device: strconv.FormatUint(uint64(uint32(st.Dev)), 10),
		Inode: strconv.FormatUint(st.Ino, 10), Generation: strconv.FormatUint(uint64(st.Gen), 10),
		BirthtimeNS: strconv.FormatInt(birth, 10), OwnerUID: st.Uid, OwnerGID: st.Gid,
		Mode: fmt.Sprintf("%04o", st.Mode&07777),
	}, st, nil
}

// The first pass enumerates and bounds the entire closed frozen tree before
// hashing any byte. Every child is opened relative to its held parent with
// O_NOFOLLOW; a path-based WalkDir cannot provide this guarantee.
func stage2aCollectFrozen(dir *os.File, relative string, ownerUID, ownerGID uint32, definition bool,
	entries *[]stage2aObservedEntry, total *uint64, mutable bool) error {
	st, err := stage2aCheckedSourceNode(int(dir.Fd()), ownerUID, ownerGID, mutable)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || len(*entries) >= stage2aMaxEntries {
		return errors.New("invalid Stage 2a frozen directory")
	}
	if err := checkDarwinACLs([]string{dir.Name()}); err != nil {
		return err
	}
	if relative != "" {
		*entries = append(*entries, stage2aObservedEntry{
			record: Stage2aDefinitionRecord{Path: relative, Kind: "directory", Mode: stage2aRecordMode(st.Mode, mutable)},
			stat:   st,
		})
	}
	children, err := stage2aReadBoundedDir(dir, stage2aMaxEntries)
	if err != nil {
		return err
	}
	slices.SortFunc(children, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for _, child := range children {
		name := child.Name()
		path := filepath.Join(relative, name)
		if !stage2aRecordPath(path) || len(*entries) >= stage2aMaxEntries {
			return errors.New("invalid or excessive Stage 2a frozen path")
		}
		if definition && relative == "Contents" && name != "SoulInfo.json" && name != "SoulLock.json" &&
			name != "opt" && name != "primitives" {
			return errors.New("unreviewed top-level Stage 2a frozen path")
		}
		fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
		if err != nil {
			return err
		}
		absolute := filepath.Join(dir.Name(), name)
		opened := os.NewFile(uintptr(fd), absolute)
		st, err := stage2aCheckedSourceNode(fd, ownerUID, ownerGID, mutable)
		if err != nil {
			opened.Close()
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			err = stage2aCollectFrozen(opened, path, ownerUID, ownerGID, definition, entries, total, mutable)
			opened.Close()
			if err != nil {
				return err
			}
			continue
		}
		if err := checkDarwinACLs([]string{absolute}); err != nil {
			opened.Close()
			return err
		}
		size := uint64(st.Size)
		if *total > stage2aMaxTotalBytes-size {
			opened.Close()
			return errors.New("Stage 2a frozen tree exceeds byte limit")
		}
		*total += size
		*entries = append(*entries, stage2aObservedEntry{
			record: Stage2aDefinitionRecord{Path: path, Kind: "regular", Mode: stage2aRecordMode(st.Mode, mutable), Size: &size},
			stat:   st,
		})
		opened.Close()
	}
	return nil
}

func stage2aReopenFrozen(rootFD int, relative string, ownerUID, ownerGID uint32, metadata map[string]unix.Stat_t) (*os.File, error) {
	return stage2aReopenSource(rootFD, relative, ownerUID, ownerGID, metadata, false)
}

func stage2aReopenSource(rootFD int, relative string, ownerUID, ownerGID uint32, metadata map[string]unix.Stat_t, mutable bool) (*os.File, error) {
	parts := strings.Split(relative, "/")
	parent, err := unix.Dup(rootFD)
	if err != nil {
		return nil, err
	}
	current := ""
	for i, part := range parts {
		flags := stage2aDirectoryOpenFlags
		if i == len(parts)-1 {
			flags = stage2aFileOpenFlags
		}
		fd, openErr := unix.Openat(parent, part, flags, 0)
		unix.Close(parent)
		if openErr != nil {
			return nil, openErr
		}
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		st, checkErr := stage2aCheckedSourceNode(fd, ownerUID, ownerGID, mutable)
		if checkErr != nil || !stage2aSameNode(st, metadata[current]) {
			unix.Close(fd)
			return nil, errors.New("Stage 2a frozen path changed between observations")
		}
		parent = fd
	}
	return os.NewFile(uintptr(parent), relative), nil
}

func observeStage2aFrozenAt(rootPath string, ownerUID, ownerGID uint32,
	approved []Stage2aDefinitionRecord) (Stage2aSnapshotIdentity, string, error) {
	return observeStage2aSourceAt(rootPath, ownerUID, ownerGID, approved, false)
}

func observeStage2aSourceAt(rootPath string, ownerUID, ownerGID uint32,
	approved []Stage2aDefinitionRecord, mutable bool) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if _, _, err := Stage2aDefinitionDigest(approved); err != nil {
		return empty, "", err
	}
	rootFD, err := unix.Open(rootPath, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(rootFD)
	identity, rootStat, err := stage2aSnapshotIdentityForSource(rootFD, ownerUID, ownerGID, mutable)
	if err != nil {
		return empty, "", err
	}
	listingFD, err := unix.Dup(rootFD)
	if err != nil {
		return empty, "", err
	}
	listing := os.NewFile(uintptr(listingFD), rootPath)
	rootEntries, listErr := stage2aReadBoundedDir(listing, 1)
	listing.Close()
	if listErr != nil || len(rootEntries) != 1 || rootEntries[0].Name() != "Contents" {
		return empty, "", errors.New("Stage 2a snapshot root has unreviewed entries")
	}
	contentsFD, err := unix.Openat(rootFD, "Contents", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	contents := os.NewFile(uintptr(contentsFD), filepath.Join(rootPath, "Contents"))
	entries := make([]stage2aObservedEntry, 0, len(approved))
	var total uint64
	err = stage2aCollectFrozen(contents, "Contents", ownerUID, ownerGID, true, &entries, &total, mutable)
	contents.Close()
	if err != nil || len(entries) != len(approved) {
		return empty, "", errors.New("Stage 2a frozen inventory differs from approved closure")
	}
	metadata := make(map[string]unix.Stat_t, len(entries))
	for i := range entries {
		got, want := entries[i].record, approved[i]
		if got.Path != want.Path || got.Kind != want.Kind || got.Mode != want.Mode ||
			(got.Size == nil) != (want.Size == nil) ||
			(got.Size != nil && *got.Size != *want.Size) {
			return empty, "", errors.New("Stage 2a frozen metadata differs from approved closure")
		}
		metadata[got.Path] = entries[i].stat
	}
	for i := range entries {
		if entries[i].record.Kind != "regular" {
			continue
		}
		file, err := stage2aReopenSource(rootFD, entries[i].record.Path, ownerUID, ownerGID, metadata, mutable)
		if err != nil {
			return empty, "", err
		}
		hash := sha256.New()
		_, err = io.CopyN(hash, file, int64(*entries[i].record.Size))
		var extra [1]byte
		n, extraErr := file.Read(extra[:])
		var after unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &after)
		file.Close()
		if err != nil || n != 0 || extraErr != io.EOF || statErr != nil ||
			!stage2aSameNode(entries[i].stat, after) {
			return empty, "", errors.New("Stage 2a frozen bytes changed during measurement")
		}
		entries[i].record.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
		if entries[i].record.SHA256 != approved[i].SHA256 {
			return empty, "", errors.New("Stage 2a frozen bytes differ from owner inventory")
		}
	}
	var afterRoot unix.Stat_t
	if err := unix.Fstat(rootFD, &afterRoot); err != nil || !stage2aSameNode(rootStat, afterRoot) {
		return empty, "", errors.New("Stage 2a frozen root changed during measurement")
	}
	records := make([]Stage2aDefinitionRecord, len(entries))
	for i, entry := range entries {
		records[i] = entry.record
	}
	digest, err := CheckStage2aApprovedDefinition(records, approved)
	if err != nil {
		return empty, "", err
	}
	return identity, digest, nil
}

// ObserveStage2aFrozenSnapshot is an independent read-only observation of an
// already-published root-owned frozen snapshot. It cannot create or publish
// the snapshot and grants no start authority. A positive launcher must repeat
// this observation immediately before exec and compare its identity with the
// same one-use signed measurement binding.
func ObserveStage2aFrozenSnapshot(expected Stage2aSnapshotIdentity,
	approved []Stage2aDefinitionRecord) (string, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		!stage2aValidSnapshotClaim(expected, 0) {
		return "", errors.New("Stage 2a frozen observation requires Machine root custody")
	}
	if err := trustedPath(OSHost{}, expected.RootPath, true); err != nil {
		return "", err
	}
	if err := checkDarwinACLs(pathAncestry(expected.RootPath)); err != nil {
		return "", err
	}
	observed, digest, err := observeStage2aFrozenAt(expected.RootPath, 0, expected.OwnerGID, approved)
	if err != nil || observed != expected {
		return "", errors.New("Stage 2a frozen snapshot identity or bytes differ")
	}
	return digest, nil
}
