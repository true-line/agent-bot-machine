//go:build darwin

package statedir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const macLockName = ".managed-machine-lifecycle.lock"
const macPreparePrefix = ".managed-machine-lifecycle.prepare-"
const macDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
const macLockFlags = unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

type macPackageLock struct {
	homePath      string
	home, library int
	file          int
	uid           int
	homeStat      unix.Stat_t
	libraryStat   unix.Stat_t
}

// LockMacPackage coordinates administrator Machine commands and the root HQ
// lifecycle caller. The caller supplies the account's registered home. Older
// lock-aware binaries use the Library inode on layouts where it is private.
func LockMacPackage(home string, uid int) (io.Closer, error) {
	euid := os.Geteuid()
	if !filepath.IsAbs(home) || uid <= 0 || (euid != uid && euid != 0) {
		return nil, errors.New("a registered macOS administrator home is required")
	}
	lock := &macPackageLock{homePath: home, uid: uid, home: -1, library: -1, file: -1}
	keep := false
	defer func() {
		if !keep {
			lock.closeDescriptors()
		}
	}()
	var err error
	lock.home, err = unix.Open(home, macDirectoryFlags, 0)
	if err != nil {
		return nil, err
	}
	if !trustedMacDirectory(lock.home, uid, &lock.homeStat) {
		return nil, errors.New("administrator home ownership or permissions changed")
	}
	lock.library, err = unix.Openat(lock.home, "Library", macDirectoryFlags, 0)
	if err != nil {
		return nil, err
	}
	if !trustedMacDirectory(lock.library, uid, &lock.libraryStat) {
		return nil, errors.New("administrator Library ownership or permissions changed")
	}
	homePrivate, libraryPrivate := lock.homeStat.Mode&0077 == 0, lock.libraryStat.Mode&0077 == 0
	if homePrivate || libraryPrivate {
		if !(homePrivate && SafeMacPathACL(lock.home, false)) && !(libraryPrivate && SafeMacPathACL(lock.library, false)) {
			return nil, errors.New("cannot verify a private directory for the legacy lifecycle lock")
		}
		if err := acquireMacFlock(lock.library); err != nil {
			return nil, err
		}
	}
	lock.file, err = lock.openFile()
	if err != nil {
		return nil, err
	}
	if !lock.unchangedDirectories() || !lock.matchesFile(macLockName, lock.file) {
		return nil, errors.New("administrator directories or lifecycle lock changed while acquiring the lock")
	}
	if err := lock.removePreparations(); err != nil {
		return nil, err
	}
	keep = true
	return lock, nil
}

func trustedMacDirectory(fd, uid int, st *unix.Stat_t) bool {
	return unix.Fstat(fd, st) == nil && int(st.Uid) == uid && st.Mode&0022 == 0 && SafeMacPathACL(fd, true)
}

func sameMacLockNode(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode
}

func (l *macPackageLock) unchangedDirectories() bool {
	var home, library, heldHome, heldLibrary unix.Stat_t
	return trustedMacDirectory(l.home, l.uid, &heldHome) && trustedMacDirectory(l.library, l.uid, &heldLibrary) &&
		unix.Lstat(l.homePath, &home) == nil && unix.Fstatat(l.home, "Library", &library, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		sameMacLockNode(l.homeStat, heldHome) && sameMacLockNode(l.libraryStat, heldLibrary) &&
		sameMacLockNode(heldHome, home) && sameMacLockNode(heldLibrary, library)
}

func acquireMacFlock(fd int) error {
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("Machine or managed HQ lifecycle is busy or unavailable: %w", err)
	}
	return nil
}

func privateMacLockFile(st unix.Stat_t) bool {
	return st.Mode == unix.S_IFREG|0600 && st.Nlink == 1 && st.Size == 0
}

func (l *macPackageLock) matchesFile(name string, fd int) bool {
	var held, named unix.Stat_t
	return unix.Fstat(fd, &held) == nil && privateMacLockFile(held) && int(held.Uid) == l.uid &&
		SafeMacPathACL(fd, false) && unix.Fstatat(l.library, name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		sameMacLockNode(held, named) && named.Nlink == 1 && named.Size == 0
}

func (l *macPackageLock) openFile() (int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		fd, err := unix.Openat(l.library, macLockName, macLockFlags|unix.O_RDONLY, 0)
		if errors.Is(err, unix.ENOENT) {
			fd, err = l.publishFile()
			if errors.Is(err, unix.EEXIST) {
				continue
			}
			return fd, err
		}
		if err != nil {
			return -1, err
		}
		if !l.matchesFile(macLockName, fd) {
			unix.Close(fd)
			return -1, errors.New("administrator lifecycle lock ownership, permissions or identity changed")
		}
		if err := acquireMacFlock(fd); err != nil {
			unix.Close(fd)
			return -1, err
		}
		// Revalidate after taking the lock to reject a closed, unlinked inode
		// opened by a contender just before its predecessor finished.
		if !l.matchesFile(macLockName, fd) {
			unix.Close(fd)
			return -1, errors.New("administrator lifecycle lock was replaced while acquiring it")
		}
		return fd, nil
	}
	return -1, errors.New("administrator lifecycle lock is busy or changed")
}

func (l *macPackageLock) publishFile() (int, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return -1, err
	}
	name := macPreparePrefix + hex.EncodeToString(nonce)
	fd, err := unix.Openat(l.library, name, macLockFlags|unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return -1, err
	}
	keep := false
	defer func() {
		if !keep {
			var held, named unix.Stat_t
			if unix.Fstat(fd, &held) == nil && unix.Fstatat(l.library, name, &named, unix.AT_SYMLINK_NOFOLLOW) == nil &&
				sameMacLockNode(held, named) && named.Nlink == 1 {
				_ = unix.Unlinkat(l.library, name, 0)
			}
			unix.Close(fd)
		}
	}()
	if err := acquireMacFlock(fd); err != nil {
		return -1, err
	}
	if os.Geteuid() == 0 {
		if err := unix.Fchown(fd, l.uid, int(l.libraryStat.Gid)); err != nil {
			return -1, err
		}
	}
	if err := unix.Fchmod(fd, 0600); err != nil {
		return -1, err
	}
	if !l.matchesFile(name, fd) || !l.unchangedDirectories() {
		return -1, errors.New("cannot verify the prepared administrator lifecycle lock")
	}
	// Publish only after ownership and mode are correct, while the inode is
	// already locked. A root process interrupted earlier leaves a preparation,
	// never a root-owned lock at the stable name.
	if err := unix.RenameatxNp(l.library, name, l.library, macLockName, unix.RENAME_EXCL); err != nil {
		return -1, err
	}
	keep = true
	return fd, nil
}

func (l *macPackageLock) removePreparations() error {
	fd, err := unix.Openat(l.library, ".", macDirectoryFlags, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), l.homePath)
	defer dir.Close()
	for {
		names, err := dir.Readdirnames(64)
		for _, name := range names {
			suffix, found := strings.CutPrefix(name, macPreparePrefix)
			if !found || len(suffix) != 24 {
				continue
			}
			if _, err := hex.DecodeString(suffix); err != nil {
				continue
			}
			var st unix.Stat_t
			err := unix.Fstatat(l.library, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if err != nil {
				return err
			}
			// A root process can die before transferring the temporary inode.
			// The verified owner can unlink that empty preparation from Library.
			// A contender that is still preparing cannot publish over our lock.
			if !privateMacLockFile(st) || (st.Uid != 0 && int(st.Uid) != l.uid) {
				return errors.New("unverified administrator lifecycle lock preparation")
			}
			if err := unix.Unlinkat(l.library, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (l *macPackageLock) Close() error {
	if l.file < 0 {
		return nil
	}
	defer l.closeDescriptors()
	if !l.unchangedDirectories() || !l.matchesFile(macLockName, l.file) {
		return errors.New("preserving a replaced administrator lifecycle lock")
	}
	if err := l.removePreparations(); err != nil {
		return err
	}
	// No lifecycle changes follow this unlink. New contenders may publish a
	// new inode, and a contender holding the old FD must verify its name
	// again after acquiring the kernel lock.
	return unix.Unlinkat(l.library, macLockName, 0)
}

func (l *macPackageLock) closeDescriptors() {
	for _, fd := range []int{l.file, l.library, l.home} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	l.file, l.library, l.home = -1, -1, -1
}
