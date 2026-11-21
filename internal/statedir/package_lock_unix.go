//go:build unix

package statedir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// LockMacPackage serializes changes to Machine and the managed HQ service. Open
// the existing registered owner's Library directory, so removal never creates a
// lock file or relies on a disposable daemon-state directory. Close to unlock.
func LockMacPackage(home string, uid int) (*os.File, error) {
	if !filepath.IsAbs(home) || uid <= 0 {
		return nil, errors.New("a registered macOS administrator home is required")
	}
	dir, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil || int(st.Uid) != uid || st.Mode&0022 != 0 {
		return nil, errors.New("administrator home ownership or permissions changed")
	}
	privateHome := st.Mode&0077 == 0
	fd, err := unix.Openat(dir, "Library", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(home, "Library"))
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != uid || st.Mode&0022 != 0 {
		f.Close()
		return nil, errors.New("administrator Library ownership or permissions changed")
	}
	if !privateHome && st.Mode&0077 != 0 {
		f.Close()
		return nil, errors.New("the lifecycle lock requires a private administrator home or Library directory")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("Machine or managed HQ lifecycle is busy or unavailable: %w", err)
	}
	cur, err := os.Lstat(f.Name())
	if err != nil || !cur.IsDir() || cur.Sys().(*syscall.Stat_t).Ino != st.Ino || uint64(cur.Sys().(*syscall.Stat_t).Dev) != uint64(st.Dev) {
		f.Close()
		return nil, errors.New("administrator Library changed while acquiring the lifecycle lock")
	}
	return f, nil
}
