//go:build darwin

package daemon

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readAdminGuestChallenge(path string, caller Caller) ([]byte, error) {
	base := filepath.Join(caller.RegisteredHome, "Library", "TartQualification")
	if filepath.Dir(path) != base || !guestVMNamePattern.MatchString(strings.TrimSuffix(filepath.Base(path), ".json")) ||
		!strings.HasSuffix(path, ".json") {
		return nil, errGuestOwnerPermit
	}
	parent, err := os.Lstat(base)
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
		return nil, errGuestOwnerPermit
	}
	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != caller.UID {
		return nil, errGuestOwnerPermit
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errGuestOwnerPermit
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() == 0 || info.Size() > 64*1024+1 {
		return nil, errGuestOwnerPermit
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(s.Uid) != caller.UID || s.Nlink != 1 {
		return nil, errGuestOwnerPermit
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+2))
	if err != nil || len(raw) > 64*1024+1 {
		return nil, errGuestOwnerPermit
	}
	return raw, nil
}
