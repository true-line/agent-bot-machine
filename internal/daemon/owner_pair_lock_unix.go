//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
)

// This file is never renamed or unlinked. A process exit releases its flock.
func lockOwnerPairing(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "owner-pair.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
