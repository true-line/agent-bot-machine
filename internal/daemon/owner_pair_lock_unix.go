//go:build unix

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// This file is never renamed or unlinked. A process exit releases its flock.
func lockOwnerPairing(dir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(dir, "owner-pair.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f.Close, nil
}
