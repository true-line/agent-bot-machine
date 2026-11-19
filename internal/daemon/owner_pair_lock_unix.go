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

// Device operations use the established lock without creating state on status.
func lockDevicePairing(dir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(dir, "owner-pair.lock"), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || verifyDirOwner(f.Name(), info) != nil || syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		_ = f.Close()
		return nil, errHQDevice
	}
	return f.Close, nil
}

// A transfer path may be supplied from a shared location. Check the opened
// descriptor without ever following its final symlink or waiting for a FIFO.
func openFirstHQProof(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}

// The legacy directory remains the public channel across the migration.
func lockLegacyChannel(dir string) (func() error, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f.Close, nil
}
