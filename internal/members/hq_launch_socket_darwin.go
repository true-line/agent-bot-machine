package members

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The open directory spans the initial absence check, bootstrap and bootout.
// The only production leaf eligible for removal is the fixed owner endpoint.
func removeStoppedLaunchSocket(socket string, parent *os.File, published os.FileInfo, pid string) error {
	if (socket != launchSocket && socket != launchRuntimeSocket) || parent.Name() != filepath.Dir(socket) {
		return errors.New("refusing unapproved HQ endpoint")
	}
	if err := trustedPath(OSHost{}, parent.Name(), true); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(parent.Name())); err != nil {
		return err
	}
	return unlinkStoppedSocket(parent, filepath.Base(socket), published, 0, pid)
}

const changedHQSocket = "preserving changed or unverified HQ owner-control endpoint"

func checkStoppedSocketIdentity(parent *os.File, name string, published os.FileInfo, uid uint32) error {
	currentParent, err := os.Lstat(parent.Name())
	if err != nil {
		return errors.New("cannot verify the anchored HQ endpoint directory")
	}
	anchored, err := parent.Stat()
	if err != nil || !os.SameFile(anchored, currentParent) {
		return errors.New(changedHQSocket)
	}
	dir, ok := anchored.Sys().(*syscall.Stat_t)
	if !ok || !anchored.IsDir() || dir.Uid != uid || dir.Mode&0022 != 0 || published == nil {
		return errors.New(changedHQSocket)
	}
	before, ok := published.Sys().(*syscall.Stat_t)
	if !ok || before.Ino == 0 || before.Nlink != 1 || before.Uid != uid || before.Mode != unix.S_IFSOCK|0666 {
		return errors.New(changedHQSocket)
	}
	fd := int(parent.Fd())
	var now unix.Stat_t
	if err := unix.Fstatat(fd, name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if now.Dev != before.Dev || now.Ino != before.Ino || now.Gen != before.Gen ||
		now.Btim.Sec != before.Birthtimespec.Sec || now.Btim.Nsec != before.Birthtimespec.Nsec ||
		now.Mode != before.Mode || now.Nlink != 1 || now.Uid != uid || now.Gid != before.Gid {
		return errors.New(changedHQSocket)
	}
	return nil
}

func unlinkStoppedSocket(parent *os.File, name string, published os.FileInfo, uid uint32, pid string) error {
	fd := int(parent.Fd())
	observe := func() error { return checkStoppedSocketIdentity(parent, name, published, uid) }
	if err := observe(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil // launchd already removed it.
		}
		return err
	}
	if pid != "" && pid != "0" {
		n, err := strconv.Atoi(pid)
		if err != nil || n <= 0 {
			return errors.New("preserving endpoint with an unverified HQ process")
		}
		// A successful bootout can precede final process exit.
		deadline := time.Now().Add(time.Second)
		for {
			err := unix.Kill(n, 0)
			if errors.Is(err, unix.ESRCH) {
				break
			}
			if err != nil || !time.Now().Before(deadline) {
				return errors.New("preserving endpoint while its HQ process may still exist")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	conn, err := net.DialTimeout("unix", filepath.Join(parent.Name(), name), 100*time.Millisecond)
	if err == nil {
		conn.Close()
		return errors.New("preserving a listening HQ owner-control endpoint")
	}
	if errors.Is(err, unix.ENOENT) {
		if errors.Is(observe(), unix.ENOENT) {
			return nil
		}
		return errors.New(changedHQSocket)
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		return errors.New("cannot verify the HQ owner-control endpoint is inactive")
	}
	if err = observe(); err == nil {
		// Darwin unlinkat(2), sys/fcntl.h. This also refuses an open
		// bound-but-not-listening Unix socket. Never fall back to unlink.
		const atNoDeleteBusy = 0x4000
		err = unix.Unlinkat(fd, name, atNoDeleteBusy)
	}
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOTSUP):
		return fmt.Errorf("preserving HQ endpoint because guarded unlink is unavailable: %w", err)
	case errors.Is(err, unix.EBUSY):
		return fmt.Errorf("preserving busy HQ endpoint: %w", err)
	}
	return err
}

// CheckDetachedDarwinSocket requires both socket types to encounter a detached
// vnode. Darwin checks a live socket's type before checking its listen state,
// so a bound, non-listening stream also vetoes removal via the datagram probe.
// Both lookups use the public filesystem entry even if launchd renamed it.
func CheckDetachedDarwinSocket(path string) error {
	for _, network := range []string{"unix", "unixgram"} {
		conn, err := net.DialTimeout(network, path, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return errors.New("preserving an endpoint with a live socket")
		}
		if !errors.Is(err, unix.ECONNREFUSED) {
			return errors.New("cannot establish that the endpoint is detached")
		}
	}
	return nil
}
