package members

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareLaunchDirectory(reviewed *launchDirectory, capability string, createdJob bool) (*os.File, error) {
	if capability == launchControlV1 && reviewed == nil {
		return nil, nil
	}
	if capability != launchControlV2 || reviewed == nil {
		return nil, errors.New("the release and approved runtime directory do not match")
	}
	observed, err := planLaunchDirectory(OSHost{}, checkDarwinACLs)
	if err != nil {
		return nil, err
	}
	if *observed != *reviewed || !createdJob && reviewed.Action == ActionCreate {
		return nil, errors.New("approved HQ runtime directory state changed; make a new plan")
	}
	if reviewed.Action == ActionNone {
		return nil, nil
	}
	dir, err := createLaunchDirectory(launchRuntimeDir, 0, 0)
	if err != nil {
		return dir, err
	}
	// Read ownership, final mode and actual inherited ACLs before use.
	observed, err = planLaunchDirectory(OSHost{}, checkDarwinACLs)
	if err == nil && observed.Action != ActionNone {
		err = errors.New("newly created HQ runtime directory is missing")
	}
	return dir, err
}

func rollbackLaunchDirectory(dir *os.File, service HQService, owner string) error {
	loaded, _, err := loadedLaunchDaemon(service, owner)
	if err != nil || loaded {
		return errors.Join(errors.New("preserving HQ runtime directory because the job may still exist"), err)
	}
	observed, err := planLaunchDirectory(OSHost{}, checkDarwinACLs)
	if err != nil || observed.Action == ActionCreate {
		return err
	}
	return removeLaunchDirectory(dir, launchRuntimeDir)
}

// Stage the final ownership and mode first. A crash during preparation
// cannot leave the reviewed name pointing to a half-configured directory.
// Exclusive publication also protects an empty directory a concurrent
// installer created after review.
func createLaunchDirectory(path string, uid, gid int) (_ *os.File, result error) {
	temp, err := os.MkdirTemp(filepath.Dir(path), ".hq-runtime-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, syscall.Rmdir(temp))
		}
	}()
	dir, err := os.OpenFile(temp, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			dir.Close()
		}
	}()
	if err := dir.Chown(uid, gid); err != nil {
		return nil, err
	}
	if err := dir.Chmod(0755); err != nil {
		return nil, err
	}
	if err := checkDarwinACLs([]string{temp}); err != nil {
		return nil, err
	}
	if err := unix.RenamexNp(temp, path, unix.RENAME_EXCL); err != nil {
		return nil, err
	}
	return dir, nil
}

// The parent is root-managed, and the open descriptor pins the directory
// created by this invocation. AT_REMOVEDIR refuses nonempty directories.
func removeLaunchDirectory(dir *os.File, path string) error {
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	var original, current unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &original); err != nil {
		return err
	}
	name := filepath.Base(path)
	if err := unix.Fstatat(int(parent.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if current.Mode&unix.S_IFMT != unix.S_IFDIR || original.Ino == 0 || current.Ino != original.Ino || current.Dev != original.Dev {
		return errors.New("preserving a changed HQ runtime directory")
	}
	return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
}
