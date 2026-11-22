package members

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
func createLaunchDirectory(path string, uid, gid int) (*os.File, error) {
	return createProtectedDirectory(path, uid, gid, 0755)
}

func createProtectedDirectory(path string, uid, gid int, mode os.FileMode) (_ *os.File, result error) {
	// The directory becomes accessible to its target UID after Fchown/Chmod.
	// Keep it below a root-private staging parent until the exclusive rename;
	// a live process with that UID must not populate or replace it first.
	private, err := os.MkdirTemp(filepath.Dir(path), ".hq-runtime-*")
	if err != nil {
		return nil, err
	}
	temp := filepath.Join(private, "directory")
	defer func() {
		if result != nil {
			result = errors.Join(result, syscall.Rmdir(temp), syscall.Rmdir(private))
		}
	}()
	if err := checkDarwinACLs([]string{private}); err != nil {
		return nil, err
	}
	if err := os.Mkdir(temp, 0700); err != nil {
		return nil, err
	}
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
	if err := dir.Chmod(mode); err != nil {
		return nil, err
	}
	info, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != uid || int(stat.Gid) != gid || info.Mode()&(os.ModePerm|os.ModeSetgid|os.ModeSetuid|os.ModeSticky) != mode {
		return nil, errors.New("prepared directory does not match the reviewed ownership and mode")
	}
	if err := checkDarwinACLs([]string{temp}); err != nil {
		return nil, err
	}
	if err := unix.RenamexNp(temp, path, unix.RENAME_EXCL); err != nil {
		return nil, err
	}
	if err := syscall.Rmdir(private); err != nil {
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

func createDarwinBrokerDirectory(p, owner, group string, mode uint32) error {
	return createDarwinBrokerDirectoryForIDs(p, owner, group, mode, -1, -1)
}

func (OSRoot) CreateReviewedBrokerDirectory(p, owner, group string, mode uint32, uid, gid int) error {
	return createDarwinBrokerDirectoryForIDs(p, owner, group, mode, uid, gid)
}

var soulEndpointSlot = regexp.MustCompile(`^[0-9a-f]{20}$`)
var soulRunnerRoleAccount = regexp.MustCompile(`^_abm-sr-[0-9a-f]{20}$`)
var soulBridgeRoleAccount = regexp.MustCompile(`^_abm-br-[0-9a-f]{20}$`)

// CreateReviewedSoulEndpointDirectory is used only by the paired B account
// plan. The path shape, role names and numeric identities are checked again
// under root before publishing a cross-owned directory.
func (OSRoot) CreateReviewedSoulEndpointDirectory(p, owner, group string, mode uint32, reviewedUID, reviewedGID int) error {
	if p == DarwinBrokerDir || filepath.Dir(p) == DarwinBrokerDir {
		return createDarwinBrokerDirectoryForIDs(p, owner, group, mode, reviewedUID, reviewedGID)
	}
	parent := filepath.Dir(p)
	base := filepath.Base(p)
	rootBase := parent == launchRuntimeDir && (base == "m" || base == "s" || base == "r")
	if rootBase {
		if owner != "root" || group != "wheel" || mode != 0755 || reviewedUID != 0 || reviewedGID != 0 {
			return errors.New("unexpected Soul endpoint root")
		}
	} else {
		kind := filepath.Base(parent)
		if filepath.Dir(parent) != launchRuntimeDir || !soulEndpointSlot.MatchString(base) || mode != 02750 ||
			!soulRunnerRoleAccount.MatchString(owner) && !soulBridgeRoleAccount.MatchString(owner) && owner != DarwinHQAccount ||
			!soulRunnerRoleAccount.MatchString(group) && !soulBridgeRoleAccount.MatchString(group) ||
			reviewedUID < 300 || reviewedUID > 399 || reviewedGID < 300 || reviewedGID > 399 {
			return errors.New("unexpected Soul endpoint directory")
		}
		switch kind {
		case "m":
			if !soulRunnerRoleAccount.MatchString(owner) || !soulBridgeRoleAccount.MatchString(group) {
				return errors.New("unexpected member endpoint roles")
			}
		case "s":
			if !soulBridgeRoleAccount.MatchString(owner) || !soulRunnerRoleAccount.MatchString(group) {
				return errors.New("unexpected relay endpoint roles")
			}
		case "r":
			if owner != DarwinHQAccount || !soulRunnerRoleAccount.MatchString(group) {
				return errors.New("unexpected admission endpoint roles")
			}
		default:
			return errors.New("unexpected Soul endpoint kind")
		}
		e, ok, err := (OSHost{}).Lstat(parent)
		if err != nil || !ok || !e.Dir || e.Owner != "root" || e.Group != "wheel" || e.Mode != 0755 {
			return errors.New("Soul endpoint root changed")
		}
	}
	if err := checkBrokerParent(OSHost{}, launchRuntimeDir); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(parent)); err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil || uid != reviewedUID || gid != reviewedGID {
		return errors.New("reviewed Soul endpoint ownership changed")
	}
	dir, err := createProtectedDirectory(p, uid, gid, fileMode(mode))
	if err != nil {
		return err
	}
	return dir.Close()
}

func createDarwinBrokerDirectoryForIDs(p, owner, group string, mode uint32, reviewedUID, reviewedGID int) error {
	switch {
	case p == DarwinBrokerDir && owner == "root" && group == "wheel" && mode == 0755:
	case filepath.Dir(p) == DarwinBrokerDir && owner == DarwinHQAccount && accountName.MatchString(group) && filepath.Base(p) == group && mode == 02750:
	default:
		return errors.New("unexpected Darwin broker directory")
	}
	parent := filepath.Dir(p)
	if err := checkBrokerParent(OSHost{}, parent); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(parent)); err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	if reviewedUID >= 0 && (uid != reviewedUID || gid != reviewedGID) {
		return errors.New("reviewed broker directory ownership changed")
	}
	dir, err := createProtectedDirectory(p, uid, gid, fileMode(mode))
	if err != nil {
		return err
	}
	return dir.Close()
}
