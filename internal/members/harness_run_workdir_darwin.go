package members

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const harnessDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func checkedHarnessDir(fd int, path string, uid int) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || int(st.Uid) != uid || st.Mode&07777 != 0700 {
		unix.Close(fd)
		return nil, errors.New("expected a private harness directory owned by its role")
	}
	return os.NewFile(uintptr(fd), path), nil
}

func createHarnessDir(parent *os.File, name string, uid int) (*os.File, error) {
	fd := int(parent.Fd())
	if err := unix.Mkdirat(fd, name, 0700); err != nil && err != unix.EEXIST {
		return nil, err
	}
	child, err := unix.Openat(fd, name, harnessDirectoryFlags, 0)
	if err != nil {
		return nil, err
	}
	return checkedHarnessDir(child, filepath.Join(parent.Name(), name), uid)
}

// This path is the working directory HQ advertises to ACP session/new.
func harnessWorkdir(home string, uid int, request harnessRunInput) (*os.File, error) {
	if !launchSoul.MatchString(request.SoulID) || !launchAdapter.MatchString(request.MemberID) {
		return nil, errLaunchInput
	}
	fd, err := unix.Open(home, harnessDirectoryFlags, 0)
	if err != nil {
		return nil, err
	}
	dir, err := checkedHarnessDir(fd, home, uid)
	if err != nil {
		return nil, err
	}
	for _, part := range []string{".agent-bot-hq", "souls", request.SoulID, request.MemberID} {
		child, err := createHarnessDir(dir, part, uid)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = child
	}

	// ACP gives its client this exact member pathname. On a case-insensitive
	// volume opening a different member spelling can return the same inode.
	// F_GETPATH reports the stored spelling for the directory we actually hold.
	var path [unix.PathMax]byte
	var pinned runtime.Pinner
	pinned.Pin(&path[0])
	defer pinned.Unpin()
	_, err = unix.FcntlInt(dir.Fd(), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&path[0]))))
	n := bytes.IndexByte(path[:], 0)
	if err != nil || n <= 0 || filepath.Base(string(path[:n])) != request.MemberID {
		dir.Close()
		return nil, errors.New("member working directory does not have the requested spelling")
	}
	return dir, nil
}

// Each state directory is resolved beneath the validated ACP directory. Member
// IDs are case-sensitive in Souls. The exact ID gives each native state tree
// a stable name independent of account-wide cache and temp defaults.
func harnessStateEnv(work *os.File, home, memberID string, uid int) ([]string, error) {
	stateName := fmt.Sprintf(".harness-%x", sha256.Sum256([]byte(memberID)))
	state, err := createHarnessDir(work, stateName, uid)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	// The private POSIX modes cannot revoke access supplied by a Darwin ACL.
	paths := []string{state.Name()}
	for path := work.Name(); ; path = filepath.Dir(path) {
		paths = append(paths, path)
		if path == home {
			break
		}
		if filepath.Dir(path) == path {
			return nil, errLaunchInput
		}
	}
	var env []string
	for _, item := range []struct {
		dir  string
		vars []string
	}{
		{"home", []string{"HOME"}},
		{"config", []string{"XDG_CONFIG_HOME", "XDG_CONFIG_DIRS"}},
		{"data", []string{"XDG_DATA_HOME", "XDG_DATA_DIRS"}},
		{"state", []string{"XDG_STATE_HOME"}},
		{"cache", []string{"XDG_CACHE_HOME"}},
		{"run", []string{"XDG_RUNTIME_DIR"}},
		// Claude Code uses its own temporary-directory setting during ACP session/new.
		{"tmp", []string{"TMPDIR", "TMP", "TEMP", "CLAUDE_CODE_TMPDIR"}},
	} {
		dir, err := createHarnessDir(state, item.dir, uid)
		if err != nil {
			return nil, err
		}
		paths = append(paths, dir.Name())
		for _, key := range item.vars {
			env = append(env, key+"="+dir.Name())
		}
		dir.Close()
	}
	if err := checkDarwinACLs(paths); err != nil {
		return nil, err
	}
	return env, nil
}

func prepareHarnessWorkdir(cmd *exec.Cmd, home string, uid int, req harnessRunInput) (*os.File, error) {
	work, err := harnessWorkdir(home, uid, req)
	if err != nil {
		return nil, err
	}
	env, err := harnessStateEnv(work, home, req.MemberID, uid)
	if err != nil {
		work.Close()
		return nil, err
	}
	cmd.Env = append(cmd.Env, env...)
	return work, nil
}
