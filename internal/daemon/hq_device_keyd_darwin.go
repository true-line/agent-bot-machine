//go:build darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Hold the opened parent through signature verification and exec. Homebrew's
// Cellar itself can be admin-group writable. Its name can move, while an
// open protected bin directory and its relative child remain the same.
func openDeviceKeydParent(path string) (*os.File, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "agent-bot-keyd" {
		return nil, "", errHQDevice
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", errHQDevice
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	current := "/"
	for i := 0; ; i++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || !safeMembersPlanACL(fd, true) {
			return nil, "", errHQDevice
		}
		uid := int(st.Uid)
		// Darwin's local admin group is 80. The release bin itself and every
		// component after the Cellar must be writable only by its owner.
		brewGroup := (current == "/opt/homebrew" || current == "/opt/homebrew/Cellar") && uid == os.Geteuid() && st.Gid == 80 && i < len(parts)
		if uid != 0 && uid != os.Geteuid() || st.Mode&0002 != 0 || st.Mode&0020 != 0 && !brewGroup {
			return nil, "", errHQDevice
		}
		if i == len(parts) {
			break
		}
		next, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return nil, "", errHQDevice
		}
		_ = unix.Close(fd)
		fd = next
		current = filepath.Join(current, parts[i])
	}
	leaf, e := unix.Openat(fd, "agent-bot-keyd", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, "", errHQDevice
	}
	defer unix.Close(leaf)
	var info unix.Stat_t
	if unix.Fstat(leaf, &info) != nil || int(info.Uid) != os.Geteuid() || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0700 || !safeMembersPlanACL(leaf, false) {
		return nil, "", errHQDevice
	}
	parent := os.NewFile(uintptr(fd), filepath.Dir(path))
	fd = -1
	cwd, err := deviceDirectoryReference(parent)
	if err != nil {
		_ = parent.Close()
		return nil, "", errHQDevice
	}
	return parent, cwd, nil
}

func deviceDirectoryReference(dir *os.File) (string, error) {
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", errHQDevice
	}
	// Darwin volfs references name a filesystem object by device and file ID.
	// Keep dir open so that its inode cannot be recycled between children.
	path := fmt.Sprintf("/.vol/%d/%d", uint32(st.Dev), st.Ino)
	actual, err := os.Stat(path)
	want, fdErr := dir.Stat()
	if err != nil || fdErr != nil || !os.SameFile(want, actual) {
		return "", errHQDevice
	}
	return path, nil
}

const deviceKeydRequirement = `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "Z5DM34QS5U" and identifier "ai.true-line.agent-bot-keyd"`

func verifyDeviceCode(ctx context.Context, directory, name, requirement string) error {
	verify := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R="+requirement, "./"+name)
	verify.Dir = directory
	verify.Env = []string{"PATH=/usr/bin:/bin"}
	return verify.Run()
}

type keydOutput struct{ buf bytes.Buffer }

func (b *keydOutput) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > 8192 {
		return 0, errHQDevice
	}
	return b.buf.Write(p)
}

func runDeviceKeyd(ctx context.Context, home string, envelope deviceDelegation) ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, errHQDevice
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, errHQDevice
	}
	path, err := KeydBinary(executable)
	if err != nil {
		return nil, errHQDevice
	}
	parent, cwd, err := openDeviceKeydParent(path)
	if err != nil {
		return nil, errHQDevice
	}
	defer parent.Close()
	if verifyDeviceCode(ctx, cwd, "agent-bot-keyd", deviceKeydRequirement) != nil {
		return nil, errHQDevice
	}
	buf, err := json.Marshal(envelope)
	if err != nil {
		return nil, errHQDevice
	}
	cmd := exec.CommandContext(ctx, "./agent-bot-keyd", "hq-device")
	cmd.Dir = cwd
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(append(buf, '\n'))
	var out keydOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errHQDevice
	}
	return out.buf.Bytes(), nil
}
