//go:build darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Explain the same directory modes and owners used for delegation.
func deviceKeydDirectoryIssue(path string, st unix.Stat_t, administrator int, ancestor bool) error {
	uid := int(st.Uid)
	if uid != 0 && uid != administrator {
		return fmt.Errorf("directory %q is owned by UID %d, expected root or the Homebrew administrator", path, uid)
	}
	mode := st.Mode & 07777
	if mode&0002 != 0 {
		return fmt.Errorf("directory %q mode %04o allows other users to write", path, mode)
	}
	if mode&0020 == 0 {
		return nil
	}
	// Darwin's local admin group is 80. The release bin itself and every
	// component after the Cellar must be writable only by its owner.
	if ancestor && (path == "/opt/homebrew" || path == "/opt/homebrew/Cellar") {
		if uid == administrator && st.Gid == 80 {
			return nil
		}
		return fmt.Errorf("directory %q mode %04o allows group %d to write; group write here requires the Homebrew administrator and macOS admin group (80)", path, mode, st.Gid)
	}
	return fmt.Errorf("directory %q mode %04o allows group %d to write", path, mode, st.Gid)
}

func deviceKeydPackagePath(executable string) (keyd, machine string, err error) {
	machine, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", "", err
	}
	keyd, err = KeydBinary(machine)
	return keyd, machine, err
}

// The local administrator's status check only inspects the custody path.
func deviceKeydPathIssue(executable string) string {
	return inspectDeviceKeydPath(executable, macPackagePrefixes[:])
}

func inspectDeviceKeydPath(executable string, prefixes []string) string {
	path, machine, err := deviceKeydPackagePath(executable)
	if err != nil {
		return ""
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		parent, _, err := openDeviceKeydParent(path)
		if err == nil {
			_ = parent.Close()
			return ""
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err.Error()
		}
	}
	// A recognized Homebrew package includes keyd. Manual Machine-only
	// installations have no bundled helper to check.
	for _, prefix := range prefixes {
		if isPackageKegBin(prefix, filepath.Dir(machine)) && isPackageProgram(prefix, machine, false) {
			return fmt.Sprintf("bundled keyd %q is missing; verify the Machine Homebrew package", path)
		}
	}
	return ""
}

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
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, "", fmt.Errorf("inspect directory %q: %w", current, err)
		}
		if !safeMembersPlanACL(fd, true) {
			return nil, "", fmt.Errorf("directory %q has an unsupported or unreadable ACL", current)
		}
		if err := deviceKeydDirectoryIssue(current, st, os.Geteuid(), i < len(parts)); err != nil {
			return nil, "", err
		}
		if i == len(parts) {
			break
		}
		next, e := unix.Openat(fd, parts[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		current = filepath.Join(current, parts[i])
		if e != nil {
			return nil, "", fmt.Errorf("open directory %q: %w", current, e)
		}
		_ = unix.Close(fd)
		fd = next
	}
	leaf, e := unix.Openat(fd, "agent-bot-keyd", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, "", fmt.Errorf("open bundled keyd %q: %w", path, e)
	}
	defer unix.Close(leaf)
	var info unix.Stat_t
	if err := unix.Fstat(leaf, &info); err != nil {
		return nil, "", fmt.Errorf("inspect bundled keyd %q: %w", path, err)
	}
	if int(info.Uid) != os.Geteuid() || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0700 {
		return nil, "", fmt.Errorf("bundled keyd %q must be a regular file owned by the Homebrew administrator with mode 0700 (observed UID %d and mode %04o)", path, info.Uid, info.Mode&07777)
	}
	if !safeMembersPlanACL(leaf, false) {
		return nil, "", fmt.Errorf("bundled keyd %q has an unsupported or unreadable ACL", path)
	}
	parent := os.NewFile(uintptr(fd), filepath.Dir(path))
	fd = -1
	cwd, err := deviceDirectoryReference(parent)
	if err != nil {
		_ = parent.Close()
		return nil, "", fmt.Errorf("cannot verify the opened directory %q for bundled keyd", filepath.Dir(path))
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

type keydOutput struct {
	buf   bytes.Buffer
	limit int
}

func deviceKeydLimits(option string) (input, output int) {
	if option == "qualification-host-report" || option == "qualification-host-report-v2" || option == "qualification-host-report-v3" || option == "qualification-host-report-v4" {
		return 2 * 1024 * 1024, 2 * 1024 * 1024
	}
	return 16384, 8192
}

func (b *keydOutput) Write(p []byte) (int, error) {
	limit := b.limit
	if limit == 0 {
		limit = 8192
	}
	if b.buf.Len()+len(p) > limit {
		return 0, errHQDevice
	}
	return b.buf.Write(p)
}

func runDeviceKeyd(ctx context.Context, home string, envelope deviceDelegation) ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, errHQDevice
	}
	path, _, err := deviceKeydPackagePath(executable)
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
	inputLimit, outputLimit := deviceKeydLimits(envelope.Option)
	if len(buf) > inputLimit {
		return nil, errHQDevice
	}
	cmd := exec.CommandContext(ctx, "./agent-bot-keyd", "hq-device")
	cmd.Dir = cwd
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(append(buf, '\n'))
	out := keydOutput{limit: outputLimit}
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errHQDevice
	}
	return out.buf.Bytes(), nil
}

// runQualificationWitnessKeyd is the local secure-admin Machine-to-keyd
// transport. It is deliberately not registered as an HQ device option or
// daemon request. The signed request is built under Machine's live pair lock;
// keyd independently checks that pair, owner root, policy and its custody.
func runQualificationWitnessKeyd(ctx context.Context, adminHome, mode string, signedRequest []byte) ([]byte, error) {
	if mode != "init" && mode != "sign" && mode != "pin" {
		return nil, errHQDevice
	}
	if len(signedRequest) == 0 || len(signedRequest) > 3*1024*1024 {
		return nil, errHQDevice
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, errHQDevice
	}
	path, _, err := deviceKeydPackagePath(executable)
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
	cmd := exec.CommandContext(ctx, "./agent-bot-keyd", "qualification-witness", mode)
	cmd.Dir = cwd
	cmd.Env = []string{"HOME=" + adminHome, "PATH=/usr/bin:/bin"}
	cmd.Stdin = qualificationWitnessInput(signedRequest)
	out := keydOutput{limit: 8192}
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errHQDevice
	}
	return out.buf.Bytes(), nil
}

// keyd reads stdin to EOF and compares it with canonical JSON bytes before
// verifying the Machine signature. Transport framing is not part of that
// signed request, so the child must receive these bytes without a delimiter.
func qualificationWitnessInput(signedRequest []byte) *bytes.Reader {
	return bytes.NewReader(bytes.Clone(signedRequest))
}
