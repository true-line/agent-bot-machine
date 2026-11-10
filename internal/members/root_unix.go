//go:build !windows

package members

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Programs an apply starts. They are named by absolute path and run with a
// fixed environment, so nothing in the caller's PATH or environment is used.
const (
	useraddPath = "/usr/sbin/useradd"
	visudoPath  = "/usr/sbin/visudo"
	shadowPath  = "/etc/shadow"
)

var rootEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// OSRoot changes the running host. Every method needs root.
type OSRoot struct{}

func runProgram(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = rootEnv
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(name), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// PasswordField implements Root.
func (OSRoot) PasswordField(account string) (string, bool, error) {
	records, err := fields(shadowPath)
	if err != nil {
		return "", false, err
	}
	for _, f := range records {
		if len(f) >= 2 && f[0] == account {
			return f[1], true, nil
		}
	}
	return "", false, nil
}

// ReadSudoers implements Root.
func (OSRoot) ReadSudoers() (string, bool, error) {
	fi, err := os.Lstat(SudoersPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if !fi.Mode().IsRegular() {
		return "", false, fmt.Errorf("%s is not a regular file", SudoersPath)
	}
	raw, err := os.ReadFile(SudoersPath)
	if err != nil {
		return "", false, err
	}
	return string(raw), true, nil
}

// CreateAccount implements Root. useradd leaves a new account locked.
func (OSRoot) CreateAccount(name string) error {
	home := filepath.Join(HomeBase, name)
	if err := runProgram(useraddPath, "--create-home", "--home-dir", home, "--user-group", "--shell", NoLoginShell, name); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
}

// CreateHQAccount implements Root. A system account gets a uid below the
// range of people's accounts and no password aging.
func (OSRoot) CreateHQAccount(name string) error {
	home := filepath.Join(HQHomeBase, name)
	if err := runProgram(useraddPath, "--system", "--create-home", "--home-dir", home, "--user-group", "--shell", NoLoginShell, name); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
}

func isDir(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", p)
	}
	return nil
}

func fileMode(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	return m
}

// SetMode implements Root.
func (OSRoot) SetMode(p string, mode uint32) error {
	if err := isDir(p); err != nil {
		return err
	}
	return os.Chmod(p, fileMode(mode))
}

func ids(owner, group string) (int, int, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// EnsureDir implements Root. The mode is set after the owner, because
// changing the owner clears the setgid bit.
func (OSRoot) EnsureDir(p, owner, group string, mode uint32) error {
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := isDir(p); err != nil {
		return err
	}
	if err := os.Lchown(p, uid, gid); err != nil {
		return err
	}
	return os.Chmod(p, fileMode(mode))
}

// RemoveDir implements Root.
func (OSRoot) RemoveDir(p string) error {
	if err := isDir(p); err != nil {
		return err
	}
	return os.RemoveAll(p)
}

// WriteFile implements Root. The temporary name has a dot in it, which
// sudo skips in sudoers.d, so a rule is never read before it is checked.
func (OSRoot) WriteFile(p string, mode uint32, content string, validate bool) error {
	tmp := filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".tmp")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(tmp, fs.FileMode(mode&0o777)); err != nil {
		return err
	}
	if validate {
		if err := runProgram(visudoPath, "-c", "-f", tmp); err != nil {
			return fmt.Errorf("the rule was not installed: %w", err)
		}
	}
	return os.Rename(tmp, p)
}

// Claim implements Root.
func (OSRoot) Claim(planID string, receipt []byte) (bool, error) {
	if err := os.MkdirAll(ReceiptsDir, 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(ReceiptPath(planID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := f.Write(receipt); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

// Finish implements Root.
func (OSRoot) Finish(planID string, receipt []byte) error {
	tmp := ReceiptPath(planID) + ".tmp"
	if err := os.WriteFile(tmp, receipt, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, ReceiptPath(planID))
}

// AncestorEnvs returns the environment of each process above this one, as
// far as /proc shows them. An agent session that starts sudo leaves its
// markers there even though sudo resets the environment of the command.
func AncestorEnvs() []map[string]string {
	var out []map[string]string
	pid := os.Getppid()
	for hops := 0; pid > 1 && hops < 64; hops++ {
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
			env := map[string]string{}
			for _, item := range strings.Split(string(raw), "\x00") {
				if k, v, ok := strings.Cut(item, "="); ok {
					env[k] = v
				}
			}
			out = append(out, env)
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		// pid (comm) state ppid ...; comm may hold spaces and parentheses.
		rest := string(stat)
		if i := strings.LastIndex(rest, ")"); i >= 0 {
			rest = rest[i+1:]
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			break
		}
		next, err := strconv.Atoi(f[1])
		if err != nil || next == pid {
			break
		}
		pid = next
	}
	return out
}
