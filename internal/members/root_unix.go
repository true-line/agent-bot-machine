//go:build !windows

package members

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Programs an apply starts. They are named by absolute path and run with a
// fixed environment, so nothing in the caller's PATH or environment is used.
const (
	useraddPath         = "/usr/sbin/useradd"
	visudoPath          = "/usr/sbin/visudo"
	iptablesPath        = "/usr/sbin/iptables"
	ip6tablesPath       = "/usr/sbin/ip6tables"
	iptablesRestorePath = "/usr/sbin/iptables-restore"
	ip6RestorePath      = "/usr/sbin/ip6tables-restore"
	systemctlPath       = "/usr/bin/systemctl"
	shPath              = "/bin/sh"
	shadowPath          = "/etc/shadow"
)

var rootEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// OSRoot changes the running host. Every method needs root.
type OSRoot struct {
	upgradeApproval  Approval
	checkUpgradePair upgradePairGuard
}

func runProgram(name string, args ...string) error {
	return runProgramInput("", name, args...)
}

func runProgramInput(input, name string, args ...string) error {
	// Account creation can wait on the host account database. Let a single
	// invocation finish instead of replaying a partial privileged operation.
	limit := time.Minute
	if name == useraddPath {
		limit = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = rootEnv
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s did not finish within %s", filepath.Base(name), limit)
		}
		return fmt.Errorf("%s: %v: %s", filepath.Base(name), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func requireProgram(name string) error {
	fi, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("required program %s is unavailable: %w", name, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
		return fmt.Errorf("required program %s is not an executable regular file", name)
	}
	return nil
}

// PasswordField implements Root.
func (OSRoot) PasswordField(account string) (string, bool, error) {
	if runtime.GOOS == "darwin" {
		return darwinPasswordField(account)
	}
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

// PreflightEgress implements Root. It proves the fixed helper parses and
// both firewall families accept the owner-match rule without changing them.
func (OSRoot) PreflightEgress(script, restore string) error {
	if runtime.GOOS == "darwin" {
		return errors.New("member egress isolation is Linux only")
	}
	for _, name := range []string{shPath, iptablesPath, ip6tablesPath, iptablesRestorePath, ip6RestorePath, systemctlPath} {
		if err := requireProgram(name); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp("", "managed-machine-egress-*.sh")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := runProgram(shPath, "-n", tmp); err != nil {
		return fmt.Errorf("the member egress helper is invalid: %w", err)
	}
	for _, name := range []string{iptablesRestorePath, ip6RestorePath} {
		if err := runProgramInput(restore, name, "--test"); err != nil {
			return fmt.Errorf("the member egress policy is unsupported: %w", err)
		}
	}
	return nil
}

// CreateAccount implements Root. useradd leaves a new account locked.
func (OSRoot) CreateAccount(name string) error {
	if runtime.GOOS == "darwin" {
		return darwinCreateRoleAccount(name, darwinHarnessHome(name), darwinHarnessRoleName, 0)
	}
	home := filepath.Join(HomeBase, name)
	if err := runProgram(useraddPath, "--create-home", "--home-dir", home, "--user-group", "--shell", NoLoginShell, name); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
}

// CreateHQAccount implements Root. A system account gets a uid below the
// range of people's accounts and no password aging.
func (OSRoot) CreateHQAccount(name string) error {
	if runtime.GOOS == "darwin" {
		return darwinCreateRoleAccount(name, HQHome(PlatformDarwin, name), darwinHQRoleName, 0)
	}
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
	if runtime.GOOS == "darwin" {
		return createDarwinBrokerDirectory(p, owner, group, mode)
	}
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

func disableLaunchRule() error {
	have, ok, err := (OSRoot{}).ReadSudoers()
	if err != nil || !ok {
		return err
	}
	if !strings.HasPrefix(have, header) {
		return fmt.Errorf("%s changed and was not removed", SudoersPath)
	}
	return os.Remove(SudoersPath)
}

// ActivateEgress implements Root. Activation is fail closed for upgrades: if
// systemd cannot establish the boundary, an older managed launch rule is
// removed before the error is returned.
func (OSRoot) ActivateEgress(unit string) error {
	if runtime.GOOS == "darwin" || unit != EgressUnitName {
		return errors.New("member egress isolation is Linux only")
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", unit}, {"restart", unit}, {"is-active", "--quiet", unit}} {
		if err := runProgram(systemctlPath, args...); err != nil {
			if disableErr := disableLaunchRule(); disableErr != nil {
				return fmt.Errorf("%w; the managed launch rule could not be disabled: %v", err, disableErr)
			}
			return fmt.Errorf("%w; the managed launch rule was disabled", err)
		}
	}
	return nil
}

// Check the manager's effective units, including runtime overrides that a
// filesystem check of /etc/systemd/system alone cannot see.
func checkHQUnits() error {
	for _, name := range []string{hqServiceName, hqSocketName} {
		out, err := hqProgramOutput(systemctlPath, "show", "--property=FragmentPath,DropInPaths", name)
		if err != nil {
			return err
		}
		for _, property := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			k, v, _ := strings.Cut(property, "=")
			if k == "DropInPaths" && v != "" || k == "FragmentPath" && v != "" && v != filepath.Join(hqSystemDir, name) {
				return refuse(RefusedPath, "%s has an external fragment or drop-in; reconcile it before enabling HQ", name)
			}
		}
	}
	return nil
}

func hqProgramOutput(program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	// The service and approved owner can have different access to the
	// invoking terminal's directory. All service probe paths are absolute.
	cmd.Dir = "/"
	cmd.Env = rootEnv
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(program), err)
	}
	return out, nil
}

func (OSRoot) PreflightHQ() error {
	if runtime.GOOS == "darwin" {
		return preflightLaunchDaemon()
	}
	if runtime.GOOS != "linux" {
		return errors.New("HQ service is Linux only")
	}
	for _, p := range []string{"/usr/sbin/runuser", "/usr/bin/python3", systemctlPath} {
		if err := requireProgram(p); err != nil {
			return err
		}
	}
	return checkHQUnits()
}

// ActivateHQ never runs release code as root. The compatibility check uses
// the HQ account; the status round trip uses the approved owner's UID.
func (r OSRoot) ActivateHQ(step Step) error {
	if step.Action == upgradeAction {
		return activateUpgrade(step, r.upgradeApproval, r.checkUpgradePair)
	}
	if runtime.GOOS == "darwin" {
		return activateLaunchDaemon(step)
	}
	s, err := decodeHQService([]byte(step.Content))
	if err != nil {
		return err
	}
	if err := s.verify(OSHost{}); err != nil {
		return err
	}
	main := filepath.Join(s.ReleaseDir, "hq/main.mjs")
	verified, err := hqProgramOutput("/usr/sbin/runuser", "-u", DefaultHQAccount, "--", s.Node, main, "check-owner-control")
	var cap struct{ Capability string }
	if err != nil || json.Unmarshal(verified, &cap) != nil || cap.Capability != "linux-owner-control/v1" {
		return errors.New("the verified HQ release did not confirm linux-owner-control/v1 under the service account")
	}
	if err := runProgram(systemctlPath, "daemon-reload"); err != nil {
		return err
	}
	if err := checkHQUnits(); err != nil {
		return err
	}
	socketActive := runProgram(systemctlPath, "is-active", "--quiet", hqSocketName) == nil
	serviceActive := runProgram(systemctlPath, "is-active", "--quiet", hqServiceName) == nil
	if serviceActive && !socketActive {
		return errors.New("the installed HQ service is active without its owner socket; reconcile it before applying")
	}
	owner, err := user.Lookup(step.Owner)
	if err != nil {
		return err
	}
	wasEnabled := runProgram(systemctlPath, "is-enabled", "--quiet", hqSocketName) == nil
	err = runProgram(systemctlPath, "enable", "--now", hqSocketName)
	if err == nil {
		// The round trip activates the socket without restarting an existing HQ.
		var out []byte
		out, err = hqProgramOutput("/usr/sbin/runuser", "-u", step.Owner, "--", s.Node, main, "status", "--owner-control", "--json")
		if err == nil && confirmsHQOwner(out, step.Owner, owner.Uid) {
			return nil
		}
		err = fmt.Errorf("owner-control status as %s did not confirm %s", step.Owner, DefaultHQAccount)
	}
	if !socketActive {
		err = errors.Join(err, runProgram(systemctlPath, "stop", hqSocketName))
	}
	if !serviceActive {
		err = errors.Join(err, runProgram(systemctlPath, "stop", hqServiceName))
	}
	if !wasEnabled {
		err = errors.Join(err, runProgram(systemctlPath, "disable", hqSocketName))
	}
	return err
}

// Claim implements Root.
func (r OSRoot) Claim(planID string, receipt []byte) (bool, error) {
	if r.upgradeApproval.Purpose == UpgradePurpose {
		// An eligible upgrade always has an existing protected receipt directory.
		err := claimUpgradeReceipt(planID, receipt)
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return err == nil, err
	}
	if err := os.MkdirAll(receiptsDir(), 0o755); err != nil {
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
	if runtime.GOOS == "darwin" {
		return darwinAncestorEnvs()
	}
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
