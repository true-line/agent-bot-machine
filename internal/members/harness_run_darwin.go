package members

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func harnessKernelRole(a HarnessAdapter) bool {
	if os.Getuid() != a.UID || os.Geteuid() != a.UID || os.Getgid() != a.UID || os.Getegid() != a.UID {
		return false
	}
	role, err := user.Lookup(a.Account)
	if err != nil || role.Uid != strconv.Itoa(a.UID) || role.Gid != role.Uid {
		return false
	}
	ids, err := role.GroupIds()
	if err != nil {
		return false
	}
	permitted := map[string]bool{role.Gid: true}
	for _, id := range ids {
		permitted[id] = true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, gid := range groups {
		if !permitted[strconv.Itoa(gid)] {
			return false
		}
	}
	return true
}

// The only launch-time inputs are the admitted identity and bootstrap token.
// Both the binary and complete argv come from the installation record.
func harnessAdapterCommand(grant installedHarness, req harnessRunInput, uid int) (*exec.Cmd, HarnessAdapter, error) {
	if grant.Policy.Action != "install" || grant.Digest != req.PlanDigest || uid == grant.Policy.HQUID {
		return nil, HarnessAdapter{}, errLaunchInput
	}
	for _, a := range grant.Policy.Adapters {
		if a.ID != req.AdapterID {
			continue
		}
		if a.UID != uid {
			return nil, HarnessAdapter{}, errLaunchInput
		}
		broker, member, err := harnessRunSockets(a.Account, req.LaunchID)
		if err != nil {
			return nil, HarnessAdapter{}, err
		}
		args := []string{"-D", "BROKER_SOCKET=" + broker, "-D", "MEMBER_SOCKET=" + member, "-f", HarnessSandbox, a.Executable}
		args = append(args, a.Args...)
		cmd := exec.Command("/usr/bin/sandbox-exec", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "USER=" + a.Account, "LOGNAME=" + a.Account,
			"AGENT_BOT_SOULS_MEMBER_ID=" + req.MemberID, "AGENT_BOT_SOULS_ROLE=" + req.Role,
			"AGENT_BOT_SOULS_MEMBER_TOKEN=" + req.MemberToken, "AGENT_BOT_SOULS_SOCKET=" + member, "AGENT_BOT_SOULS_BROKER=" + broker}
		return cmd, a, nil
	}
	return nil, HarnessAdapter{}, errLaunchInput
}

func verifyHarnessLaunchFiles(grant installedHarness, adapter HarnessAdapter) error {
	if err := qualifiedHarnessAdapter(adapter); err != nil {
		return err
	}
	if err := verifyHarnessRoles(grant.Policy); err != nil {
		return err
	}
	if !harnessKernelRole(adapter) {
		return errors.New("unexpected harness process credentials")
	}
	me, err := os.Executable()
	if err != nil || filepath.Clean(me) != HarnessLauncher {
		return errors.New("unexpected harness launcher path")
	}
	if err := verifyHarnessExecutable(HarnessLauncher, grant.Policy.Launcher.SHA256); err != nil {
		return err
	}
	if err := verifyHarnessExecutable(adapter.Executable, adapter.SHA256); err != nil {
		return err
	}
	if grant.Policy.Sandbox.SHA256 != harnessSHA(harnessProfile) {
		return errors.New("unexpected harness sandbox profile")
	}
	if err := trustedPath(OSHost{}, HarnessSandbox, false); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(HarnessSandbox)); err != nil {
		return err
	}
	f, err := openPinnedFile(HarnessSandbox, grant.Policy.Sandbox.SHA256)
	if err != nil {
		return err
	}
	return f.Close()
}

// RunHarness is reachable via one fixed sudoers command under the target UID.
// It must execute in its own process because it sets its umask and directory.
func RunHarness() int {
	uid := os.Geteuid()
	if uid < 300 || uid > 399 {
		return harnessRefused
	}
	request, acp, err := readHarnessRunInput(os.Stdin)
	if err != nil {
		return harnessRefused
	}
	file, grant, err := lockInstalledHarness(false)
	if err != nil {
		return harnessRefused
	}
	defer file.Close()
	if os.Getenv("SUDO_UID") != strconv.Itoa(grant.Policy.HQUID) || os.Getenv("SUDO_USER") != DarwinHQAccount {
		return harnessRefused
	}
	cmd, adapter, err := harnessAdapterCommand(grant, request, uid)
	if err != nil || verifyHarnessLaunchFiles(grant, adapter) != nil {
		return harnessRefused
	}
	syscall.Umask(0077)
	work, err := prepareHarnessWorkdir(cmd, darwinHarnessHome(adapter.Account), uid, request)
	if err != nil {
		return harnessRefused
	}
	defer work.Close()
	if err := work.Chdir(); err != nil {
		return harnessRefused
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer cancel()
	return superviseHarness(ctx, cmd, acp, os.Stdin, os.Stdout, &harnessReporter{output: os.Stderr}, 5*time.Second)
}
