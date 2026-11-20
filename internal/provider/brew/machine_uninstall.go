package brew

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

const MachineTap = "true-line/agent-bot-machine"
const hqJob = "ai.true-line.agent-bot-hq"

var ErrRemoveHQFirst = errors.New("managed HQ may still be installed or running; remove it first with sudo managed-machine members uninstall-hq PLAN_ID, then retry as the Homebrew prefix owner")

func NoManagedHQ() error {
	for _, path := range []string{"/Library/LaunchDaemons/" + hqJob + ".plist", "/Library/Application Support/" + hqJob + "/owner-control.sock", "/private/var/agent-bot-hq-control.sock"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrRemoveHQFirst
		}
	}
	// Darwin launchctl uses exactly 113 for an absent named service. Permission
	// errors and unclassified failures cannot establish absence.
	if !exitedWith(exec.Command("/bin/launchctl", "print", "system/"+hqJob).Run(), 113) {
		return ErrRemoveHQFirst
	}
	role, err := user.Lookup("_agent-bot-hq")
	if err != nil {
		var absent user.UnknownUserError
		if errors.As(err, &absent) {
			return nil
		}
		return ErrRemoveHQFirst
	}
	if _, err := strconv.ParseUint(role.Uid, 10, 32); err != nil {
		return ErrRemoveHQFirst
	}
	if !exitedWith(exec.Command("/usr/bin/pgrep", "-u", role.Uid).Run(), 1) {
		return errors.New("the dedicated HQ account still has processes or process status is unavailable; inspect the role with its administrator before removing Machine")
	}
	return nil
}

func exitedWith(err error, code int) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == code
}

func MachineCustodyPIDs(uid int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/pgrep", "-u", strconv.Itoa(uid), "-x", "managed-machine|agent-machine|agent-bot-keyd")
	out, err := cmd.Output()
	if exitedWith(err, 1) {
		return nil, nil
	}
	return out, err
}

func VerifyMachineRemovalPrefix(prefix string, env []string) error {
	brewPath := filepath.Join(prefix, "bin", "brew")
	for _, contract := range []struct{ flag, want string }{{"--prefix", prefix}, {"--cellar", filepath.Join(prefix, "Cellar")}} {
		cmd := exec.Command(brewPath, contract.flag)
		cmd.Env = append(env, Env...)
		out, err := cmd.Output()
		if err != nil || string(out) != contract.want+"\n" {
			return errors.New("Homebrew did not verify the active Machine prefix and Cellar")
		}
	}
	return nil
}

func UninstallMachineFormula(prefix string, env []string) error {
	cmd := exec.Command(filepath.Join(prefix, "bin", "brew"), "uninstall", "--formula", MachineTap+"/managed-machine")
	cmd.Env = append(append(env, Env...), "HOMEBREW_NO_AUTOREMOVE=1")
	if err := cmd.Run(); err != nil {
		return errors.New("Homebrew could not remove the Machine formula; its user services were uninstalled")
	}
	return nil
}

// ReadMachineUserJob reads current job metadata without logging its environment.
func ReadMachineUserJob(uid int, domain, label string) ([]byte, bool, error) {
	target := domain + "/" + strconv.Itoa(uid) + "/" + label
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", target).Output()
	if exitedWith(err, 113) || exitedWith(err, 112) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("cannot verify the Machine user service")
	}
	return out, true, nil
}
