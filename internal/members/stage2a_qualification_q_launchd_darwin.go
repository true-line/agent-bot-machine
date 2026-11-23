package members

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	stage2aQualificationQSandboxExec = "/usr/bin/sandbox-exec"
	stage2aQualificationQLabel       = "ai.true-line.agent-bot.stage2a-qualification-q"
	stage2aQualificationQPlist       = "/Library/LaunchDaemons/" + stage2aQualificationQLabel + ".plist"
	stage2aQualificationQTrigger     = "/private/var/db/managed-machine/q-trigger.sock"
)

func renderStage2aQualificationQLaunchd(install stage2aQualificationQInstall) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>UserName</key><string>%s</string>
<key>GroupName</key><string>%s</string>
<key>InitGroups</key><false/>
<key>inetdCompatibility</key><dict><key>Wait</key><false/></dict>
<key>ProgramArguments</key><array><string>%s</string><string>-f</string><string>%s</string><string>%s</string><string>%s</string></array>
<key>Umask</key><integer>63</integer>
<key>Sockets</key><dict><key>Trigger</key><dict>
<key>SockPathName</key><string>%s</string>
<key>SockPathOwner</key><integer>%d</integer>
<key>SockPathGroup</key><integer>%d</integer>
<key>SockPathMode</key><integer>384</integer>
</dict></dict>
</dict></plist>
`, stage2aQualificationQLabel, stage2aQualificationQAccount, stage2aQualificationQAccount,
		stage2aQualificationQSandboxExec, stage2aQualificationQProfile, SoulLauncher, stage2aQualificationQCommand, stage2aQualificationQTrigger, install.AdminUID, install.AdminGID))
}

func stage2aQualificationQLaunchdLoaded() (bool, error) {
	out, err := hqProgramOutput("/bin/launchctl", "print", "system/"+stage2aQualificationQLabel)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 113 {
			return false, nil
		}
		return false, err
	}
	var source, program string
	var args []string
	inArguments := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case inArguments && line == "}":
			inArguments = false
		case inArguments:
			args = append(args, line)
		case line == "arguments = {":
			inArguments = true
		case strings.HasPrefix(line, "path = ") && source == "":
			source = strings.TrimPrefix(line, "path = ")
		case strings.HasPrefix(line, "program = ") && program == "":
			program = strings.TrimPrefix(line, "program = ")
		}
	}
	if inArguments || source != stage2aQualificationQPlist || program != stage2aQualificationQSandboxExec ||
		!slices.Equal(args, []string{stage2aQualificationQSandboxExec, "-f", stage2aQualificationQProfile, SoulLauncher, stage2aQualificationQCommand}) {
		return false, errQualificationAdmissionUnavailable
	}
	return true, nil
}

func checkStage2aQualificationQTrigger(install stage2aQualificationQInstall) error {
	var stat unix.Stat_t
	if trustedPath(OSHost{}, filepath.Dir(stage2aQualificationQTrigger), true) != nil ||
		unix.Lstat(stage2aQualificationQTrigger, &stat) != nil ||
		stat.Mode != unix.S_IFSOCK|0600 || stat.Uid != uint32(install.AdminUID) || stat.Gid != uint32(install.AdminGID) ||
		checkDarwinACLs(pathAncestry(stage2aQualificationQTrigger)) != nil {
		return errQualificationAdmissionUnavailable
	}
	return nil
}

// takeStage2aQualificationQTrigger accepts the launchd-transferred connected
// stream, never an argument from a terminal or an untrusted Q request file.
func takeStage2aQualificationQTrigger(install stage2aQualificationQInstall) (string, error) {
	if os.Getppid() != 1 {
		return "", errQualificationAdmissionUnavailable
	}
	conn, err := net.FileConn(os.Stdin)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok || conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return "", errQualificationAdmissionUnavailable
	}
	peer, err := ObserveSoulAdmissionPeer(uc)
	if err != nil || peer.UID != install.AdminUID {
		return "", errQualificationAdmissionUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(uc, 96))
	if err != nil || len(raw) == 0 || raw[len(raw)-1] != '\n' ||
		string(raw[:len(raw)-1]) != stage2aQualificationQSessionName {
		return "", errQualificationAdmissionUnavailable
	}
	if _, err := fmt.Fprintln(uc, os.Getpid()); err != nil {
		return "", err
	}
	// The observer gets no copy of the A-only trigger on inherited stdio.
	fd, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	for _, std := range []int{0, 1, 2} {
		if err := unix.Dup2(fd, std); err != nil {
			return "", err
		}
	}
	return string(raw[:len(raw)-1]), nil
}

func triggerStage2aQualificationQ(ctx context.Context, install stage2aQualificationQInstall, selector string) (int, error) {
	if selector != stage2aQualificationQSessionName || checkStage2aQualificationQTrigger(install) != nil {
		return 0, errQualificationAdmissionUnavailable
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", stage2aQualificationQTrigger)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	stream := conn.(*net.UnixConn)
	if stream.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return 0, errQualificationAdmissionUnavailable
	}
	if _, err := fmt.Fprintln(stream, selector); err != nil {
		return 0, err
	}
	if err := stream.CloseWrite(); err != nil {
		return 0, err
	}
	raw, err := io.ReadAll(io.LimitReader(stream, 32))
	if err != nil || len(raw) < 2 || raw[len(raw)-1] != '\n' {
		return 0, errQualificationAdmissionUnavailable
	}
	return strconv.Atoi(string(raw[:len(raw)-1]))
}

func stage2aQualificationKernelGroupsMatch(p soulKernelProcessSnapshot, install stage2aQualificationQInstall) bool {
	groups := make([]int, len(p.Groups))
	for i, group := range p.Groups {
		groups[i] = int(group)
	}
	return exactStage2aQualificationQGroups(groups, install.GID, install.SupplementalGIDs)
}

func stage2aQualificationQExit(p soulKernelProcessSnapshot) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := observeSoulKernelProcess(p.PID)
		if err == nil && !sameSoulKernelProcess(p, current) ||
			err != nil && errors.Is(unix.Kill(p.PID, 0), syscall.ESRCH) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("qualification observer did not exit after local session close: %w", syscall.ETIMEDOUT)
}
