//go:build !windows

package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const launchctl = "/bin/launchctl"

func preflightLaunchDaemon() error {
	for _, program := range []string{launchctl, "/usr/bin/ruby", "/usr/bin/sudo", "/usr/bin/plutil"} {
		if err := requireProgram(program); err != nil {
			return err
		}
	}
	for _, parent := range []string{filepath.Dir(launchPlist), filepath.Dir(launchSocket)} {
		if err := trustedPath(OSHost{}, parent, true); err != nil {
			return err
		}
	}
	return nil
}

// A matching installed plist may be reapplied. A loaded job pointing at a
// different plist or a socket left by a different service is never displaced.
func loadedLaunchDaemon(s HQService, owner string) (bool, string, error) {
	out, err := hqProgramOutput(launchctl, "print", "system/"+launchLabel)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 113 {
			return false, "", nil
		}
		return false, "", err
	}
	// The file on disk can have been replaced since launchd loaded it.
	// Check the active job's source and complete argv, independently of
	// whether the job currently has a process.
	var args []string
	var source, program, pid string
	inArguments := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if inArguments {
			if line == "}" {
				inArguments = false
			} else {
				args = append(args, line)
			}
			continue
		}
		switch {
		case line == "arguments = {":
			inArguments = true
		case strings.HasPrefix(line, "path = ") && source == "":
			source = strings.TrimPrefix(line, "path = ")
		case strings.HasPrefix(line, "program = "):
			program = strings.TrimPrefix(line, "program = ")
		case strings.HasPrefix(line, "pid = "):
			pid = strings.TrimPrefix(line, "pid = ")
		}
	}
	want := []string{"/usr/bin/ruby", "--disable-gems", filepath.Join(s.ReleaseDir, "helpers/darwin-owner.rb"),
		"launch", s.Node, filepath.Join(s.ReleaseDir, "hq/main.mjs"), "run", "--home", launchState, "--owner-account", owner}
	if source != launchPlist || program != want[0] || !slices.Equal(args, want) {
		return false, "", refuse(RefusedPath, "loaded LaunchDaemon differs from the approved job")
	}
	return true, pid, nil
}

func activateLaunchDaemon(step Step) (err error) {
	if step.Target != launchLabel {
		return errors.New("expected Darwin LaunchDaemon step")
	}
	var rec launchRecord
	if err = json.Unmarshal([]byte(step.Content), &rec); err != nil {
		return err
	}
	if err = verifyDarwinRelease(rec.Service, OSHost{}); err != nil {
		return err
	}
	if err = preflightLaunchDaemon(); err != nil {
		return err
	}
	u, err := user.Lookup(step.Owner)
	if err != nil {
		return err
	}
	if u.Uid != strconv.Itoa(rec.OwnerUID) {
		return errors.New("approved owner's UID changed")
	}
	loaded, _, err := loadedLaunchDaemon(rec.Service, step.Owner)
	if err != nil {
		return err
	}
	if !loaded {
		if _, err := os.Lstat(launchSocket); err == nil || !errors.Is(err, os.ErrNotExist) {
			return refuse(RefusedPath, "owner control socket path already occupied or inaccessible")
		}
	}
	main := filepath.Join(rec.Service.ReleaseDir, "hq/main.mjs")
	capability, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", DarwinHQAccount, "--", rec.Service.Node, main, "check-owner-control")
	var cap struct{ Capability string }
	if err != nil || json.Unmarshal(capability, &cap) != nil || cap.Capability != "darwin-owner-control/v1" {
		return errors.New("the approved release did not confirm darwin-owner-control/v1 as the HQ account")
	}
	created := step.Action == ActionCreate
	if created && loaded {
		return errors.New("refusing existing loaded job during first install")
	}
	if created {
		// O_EXCL prevents overwriting a job installed concurrently. The
		// completed temporary file is linked into place only after plutil.
		f, err := os.CreateTemp(filepath.Dir(launchPlist), ".hq-launchd-*.plist")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err = f.WriteString(rec.Plist); err == nil {
			err = f.Chown(0, 0)
		}
		if err == nil {
			err = f.Chmod(0644)
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err = runProgram("/usr/bin/plutil", "-lint", f.Name()); err != nil {
			return err
		}
		if err = os.Link(f.Name(), launchPlist); err != nil {
			return err
		}
	} else {
		if err = trustedPath(OSHost{}, launchPlist, false); err != nil {
			return err
		}
		if err = checkDarwinACLs([]string{launchPlist}); err != nil {
			return err
		}
		have, err := os.ReadFile(launchPlist)
		if err != nil || string(have) != rec.Plist {
			return errors.New("LaunchDaemon changed before activation")
		}
	}

	started := false
	defer func() {
		if err == nil {
			return
		}
		if started {
			if stopErr := runProgram(launchctl, "bootout", "system/"+launchLabel); stopErr != nil {
				err = errors.Join(err, stopErr)
				return
			}
		}
		if created {
			if have, readErr := os.ReadFile(launchPlist); readErr == nil && string(have) == rec.Plist {
				err = errors.Join(err, os.Remove(launchPlist))
			}
		}
	}()
	if !loaded {
		if err = runProgram(launchctl, "bootstrap", "system", launchPlist); err != nil {
			return err
		}
		started = true
		if err := waitForLaunchSocket(launchSocket, 0, 3*time.Second); err != nil {
			return inspectFailedLaunch(err)
		}
	}
	out, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", step.Owner, "--", rec.Service.Node, main, "status", "--owner-control", "--json")
	if err != nil {
		return inspectFailedLaunch(ownerStatusFailure(err))
	}
	if !confirmsServiceOwner(out, step.Owner, u.Uid, DarwinHQAccount, launchSocket, "getpeereid") {
		return errors.New("running HQ did not confirm the approved macOS owner-control endpoint")
	}
	loaded, pid, err := loadedLaunchDaemon(rec.Service, step.Owner)
	if err != nil {
		return err
	}
	n, parseErr := strconv.Atoi(pid)
	if !loaded || parseErr != nil || n <= 0 {
		return errors.New("HQ has no live launchd process")
	}
	role, err := user.Lookup(DarwinHQAccount)
	if err != nil {
		return err
	}
	uid, err := hqProgramOutput("/bin/ps", "-o", "uid=", "-p", pid)
	if err != nil || strings.TrimSpace(string(uid)) != role.Uid {
		return errors.New("launchd HQ process does not run under the dedicated service UID")
	}
	return nil
}

// Bootstrap can return before launchd publishes its public socket. Once a
// node exists, the owner client verifies its metadata and authenticates it.
func waitForLaunchSocket(path string, expectedUID uint32, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || info.Mode() != os.ModeSocket|0666 || stat.Uid != expectedUID {
				return errors.New("owner-control socket has unexpected type, owner or mode")
			}
			return nil
		case !errors.Is(err, syscall.ENOENT):
			return errors.New("cannot inspect the launchd owner-control endpoint")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("launchd did not publish the owner-control socket before the deadline")
		}
		time.Sleep(min(25*time.Millisecond, remaining))
	}
}

// A failed client may print a complete response or stack trace to stderr.
func ownerStatusFailure(err error) error {
	base := "query launched HQ as approved owner: status command did not complete"
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			base = fmt.Sprintf("query launched HQ as approved owner: sudo exit status %d", code)
		}
		if reason := ownerStatusStderr(exit.Stderr); reason != "" {
			base += " (" + reason + ")"
		}
	}
	return errors.New(base)
}

// Only sanitized errors enter this function. Capture launchd's state before
// deferred rollback unloads the job, including when no public socket appeared.
func inspectFailedLaunch(stage error) error {
	job, _ := hqProgramOutput(launchctl, "print", "system/"+launchLabel)
	return withLaunchState(stage, job)
}

func withLaunchState(stage error, job []byte) error {
	var state, runs, lastExit string
	for _, line := range strings.Split(string(job), "\n") {
		key, val, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		switch key {
		case "\tstate":
			switch val {
			case "running", "not running", "waiting", "spawn scheduled", "spawn pending", "exited", "stopped":
				state = "launchd state " + val
			}
		case "\truns":
			if n, parseErr := strconv.ParseUint(val, 10, 32); parseErr == nil {
				runs = fmt.Sprintf("launchd runs %d", n)
			}
		case "\tlast exit code":
			if val == "(never exited)" {
				lastExit = "launchd has never exited"
			}
			if n, parseErr := strconv.Atoi(val); parseErr == nil && n >= 0 && n <= 255 {
				lastExit = fmt.Sprintf("launchd last exit code %d", n)
			}
		}
	}
	var details []string
	if state != "" {
		details = append(details, state)
	}
	if runs != "" {
		details = append(details, runs)
	}
	if lastExit != "" {
		details = append(details, lastExit)
	}
	if len(details) == 0 {
		return stage
	}
	return fmt.Errorf("%w (%s)", stage, strings.Join(details, ", "))
}

func ownerStatusStderr(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	var reply struct {
		Transport string `json:"transport_error"`
		Code      string `json:"code"`
	}
	if json.Unmarshal(raw, &reply) == nil {
		if reply.Transport != "" {
			s = reply.Transport
		} else if reply.Code != "" {
			return "HQ returned a status refusal"
		}
	}
	switch {
	case s == "connection closed", strings.HasPrefix(s, "read ECONNRESET"):
		return "owner-control connection closed"
	case s == "expected an owner control socket owned by uid 0 at mode 666":
		return "owner-control socket has unexpected type, owner or mode"
	case s == "owner control requires a root-managed directory at /private" || s == "owner control requires a root-managed directory at /private/var":
		return "owner-control socket parent is not root-managed"
	case s == "connect ENOENT "+launchSocket, s == "ENOENT: no such file or directory, lstat '"+launchSocket+"'":
		return "owner-control socket missing"
	case s == "connect ECONNREFUSED "+launchSocket:
		return "owner-control connection refused"
	case s == "connect EACCES "+launchSocket, s == "connect EPERM "+launchSocket, s == "EACCES: permission denied, lstat '"+launchSocket+"'", s == "EPERM: operation not permitted, lstat '"+launchSocket+"'":
		return "owner-control socket access denied"
	case strings.HasPrefix(s, "sudo: a password is required"):
		return "sudo requires authentication"
	}
	return ""
}
