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

type launchRoleCapability struct {
	Capability        string
	LaunchDiagnostics any `json:"launch_diagnostics"`
}

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
	pid, approved := approvedLaunchPID(out, s, owner)
	if !approved {
		return false, "", refuse(RefusedPath, "loaded LaunchDaemon differs from the approved job")
	}
	return true, pid, nil
}

// The installed plist may have changed since launchd loaded it. Match the
// source, program and complete argument list from this snapshot of the job.
func approvedLaunchPID(out []byte, s HQService, owner string) (string, bool) {
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
	return pid, source == launchPlist && program == want[0] && slices.Equal(args, want)
}

func withLaunchLock(mode int, run func() error) error {
	// Different approved plans can race for the same service. Hold this
	// receipt-directory lock through bootstrap, verification and rollback.
	lock, err := os.OpenFile(filepath.Join(receiptsDir(), ".hq-launchd.lock"), os.O_CREATE|os.O_RDONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), mode); err != nil {
		return err
	}

	return run()
}

func activateLaunchDaemon(step Step) error {
	return withLaunchLock(syscall.LOCK_EX, func() error {
		if _, err := os.Lstat(filepath.Join(receiptsDir(), upgradeJournalName)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("an interrupted HQ release transition needs reconciliation")
		}
		return activateReviewedLaunch(step, nil, nil)
	})
}

// Only the launchctl submission runs inside the optional upgrade pairing guard.
// First installation has its separate reviewed plan and no prior pairing.
func submitHQBootstrap(guard func(func() error) error, submit func() error) error {
	if guard == nil {
		return submit()
	}
	return guard(submit)
}

func activateReviewedLaunch(step Step, guardBootstrap func(func() error) error, stopStarted func(*os.File, os.FileInfo) error) (err error) {
	if step.Target != launchLabel {
		return errors.New("expected Darwin LaunchDaemon step")
	}
	var rec launchRecord
	if err = json.Unmarshal([]byte(step.Content), &rec); err != nil {
		return err
	}
	expected, err := verifyDarwinRelease(rec.Service, OSHost{})
	if err != nil {
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
	main := filepath.Join(rec.Service.ReleaseDir, "hq/main.mjs")
	capability, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", DarwinHQAccount, "--", rec.Service.Node, main, "check-owner-control")
	var cap launchRoleCapability
	if err != nil || json.Unmarshal(capability, &cap) != nil || cap.Capability != expected {
		return fmt.Errorf("the approved release did not confirm %s as the HQ account", expected)
	}
	created := step.Action == ActionCreate
	if created && loaded {
		return errors.New("refusing existing loaded job during first install")
	}
	dir, dirErr := prepareLaunchDirectory(rec.RuntimeDir, expected, created)
	if dir != nil {
		defer func() {
			defer dir.Close()
			if err != nil {
				err = errors.Join(err, rollbackLaunchDirectory(dir, rec.Service, step.Owner))
			}
		}()
	}
	if dirErr != nil {
		return dirErr
	}
	socket := socketForCapability(expected)
	var socketParent *os.File
	var published os.FileInfo
	if !loaded {
		socketParent, err = os.OpenFile(filepath.Dir(socket), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer socketParent.Close()
		if _, err := os.Lstat(socket); err == nil || !errors.Is(err, os.ErrNotExist) {
			return refuse(RefusedPath, "owner control socket path already occupied or inaccessible")
		}
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
		if started && stopStarted != nil {
			// An upgrade must durably identify its newly published endpoint before
			// bootout so a later apply can finish the same guarded cleanup.
			err = errors.Join(err, stopStarted(socketParent, published))
			return
		}
		if started {
			ours, pid, inspectErr := loadedLaunchDaemon(rec.Service, step.Owner)
			if inspectErr != nil || !ours {
				err = errors.Join(err, errors.New("cannot verify the approved job before rollback"), inspectErr)
				return
			}
			if stopErr := runProgram(launchctl, "bootout", "system/"+launchLabel); stopErr != nil {
				err = errors.Join(err, stopErr)
				return
			}
			loaded, _, inspectErr := loadedLaunchDaemon(rec.Service, step.Owner)
			if inspectErr != nil || loaded {
				err = errors.Join(err, errors.New("cannot confirm the HQ job was unloaded"), inspectErr)
				return
			}
			if published != nil {
				err = errors.Join(err, removeStoppedLaunchSocket(socket, socketParent, published, pid))
			}
		}
		if created {
			if have, readErr := os.ReadFile(launchPlist); readErr == nil && string(have) == rec.Plist {
				err = errors.Join(err, os.Remove(launchPlist))
			}
		}
	}()
	if !loaded {
		if err = submitHQBootstrap(guardBootstrap, func() error { return runProgram(launchctl, "bootstrap", "system", launchPlist) }); err != nil {
			return err
		}
		started = true
		published, err = waitForLaunchSocket(socket, 0, 3*time.Second)
		if err != nil {
			return inspectFailedLaunch(err, rec.Service, step.Owner, cap, started)
		}
	}
	out, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", step.Owner, "--", rec.Service.Node, main, "status", "--owner-control", "--json")
	if err != nil {
		return inspectFailedLaunch(ownerStatusFailure(err), rec.Service, step.Owner, cap, started)
	}
	if !confirmsServiceOwner(out, step.Owner, u.Uid, DarwinHQAccount, socket, "getpeereid") {
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
	return verifyHQProcessUID(pid)
}

func verifyHQProcessUID(pid string) error {
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
func waitForLaunchSocket(path string, expectedUID uint32, limit time.Duration) (os.FileInfo, error) {
	deadline := time.Now().Add(limit)
	for {
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || info.Mode() != os.ModeSocket|0666 || stat.Uid != expectedUID {
				return nil, errors.New("owner-control socket has unexpected type, owner or mode")
			}
			return info, nil
		case !errors.Is(err, syscall.ENOENT):
			return nil, errors.New("cannot inspect the launchd owner-control endpoint")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("launchd did not publish the owner-control socket before the deadline")
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
func inspectFailedLaunch(stage error, service HQService, owner string, cap launchRoleCapability, started bool) error {
	job, err := hqProgramOutput(launchctl, "print", "system/"+launchLabel)
	if err != nil {
		return stage
	}
	return withLaunchState(stage, job, cap.exitDiagnostics(job, service, owner, started))
}

// A pre-existing job can have exit history from an older version at the same
// path. Attribute an exit only to a newly bootstrapped, verified job.
func (cap launchRoleCapability) exitDiagnostics(job []byte, service HQService, owner string, started bool) string {
	diagnostics, ok := cap.LaunchDiagnostics.(string)
	recognized := ok && (diagnostics == launchExitsV1 || diagnostics == launchExitsV2)
	if !started || (cap.Capability != launchControlV1 && cap.Capability != launchControlV2) || !recognized ||
		!strings.HasPrefix(string(job), "system/"+launchLabel+" = {\n") {
		return ""
	}
	pid, approved := approvedLaunchPID(job, service, owner)
	if approved && (pid == "" || pid == "0") {
		return diagnostics
	}
	return ""
}

const launchExitsV1 = "darwin-hq-launch-exits/v1"
const launchExitsV2 = "darwin-hq-launch-exits/v2"

var hqLaunchExitReasons = map[int]string{
	80: "native launcher rejected the role or arguments",
	81: "native launchd socket check-in failed",
	82: "launchd returned an unexpected descriptor count",
	83: "native launcher could not validate the inherited Unix stream descriptor",
	84: "native launcher could not verify the protected public socket metadata",
	85: "native launcher could not verify the launchd-bound address",
	86: "native launcher could not execute the approved Node runtime",
	87: "Node owner-control activation failed after exec",
}

func withLaunchState(stage error, job []byte, diagnostics string) error {
	exitCode := -1
	var state, runs, lastExit, reason string
	var runCount uint64
	for _, line := range strings.Split(string(job), "\n") {
		key, val, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		switch key {
		case "\tstate":
			switch val {
			case "running", "not running", "waiting", "spawn scheduled", "spawn pending", "exited", "stopped":
				state = val
			}
		case "\truns":
			if n, parseErr := strconv.ParseUint(val, 10, 32); parseErr == nil {
				runCount = n
				runs = fmt.Sprintf("launchd runs %d", n)
			}
		case "\tlast exit code":
			if val == "(never exited)" {
				lastExit = "launchd has never exited"
				exitCode = -1
				reason = ""
			}
			if n, parseErr := strconv.Atoi(val); parseErr == nil && n >= 0 && n <= 255 {
				lastExit = fmt.Sprintf("launchd last exit code %d", n)
				exitCode = n
				reason = hqLaunchExitReasons[n]
			}
		}
	}
	var details []string
	if state != "" {
		details = append(details, "launchd state "+state)
	}
	if runs != "" {
		details = append(details, runs)
	}
	if lastExit != "" {
		details = append(details, lastExit)
		if diagnostics != "" && runCount > 0 && state != "" && state != "running" {
			if diagnostics == launchExitsV2 && exitCode == 88 {
				reason = "native launchd socket check-in returned 159"
				if out, err := hqProgramOutput(launchctl, "error", "posix", "159"); err == nil && strings.TrimSpace(string(out)) == "159: Sandbox restriction" {
					reason += ": Sandbox restriction"
				}
			}
			if reason != "" {
				details = append(details, reason)
			}
		}
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
	}
	for _, socket := range []string{launchSocket, launchRuntimeSocket} {
		for _, dir := range pathAncestry(filepath.Dir(socket)) {
			if s == "owner control requires a root-managed directory at "+dir {
				return "owner-control socket parent is not root-managed"
			}
		}
		switch s {
		case "connect ENOENT " + socket, "ENOENT: no such file or directory, lstat '" + socket + "'":
			return "owner-control socket missing"
		case "connect ECONNREFUSED " + socket:
			return "owner-control connection refused"
		case "connect EACCES " + socket, "connect EPERM " + socket, "EACCES: permission denied, lstat '" + socket + "'", "EPERM: operation not permitted, lstat '" + socket + "'":
			return "owner-control socket access denied"
		}
	}
	switch {
	case strings.HasPrefix(s, "sudo: a password is required"):
		return "sudo requires authentication"
	}
	return ""
}
