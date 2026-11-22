package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func absentPackageServices() packageObservers {
	return packageObservers{grantAbsent: func() error { return nil }, job: func(int, string, string) ([]byte, bool, error) { return nil, false, nil }, processes: func(int) ([]byte, error) { return nil, nil }}
}

func TestHomebrewPackageGrantObserverKeepsNonrootCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("package owner runs without root")
	}
	// The real package-uninstall observer must remain callable by the Homebrew
	// prefix owner. A separate root-only check protects HQ service uninstall.
	if err := checkPackageLaunchGrant(); err != nil && strings.Contains(err.Error(), "root required") {
		t.Fatalf("package owner lost its grant observer: %v", err)
	}
}

func TestHomebrewPackageUninstall(t *testing.T) {
	for _, filename := range []string{"keyd-original.plist", "keyd-background.plist"} {
		t.Run(filename, func(t *testing.T) {
			template, err := os.ReadFile(filepath.Join("testdata", filename))
			if err != nil {
				t.Fatal(err)
			}
			testHomebrewPackageUninstall(t, string(template))
		})
	}
}

func testHomebrewPackageUninstall(t *testing.T, keydTemplate string) {
	base, err := os.MkdirTemp("/private/tmp", "abu.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	home := filepath.Join(base, "home")
	prefix := filepath.Join(base, "prefix")
	keg := filepath.Join(prefix, "Cellar", "managed-machine", "1.0.0")
	for _, p := range []string{filepath.Join(keg, "bin"), filepath.Join(prefix, "bin"), filepath.Join(prefix, "opt"), filepath.Join(home, "Library", "LaunchAgents")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	put := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keg, filepath.Join(prefix, "opt", "managed-machine")); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(keg, "bin", "managed-machine")
	put(core, "fixture", 0700)
	put(filepath.Join(keg, "bin", "agent-bot-keyd"), "fixture", 0700)
	if err := os.Symlink("managed-machine", filepath.Join(keg, "bin", "agent-machine")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"managed-machine", "agent-machine", "agent-bot-keyd"} {
		if err := os.Symlink(filepath.Join(keg, "bin", name), filepath.Join(prefix, "bin", name)); err != nil {
			t.Fatal(err)
		}
	}
	receipt := filepath.Join(keg, "INSTALL_RECEIPT.json")
	put(receipt, `{"source":{"tap":"other/tap"}}`, 0600)
	if _, err := activeMachinePackage(core, []string{prefix}); err == nil {
		t.Fatal("accepted another tap")
	}
	put(receipt, `{"source":{"tap":"true-line/agent-bot-machine"}}`, 0600)
	older := filepath.Join(filepath.Dir(keg), "0.9.0")
	if err := os.Mkdir(older, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := activeMachinePackage(core, []string{prefix}); err == nil {
		t.Fatal("accepted multiple installed kegs")
	}
	if err := os.Remove(older); err != nil {
		t.Fatal(err)
	}
	manual := filepath.Join(base, "managed-machine")
	put(manual, "fixture", 0700)
	if _, err := activeMachinePackage(manual, []string{prefix}); err == nil {
		t.Fatal("treated a staged copy as the installed executable")
	}
	if _, err := activeMachinePackage(core, []string{prefix, prefix}); err == nil {
		t.Fatal("accepted conflicting installations")
	}
	if _, err := activeMachinePackage(core, []string{filepath.Join(base, "not-installed")}); err == nil {
		t.Fatal("removed an unreceipted manual installation")
	}
	for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
		text := darwinAgent(home, core)
		if label == darwinKeydServiceLabel {
			text = strings.NewReplacer("{{PROGRAM}}", filepath.Join(keg, "bin", "agent-bot-keyd"),
				"{{STATE}}", filepath.Join(home, ".local", "state", "agent-bot")).Replace(keydTemplate)
		}
		put(filepath.Join(home, "Library", "LaunchAgents", label+".plist"), text, 0600)
	}
	put(filepath.Join(prefix, "bin", "brew"), `#!/bin/sh
set -eu
dir=$(cd "$(dirname "$0")/.." && pwd -P)
case "$1" in
--prefix) echo "$dir";;
--cellar) echo "$dir/Cellar";;
uninstall) test "$HOMEBREW_NO_AUTOREMOVE" = 1 || exit 1
 test "$#" = 3 && test "$2" = --formula && test "$3" = true-line/agent-bot-machine/managed-machine || exit 1
 test ! -e "$dir/refuse" || exit 1
 rm "$dir/bin/managed-machine" "$dir/bin/agent-machine" "$dir/bin/agent-bot-keyd" "$dir/opt/managed-machine"
 rm -r "$dir/Cellar/managed-machine";;
*) exit 1;;
esac
`, 0700)
	for path, mode := range map[string]os.FileMode{home: 0750, filepath.Join(home, "Library"): 0755} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	caller := Caller{UID: os.Getuid(), Username: u.Username, Home: home, RegisteredHome: home, PrefixOwner: u.Username, DarwinAdmin: true}
	stops := 0
	deps := Deps{LockLifecycle: testMacPackageLock, GOOS: "darwin", Caller: func() (Caller, error) { return caller, nil }, Root: func() (string, error) { return home, nil }, Deactivate: func(string) error { stops++; return nil }}
	t.Setenv(channelEnv, filepath.Join(prefix, "var", "agent-machine"))
	observe := absentPackageServices()
	runRemove := func(check func() error) error {
		observe.noSystemHQ = check
		return removeMacPackage(deps, core, []string{prefix}, observe)
	}
	grantPresent := errors.New("grant is still installed")
	observe.grantAbsent = func() error { return grantPresent }
	if err := runRemove(func() error { return nil }); !errors.Is(err, grantPresent) || stops != 0 {
		t.Fatal("package removal must preserve both services for grant retirement", err)
	}
	for _, path := range []string{core, receipt, filepath.Join(home, "Library", "LaunchAgents", darwinServiceLabel+".plist")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatal("package removal changed files while a launch grant remains", err)
		}
	}
	observe = absentPackageServices()
	if err := runRemove(func() error { return removeHQFirst }); !errors.Is(err, removeHQFirst) || stops != 0 {
		t.Fatalf("HQ gate: %v; stops=%d", err, stops)
	}
	lock, err := testMacPackageLock(home, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := runRemove(func() error { return nil }); err == nil || stops != 0 {
		t.Fatal("concurrent package change continued")
	}
	lock.Close()
	channel := filepath.Join(prefix, "var", "agent-machine")
	private := filepath.Join(home, ".local", "state", "agent-bot", "keyd")
	for _, dir := range []string{channel, private} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{filepath.Join(channel, "daemon.pub"), filepath.Join(private, "audit.jsonl")} {
		put(p, "retain", 0600)
	}
	for _, p := range []string{filepath.Join(channel, "daemon.sock"), filepath.Join(private, "keyd.sock"), filepath.Join(private, "owner.sock")} {
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		l.Close()
	}
	// First both stops fail, then only Machine refuses. Neither attempt may
	// remove service files or the keg. The remaining steps retry from there.
	machineUnit := filepath.Join(home, "Library", "LaunchAgents", darwinServiceLabel+".plist")
	keydUnit := filepath.Join(home, "Library", "LaunchAgents", darwinKeydServiceLabel+".plist")
	preserved := []string{core, receipt, machineUnit, keydUnit, filepath.Join(channel, "daemon.sock"),
		filepath.Join(private, "keyd.sock"), filepath.Join(private, "owner.sock")}
	t.Run("verified independent Identity owner present", func(t *testing.T) {
		owned, err := os.ReadFile(keydUnit)
		if err != nil {
			t.Fatal(err)
		}
		state := filepath.Dir(private)
		program := filepath.Join(t.TempDir(), "agent-bot-keyd")
		put(program, "independent executable", 0700)
		independent := strings.ReplaceAll(keydAgent(state, program), "\t", "  ")
		put(keydUnit, independent, 0600)
		record := filepath.Join(private, "keyd.json")
		binding := fmt.Sprintf("{\"bin\":%q,\"label\":%q}\n", program, darwinKeydServiceLabel)
		put(record, binding, 0600)
		t.Cleanup(func() {
			put(keydUnit, string(owned), 0600)
			observe = absentPackageServices()
			if err := os.Remove(record); err != nil {
				t.Error(err)
			}
		})
		observe.job = func(_ int, domain, label string) ([]byte, bool, error) {
			if domain == "gui" && label == darwinKeydServiceLabel {
				return []byte("\tpath = " + keydUnit + "\n\tprogram = " + program + "\n\targuments = {\n\t\t" + program + "\n\t\tserve\n\t\t--state-dir\n\t\t" + state + "\n\t}\n"), true, nil
			}
			return nil, false, nil
		}
		if !independentKeydRecorded(state, program, caller.UID) {
			t.Fatal("invalid independent registration")
		}
		if err := runRemove(func() error { return nil }); err == nil || !strings.Contains(err.Error(), "preserving a customized or unrelated Machine LaunchAgent") || stops != 0 {
			t.Fatalf("unexpected result: %v, stops %d", err, stops)
		}
		for _, path := range preserved {
			if _, err := os.Lstat(path); err != nil {
				t.Fatal(err)
			}
		}
		for path, want := range map[string]string{program: "independent executable", keydUnit: independent, record: binding} {
			b, err := os.ReadFile(path)
			if err != nil || string(b) != want {
				t.Fatal("changed independent resource", path, err)
			}
		}
	})
	machineFailure := errors.New("Machine bootout failed")
	keydFailure := errors.New("keyd bootout failed")
	normalStop := deps.Deactivate
	for _, keydResult := range []error{keydFailure, nil} {
		var attempted []string
		deps.Deactivate = func(path string) error {
			attempted = append(attempted, path)
			if path == machineUnit {
				return machineFailure
			}
			return keydResult
		}
		err := runRemove(func() error { return nil })
		if len(attempted) != 2 || attempted[0] != machineUnit || attempted[1] != keydUnit {
			t.Fatalf("expected both verified service stops in order, observed %v", attempted)
		}
		if !errors.Is(err, machineFailure) || errors.Is(err, keydFailure) != (keydResult != nil) {
			t.Fatalf("missing or unexpected stop failure: %v", err)
		}
		for _, path := range preserved {
			if _, e := os.Lstat(path); e != nil {
				t.Fatalf("did not preserve %s after a failed stop: %v", filepath.Base(path), e)
			}
		}
	}
	deactivated := false
	deps.Deactivate = func(string) error { deactivated = true; return nil }
	observe.job = func(int, string, string) ([]byte, bool, error) {
		if deactivated {
			return nil, false, errors.New("fixture launchd observation failed")
		}
		return nil, false, nil
	}
	if err := runRemove(func() error { return nil }); err == nil || !strings.Contains(err.Error(), "fixture launchd") {
		t.Fatalf("post-stop observation failure: %v", err)
	}
	for _, path := range preserved {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("lost %v on failed post-stop observation", filepath.Base(path))
		}
	}
	observe = absentPackageServices()
	deps.Deactivate = normalStop
	put(filepath.Join(prefix, "refuse"), "", 0600)
	if err := runRemove(func() error { return nil }); err == nil || !strings.Contains(err.Error(), "Homebrew could not remove") {
		t.Fatalf("expected safe Homebrew refusal, got %v", err)
	}
	if _, err := os.Stat(core); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(prefix, "refuse")); err != nil {
		t.Fatal(err)
	}
	if err := runRemove(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(channel, "daemon.sock"), filepath.Join(private, "keyd.sock"),
		filepath.Join(private, "owner.sock"), filepath.Join(home, "Library", ".managed-machine-lifecycle.lock"), core} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("left %s: %v", filepath.Base(p), err)
		}
	}
	for _, p := range []string{filepath.Join(channel, "daemon.pub"), filepath.Join(private, "audit.jsonl")} {
		if b, err := os.ReadFile(p); err != nil || string(b) != "retain" {
			t.Fatal("removed protected state")
		}
	}
}

func removeObservedTestSocket(path string, uid int, unlinkStopped func(int, string, int, unix.Stat_t) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeStoppedPackageSocket(packageLeaf{path: path, info: info}, uid, unlinkStopped)
}

func TestPackageStopWaitsForDeregistrationAndOriginalProcesses(t *testing.T) {
	uid := os.Getuid()
	observe := absentPackageServices()
	seen := map[string]int{}
	observe.job = func(id int, domain, label string) ([]byte, bool, error) {
		if id != uid {
			t.Fatal("wrong owner")
		}
		target := domain + "/" + label
		seen[target]++
		return nil, target == "user/"+darwinServiceLabel && seen[target] <= 2, nil
	}
	if err := observe.waitForStop(uid, nil, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
		for _, domain := range []string{"gui", "user"} {
			if seen[domain+"/"+label] < 3 {
				t.Fatal("did not confirm absence on both domains")
			}
		}
	}
	observe = absentPackageServices()
	observe.job = func(int, string, string) ([]byte, bool, error) { return nil, true, nil }
	if err := observe.waitForStop(uid, nil, 0); err == nil || !strings.Contains(err.Error(), darwinServiceLabel+" remains registered in the gui launchd domain") {
		t.Fatalf("continuing registration: %v", err)
	}
	observe = absentPackageServices()
	if err := observe.waitForStop(uid, []int{os.Getpid()}, 0); err == nil || !strings.Contains(err.Error(), "original Machine or keyd registration has not exited") {
		t.Fatalf("recorded living PID: %v", err)
	}
	observe.processes = func(int) ([]byte, error) { return []byte(fmt.Sprintf("%d\n%d\n", os.Getpid(), os.Getpid()+1)), nil }
	if err := observe.waitForStop(uid, nil, 0); err == nil || !strings.Contains(err.Error(), "another Machine or keyd process is running") {
		t.Fatalf("process without a registered job: %v", err)
	}
	observe.processes = func(int) ([]byte, error) { return nil, errors.New("unavailable") }
	if err := observe.waitForStop(uid, nil, 0); err == nil {
		t.Fatal("unknown process inventory permitted cleanup")
	}
	observe.processes = func(int) ([]byte, error) { return []byte(strconv.Itoa(os.Getpid())), nil }
	if err := observe.waitForStop(uid, nil, 0); err != nil {
		t.Fatal(err)
	}
}

func TestStoppedSocketNeedsExclusiveEvidence(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "abs.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "owner.sock")
	uid := os.Getuid()
	calls := 0
	quiescent := func(fd int, name string, uid int, original unix.Stat_t) error {
		calls++
		return unlinkQuiescentSocket(fd, name, uid, original, func(int) ([]byte, error) { return []byte(strconv.Itoa(os.Getpid())), nil })
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := removeObservedTestSocket(p, uid, quiescent); err == nil || calls != 0 {
		t.Fatal("accepted live socket")
	}
	listener.Close()
	other := func(fd int, name string, uid int, original unix.Stat_t) error {
		return unlinkQuiescentSocket(fd, name, uid, original, func(int) ([]byte, error) { return []byte(fmt.Sprint(os.Getpid() + 1)), nil })
	}
	if err := removeObservedTestSocket(p, uid, other); err == nil {
		t.Fatal("older macOS removed endpoint with another process")
	}
	if err := removeObservedTestSocket(p, uid, quiescent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeObservedTestSocket(p, uid, quiescent); err == nil {
		t.Fatal("accepted foreign file")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign", p); err != nil {
		t.Fatal(err)
	}
	if err := removeObservedTestSocket(p, uid, quiescent); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestVerifyPackageServicesRequiresKnownFilesAndLiveJobs(t *testing.T) {
	home := t.TempDir()
	uid := os.Getuid()
	agents := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agents, 0700); err != nil {
		t.Fatal(err)
	}
	caller := Caller{UID: uid, RegisteredHome: home}
	prefix := filepath.Join(t.TempDir(), "brew")
	machine := filepath.Join(prefix, "Cellar", "managed-machine", "0.12.1", "bin", "managed-machine")
	keyd := filepath.Join(prefix, "opt", "managed-machine", "bin", "agent-bot-keyd")
	state := filepath.Join(home, ".local", "state", "agent-bot")
	for _, tc := range []struct {
		name, label, program string
		args                 []string
	}{
		{"legacy-Machine", darwinServiceLabel, machine, []string{"daemon", "run"}},
		{"keyd", darwinKeydServiceLabel, keyd, []string{"serve", "--state-dir", state}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(agents, tc.label+".plist")
			// launchd may still have the registered job after its plist was removed.
			job := func(bin string, args []string) []byte {
				return []byte("\tpath = " + file + "\n\tprogram = " + bin + "\n\targuments = {\n\t\t" + bin + "\n\t\t" + strings.Join(args, "\n\t\t") + "\n\t}\n\tpid = 12345\n")
			}
			args := tc.args
			program := tc.program
			readJob := func(id int, domain, label string) ([]byte, bool, error) {
				if id != uid {
					t.Fatal("wrong UID")
				}
				if domain == "user" && label == tc.label {
					return job(program, args), true, nil
				}
				return nil, false, nil
			}
			if tc.label == darwinKeydServiceLabel {
				if _, err := inspectPackageServices(prefix, caller, readJob); err == nil {
					t.Fatal("shared label and argv alone identified the keyd installer")
				}
				if err := os.WriteFile(file, []byte(keydAgent(state, program)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := inspectPackageServices(prefix, caller, readJob)
			if err != nil || len(snapshot.pids) != 1 || snapshot.pids[0] != 12345 {
				t.Fatalf("expected verified original PID: %v", err)
			}
			program = "/tmp/unrelated-program"
			if _, err := inspectPackageServices(prefix, caller, readJob); err == nil {
				t.Fatal("accepted unrelated loaded job")
			}
			program = tc.program
			args = []string{"other-operation"}
			if _, err := inspectPackageServices(prefix, caller, readJob); err == nil {
				t.Fatal("accepted unrelated loaded arguments")
			}
			args = tc.args
			body := darwinAgent(home, program)
			if tc.label == darwinKeydServiceLabel {
				body = keydAgent(state, program)
			}
			if err := os.WriteFile(file, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectPackageServices(prefix, caller, readJob); err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(body, "</dict>", "<key>Other</key><true/></dict>", 1)
			if err := os.WriteFile(file, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectPackageServices(prefix, caller, readJob); err == nil {
				t.Fatal("accepted a lookalike service file")
			}
			got, err := os.ReadFile(file)
			if err != nil || string(got) != changed {
				t.Fatal("changed unrelated file")
			}
			os.Remove(file)
		})
	}
}

// Exercise the ordinary pre-guarded-unlink fallback on a socket with an open
// descriptor but no listener, using only this process and a temporary directory.
func TestDarwin15RetainsBoundNonListeningPackageSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "abb.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "owner.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path + ".original"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".original", path); err != nil {
		t.Fatal(err)
	}
	legacy := func(parent int, path string, uid int, original unix.Stat_t) error {
		return unlinkQuiescentSocket(parent, path, uid, original, func(int) ([]byte, error) { return nil, nil })
	}
	if err := removeObservedTestSocket(path, os.Getuid(), legacy); err == nil {
		t.Fatal("removed bound socket")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
}

func TestPackageStopPreservesChangesDuringUnload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		socket  bool
		initial bool
		replace bool
	}{
		{"new-plist", false, false, false},
		{"replaced-plist-same-bytes", false, true, true},
		{"rewritten-plist", false, true, false},
		{"new-socket", true, false, false},
		{"replaced-socket", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := os.MkdirTemp("/private/tmp", "abp.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(home) })
			prefix := filepath.Join(home, "p")
			path := filepath.Join(home, "Library", "LaunchAgents", darwinServiceLabel+".plist")
			if tc.socket {
				path = filepath.Join(prefix, "var", "agent-machine", "daemon.sock")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			body := darwinAgent(home, filepath.Join(prefix, "bin", "managed-machine"))
			create := func(body string) {
				t.Helper()
				if !tc.socket {
					if err := os.WriteFile(path, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
					return
				}
				s, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				s.SetUnlinkOnClose(false)
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if tc.initial {
				create(body)
			}
			changed := false
			deps := Deps{Deactivate: func(string) error {
				if changed {
					return nil
				}
				if tc.replace {
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
				} else if tc.initial {
					body = "another job"
				}
				create(body)
				changed = true
				return nil
			}}
			caller := Caller{UID: os.Getuid(), RegisteredHome: home}
			err = stopPackageServices(deps, prefix, caller, absentPackageServices())
			if !changed || err == nil || !strings.Contains(err.Error(), "changed during unload") {
				t.Fatalf("expected a changed service refusal, got %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil || tc.socket && info.Mode()&os.ModeSocket == 0 {
				t.Fatal("replacement removed")
			}
			if !tc.socket {
				b, err := os.ReadFile(path)
				if err != nil || string(b) != body {
					t.Fatal("replacement modified")
				}
			}
		})
	}
}

func TestDarwin15PackageSocketParentReplacedAfterProbe(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "pkg-parent.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "runtime")
	path := filepath.Join(dir, "owner.sock")
	newSocket := func() os.FileInfo {
		t.Helper()
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	original := newSocket()
	var replacement os.FileInfo
	probe := unusedMachineSocket
	t.Cleanup(func() { unusedMachineSocket = probe })
	unusedMachineSocket = func(path string) error {
		if err := probe(path); err != nil {
			return err
		}
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Fatal(err)
		}
		replacement = newSocket()
		return nil
	}
	err = removeStoppedPackageSocket(packageLeaf{path: path, info: original}, os.Getuid(), func(fd int, path string, uid int, recorded unix.Stat_t) error {
		return unlinkQuiescentSocket(fd, path, uid, recorded, func(int) ([]byte, error) { return nil, nil })
	})
	if err == nil || replacement == nil {
		t.Fatalf("replaced directory removal: %v", err)
	}
	for p, want := range map[string]os.FileInfo{path: replacement, filepath.Join(dir+".old", "owner.sock"): original} {
		info, e := os.Lstat(p)
		if e != nil || !os.SameFile(info, want) {
			t.Fatalf("lost socket: %v", e)
		}
	}
}
