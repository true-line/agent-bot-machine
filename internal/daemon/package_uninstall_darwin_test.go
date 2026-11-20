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
)

func TestHomebrewPackageUninstall(t *testing.T) {
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
			text = keydAgent(filepath.Join(home, ".local", "state", "agent-bot"), filepath.Join(keg, "bin", "agent-bot-keyd"))
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
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	caller := Caller{UID: os.Getuid(), Username: u.Username, Home: home, RegisteredHome: home, PrefixOwner: u.Username, DarwinAdmin: true}
	stops := 0
	deps := Deps{LockLifecycle: testMacPackageLock, GOOS: "darwin", Caller: func() (Caller, error) { return caller, nil }, Root: func() (string, error) { return home, nil }, Deactivate: func(string) error { stops++; return nil }}
	t.Setenv(channelEnv, filepath.Join(prefix, "var", "agent-machine"))
	runRemove := func(check func() error) error {
		return removeMacPackage(deps, core, []string{prefix}, check, func(int, string, string) ([]byte, bool, error) { return nil, false, nil })
	}
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
	for _, p := range []string{filepath.Join(channel, "daemon.sock"), filepath.Join(private, "keyd.sock"), filepath.Join(private, "owner.sock"), core} {
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

func TestStoppedSocketNeedsExclusiveEvidence(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "abs.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "owner.sock")
	uid := os.Getuid()
	calls := 0
	quiescent := func(fd int, name string, uid int) error {
		calls++
		return unlinkQuiescentSocket(fd, name, uid, func(int) ([]byte, error) { return []byte(strconv.Itoa(os.Getpid())), nil })
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := removeStoppedPackageSocket(p, uid, quiescent); err == nil || calls != 0 {
		t.Fatal("accepted live socket")
	}
	listener.Close()
	other := func(fd int, name string, uid int) error {
		return unlinkQuiescentSocket(fd, name, uid, func(int) ([]byte, error) { return []byte(fmt.Sprint(os.Getpid() + 1)), nil })
	}
	if err := removeStoppedPackageSocket(p, uid, other); err == nil {
		t.Fatal("older macOS removed endpoint with another process")
	}
	if err := removeStoppedPackageSocket(p, uid, quiescent); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeStoppedPackageSocket(p, uid, quiescent); err == nil {
		t.Fatal("accepted foreign file")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign", p); err != nil {
		t.Fatal(err)
	}
	if err := removeStoppedPackageSocket(p, uid, quiescent); err == nil {
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
				return []byte("path = " + file + "\nprogram = " + bin + "\narguments = {\n" + bin + "\n" + strings.Join(args, "\n") + "\n}\n")
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
			if err := verifyPackageServices(prefix, caller, readJob); err != nil {
				t.Fatal(err)
			}
			program = "/tmp/unrelated-program"
			if err := verifyPackageServices(prefix, caller, readJob); err == nil {
				t.Fatal("accepted unrelated loaded job")
			}
			program = tc.program
			args = []string{"other-operation"}
			if err := verifyPackageServices(prefix, caller, readJob); err == nil {
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
			if err := verifyPackageServices(prefix, caller, readJob); err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(body, "</dict>", "<key>Other</key><true/></dict>", 1)
			if err := os.WriteFile(file, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyPackageServices(prefix, caller, readJob); err == nil {
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
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	legacy := func(parent int, path string, uid int) error {
		return unlinkQuiescentSocket(parent, path, uid, func(int) ([]byte, error) { return nil, nil })
	}
	if err := removeStoppedPackageSocket(path, os.Getuid(), legacy); err == nil {
		t.Fatal("removed bound socket")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
}
