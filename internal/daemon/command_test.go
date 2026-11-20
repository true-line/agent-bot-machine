package daemon

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
)

func mustLoadPub(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	pub, err := loadPublic(path)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func owner(root string) Deps {
	return Deps{
		GOOS: "darwin",
		Caller: func() (Caller, error) {
			return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root}, nil
		},
		Root: func() (string, error) { return root, nil },
		Executable: func() (string, error) {
			return "/opt/managed-machine/bin/managed-machine", nil
		},
	}
}

func TestDaemonInstallAndStatus(t *testing.T) {
	t.Setenv("AGENT_MACHINE_CHANNEL", filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	res := run(owner(root), cli.Context{}, []string{"install"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	res = run(owner(root), cli.Context{}, []string{"status"})
	if res.Diagnostic != nil || len(res.Records) != 1 {
		t.Fatalf("status %#v", res)
	}
	got, ok := res.Records[0].Get("state")
	if !ok || got != "installed" {
		t.Fatalf("state %v", got)
	}
	res = run(owner(root), cli.Context{}, []string{"receipts"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	got, ok = res.Records[0].Get("state")
	if !ok || got != "installed" {
		t.Fatalf("receipts with unit file and no socket %v", got)
	}
	res = run(owner(root), cli.Context{}, []string{"uninstall"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
}

func TestDaemonRefusesAgent(t *testing.T) {
	root := t.TempDir()
	deps := owner(root)
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "qwts-cursor-agent", UID: 502, Home: root, RegisteredHome: root}, nil
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonCallerRefused {
		t.Fatalf("diagnostic %#v", res.Diagnostic)
	}
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "user", UID: 502, Home: root, RegisteredHome: root, PrefixOwner: "admin"}, nil
	}
	res = run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonCallerRefused {
		t.Fatalf("non-owner diagnostic %#v", res.Diagnostic)
	}
}

func TestInstallWaitHealthyIsRunning(t *testing.T) {
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	deps.Activate = func(string) error { return nil }
	deps.WaitHealthy = func() error { return nil }
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	got, ok := res.Records[0].Get("state")
	if !ok || got != "running" {
		t.Fatalf("state %v", got)
	}
}

func TestInstallActivates(t *testing.T) {
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	var got string
	deps.Activate = func(path string) error {
		got = path
		return nil
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if got == "" {
		t.Fatal("install did not activate the unit")
	}
}

func TestRefusedInstallDoesNotActivate(t *testing.T) {
	root := t.TempDir()
	deps := owner(root)
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "qwts-cursor-agent", UID: 502, Home: root, RegisteredHome: root}, nil
	}
	deps.Activate = func(string) error {
		t.Fatal("refused install activated the unit")
		return nil
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil {
		t.Fatal("expected a refusal")
	}
}

func TestDaemonUsage(t *testing.T) {
	res := run(owner(t.TempDir()), cli.Context{}, []string{"reboot"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.Usage {
		t.Fatalf("diagnostic %#v", res.Diagnostic)
	}
}

func TestDaemonPairAndUnpair(t *testing.T) {
	root := t.TempDir()
	debugOn(t, stateDir(root))
	res := run(owner(root), cli.Context{}, []string{"pair"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	dir := stateDir(root)
	pairing, err := loadPairing(dir)
	if err != nil || len(pairing.Terminal) == 0 {
		t.Fatalf("paired terminal key %v %v", pairing, err)
	}
	for _, args := range [][]string{
		{"unpair", "--client", "agent-daemon"},
		{"unpair", "--client=unknown"},
		{"unpair", "--client", ""},
		{"unpair", "--client=agent-daemon", "--client", "terminal"},
	} {
		res := run(owner(root), cli.Context{}, args)
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.Usage {
			t.Fatalf("expected usage error for %q, got %#v", args, res)
		}
	}
	stillPaired, err := loadPairing(dir)
	if err != nil || !stillPaired.Terminal.Equal(pairing.Terminal) {
		t.Fatalf("refused unpair changed the terminal pairing: %v", err)
	}
	res = run(owner(root), cli.Context{}, []string{"unpair"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	pairing, err = loadPairing(dir)
	if err != nil || len(pairing.Terminal) != 0 {
		t.Fatalf("unpaired terminal key %v %v", pairing, err)
	}
	res = run(owner(root), cli.Context{}, []string{"unpair", "--client", "terminal"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}

	userRoot := t.TempDir()
	userDeps := owner(userRoot)
	userDeps.Caller = func() (Caller, error) {
		return Caller{Username: "user", UID: 502, Home: userRoot, RegisteredHome: userRoot, PrefixOwner: "admin"}, nil
	}
	userDeps.Root = func() (string, error) { return userRoot, nil }
	for _, verb := range []string{"install", "start", "stop", "uninstall", "run", "unpair"} {
		res := run(userDeps, cli.Context{}, []string{verb})
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonCallerRefused {
			t.Fatalf("expected user %s to be refused, got %#v", verb, res.Diagnostic)
		}
	}
	t.Setenv("AGENT_MACHINE_CHANNEL", filepath.Join(userRoot, "channel"))
	res = run(userDeps, cli.Context{}, []string{"pair"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	got, ok := res.Records[0].Get("state")
	if !ok || got != "minted" {
		t.Fatalf("user pair state %v", res)
	}
	rawPath, _ := res.Records[0].Get("path")
	pubPath, _ := rawPath.(string)
	if pubPath != filepath.Join(stateDir(userRoot), "client.pub") {
		t.Fatalf("expected user client.pub, got %s", pubPath)
	}
	pub := mustLoadPub(t, pubPath)
	pubHex := hex.EncodeToString(pub)
	fp := publicFingerprint(pub)
	wantHint := "managed-machine daemon pair --enroll " + pubHex + " --fingerprint " + fp
	gotEnroll, ok := res.Records[0].Get("enroll")
	if !ok || gotEnroll != wantHint {
		t.Fatalf("user pair enroll hint %v", res)
	}
	if res.Human != "As the prefix owner run:\n"+wantHint+"\n" {
		t.Fatalf("user pair human %q", res.Human)
	}
	if got, _ := res.Records[0].Get("public"); got != pubHex {
		t.Fatalf("user pair public %v", got)
	}
	if got, _ := res.Records[0].Get("fingerprint"); got != fp {
		t.Fatalf("user pair fingerprint %v", got)
	}
	res = run(userDeps, cli.Context{}, []string{"pair", "--enroll", pubHex, "--fingerprint", fp})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonCallerRefused {
		t.Fatalf("expected user enroll to be refused, got %#v", res.Diagnostic)
	}
	res = run(owner(root), cli.Context{}, []string{"pair", "--enroll", pubHex})
	if res.Diagnostic == nil {
		t.Fatal("expected enroll without fingerprint to fail")
	}
	res = run(owner(root), cli.Context{}, []string{"pair", "--enroll", pubHex, "--fingerprint", strings.Repeat("0", 64)})
	if res.Diagnostic == nil {
		t.Fatal("expected fingerprint mismatch to fail")
	}
	res = run(owner(root), cli.Context{}, []string{"pair", "--enroll", pubHex, "--fingerprint", fp})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	pairing, err = loadPairing(stateDir(root))
	if err != nil || !pairing.allows(pub) {
		t.Fatalf("enrolled user key %v %v", pairing, err)
	}
}

func TestDaemonPairEnrollRequiresKey(t *testing.T) {
	root := t.TempDir()
	res := run(owner(root), cli.Context{}, []string{"pair", "--enroll"})
	if res.Diagnostic == nil {
		t.Fatal("expected --enroll without a key to fail")
	}
}

func TestFailedActivationLeavesNoUnitBehind(t *testing.T) {
	t.Setenv("AGENT_MACHINE_CHANNEL", filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	deps.GOOS = "linux"
	deps.Activate = func(string) error {
		return errors.New("Failed to connect to bus: No medium found")
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed {
		t.Fatalf("diagnostic %#v", res.Diagnostic)
	}
	if !strings.Contains(res.Diagnostic.Message, "No medium found") {
		t.Fatalf("message %q", res.Diagnostic.Message)
	}
	res = run(deps, cli.Context{}, []string{"status"})
	if got, _ := res.Records[0].Get("state"); got != "absent" {
		t.Fatalf("status after a refused activation: %v", got)
	}
	if kpath, err := keydUnitPath("linux", root); err == nil {
		if _, err := os.Stat(kpath); !os.IsNotExist(err) {
			t.Fatalf("keyd unit left behind after a refused activation: %v", err)
		}
	}
}

func TestFailedActivationRestoresThePreviousUnit(t *testing.T) {
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	deps.GOOS = "linux"
	path, err := unitPath("linux", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	old := []byte("[Service]\nExecStart=/old/managed-machine daemon run\n")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	deps.Activate = func(unit string) error {
		if unit == path {
			return errors.New("unit refused")
		}
		return nil
	}
	var reloadSaw []byte
	deps.Reload = func() error {
		reloadSaw, _ = os.ReadFile(path)
		return nil
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed {
		t.Fatalf("diagnostic %#v", res.Diagnostic)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("unit after a refused activation: %q %v", got, err)
	}
	if !bytes.Equal(reloadSaw, old) {
		t.Fatalf("service manager was not reloaded with the restored unit: %q", reloadSaw)
	}
}

func TestServiceFailureIsNotACallerRefusal(t *testing.T) {
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	deps.Deactivate = func(string) error { return errors.New("launchctl: input/output error") }
	for _, verb := range []string{"stop", "uninstall"} {
		res := run(deps, cli.Context{}, []string{verb})
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed {
			t.Fatalf("%s diagnostic %#v", verb, res.Diagnostic)
		}
	}
	deps = owner(root)
	deps.Activate = func(string) error { return nil }
	deps.WaitHealthy = func() error { return errors.New("socket never accepted") }
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed {
		t.Fatalf("unhealthy install diagnostic %#v", res.Diagnostic)
	}
}

func TestFailedReloadAfterRestoreIsReported(t *testing.T) {
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	deps := owner(root)
	deps.GOOS = "linux"
	deps.Activate = func(string) error { return errors.New("enable refused") }
	deps.Reload = func() error { return errors.New("reload refused") }
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed ||
		!strings.Contains(res.Diagnostic.Message, "enable refused") || !strings.Contains(res.Diagnostic.Message, "reload refused") {
		t.Fatalf("diagnostic %#v", res.Diagnostic)
	}
}

func TestDebugClientIsOffUntilInstallDebug(t *testing.T) {
	t.Setenv("AGENT_MACHINE_CHANNEL", filepath.Join(t.TempDir(), "channel"))
	root := t.TempDir()
	dir := stateDir(root)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	res := run(owner(root), cli.Context{}, []string{"install"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if got, _ := res.Records[0].Get("debug_client"); got != "off" {
		t.Fatalf("debug_client after install: %v", got)
	}
	if err := adoptTerminal(dir, pub, 502); err == nil || !strings.Contains(err.Error(), "daemon install --debug") {
		t.Fatalf("bootstrap with debug off: %v", err)
	}
	res = run(owner(root), cli.Context{}, []string{"install", "--debug"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if got, _ := res.Records[0].Get("debug_client"); got != "on" {
		t.Fatalf("debug_client after install --debug: %v", got)
	}
	if err := adoptTerminal(dir, pub, 502); err != nil {
		t.Fatalf("bootstrap with debug on: %v", err)
	}
	pairing, err := loadPairing(dir)
	if err != nil || !pairing.allows(pub) {
		t.Fatalf("terminal key with debug on: %#v %v", pairing, err)
	}
	// start keeps the mode; a plain install turns it off and the enrolled
	// terminal key stops being a live pairing.
	res = run(owner(root), cli.Context{}, []string{"start"})
	if got, _ := res.Records[0].Get("debug_client"); res.Diagnostic != nil || got != "on" {
		t.Fatalf("debug_client after start: %v %#v", got, res.Diagnostic)
	}
	res = run(owner(root), cli.Context{}, []string{"install"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	pairing, err = loadPairing(dir)
	if err != nil || pairing.allows(pub) {
		t.Fatalf("terminal key with debug off again: %#v %v", pairing, err)
	}
}

func TestDebugFlagsAreInstallOnly(t *testing.T) {
	for _, args := range [][]string{{"start", "--debug"}, {"install", "--user", "someone"}, {"start", "--user", "someone"}} {
		res := run(owner(t.TempDir()), cli.Context{}, args)
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.Usage {
			t.Fatalf("%v diagnostic %#v", args, res.Diagnostic)
		}
	}
}

func TestPairEnrollAgentDaemonReportsTheBinding(t *testing.T) {
	root := t.TempDir()
	deps := owner(root)
	deps.GOOS = hostOS()
	old := lookupUser
	t.Cleanup(func() { lookupUser = old })
	lookupUser = func(name string) (*user.User, error) {
		if name == "hq" {
			return &user.User{Username: "hq", Uid: "777"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"pair", "--enroll", hex.EncodeToString(pub), "--fingerprint", publicFingerprint(pub), "--client", "agent-daemon"}
	res := run(deps, cli.Context{}, args)
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if got, _ := res.Records[0].Get("uid"); got != "any" {
		t.Fatalf("uid with no HQ account: %v", got)
	}
	res = run(deps, cli.Context{}, append(args, "--user", "hq"))
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if got, _ := res.Records[0].Get("uid"); got != "777" {
		t.Fatalf("uid with --user: %v", got)
	}
	res = run(deps, cli.Context{}, append(args, "--user", "ghost"))
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonCallerRefused {
		t.Fatalf("unknown --user: %#v", res.Diagnostic)
	}
}

// Drive normal install and start against disposable services; launchd dispatch
// is the only simulated service lifecycle operation.
func TestBundledDarwinKeydReadiness(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin LaunchAgent and Unix peer credentials")
	}
	home, err := os.MkdirTemp("/private/tmp", "mmkr.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv(channelEnv, filepath.Join(home, "channel"))
	if err := os.MkdirAll(filepath.Dir(ChannelSocket()), 0700); err != nil {
		t.Fatal(err)
	}
	machine, err := net.Listen("unix", ChannelSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	keydDir := filepath.Join(home, ".local", "state", "agent-bot", "keyd")
	if err := os.MkdirAll(keydDir, 0700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "agent-bot-keyd"), []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	t.Setenv("XDG_STATE_HOME", other)
	caller := Caller{UID: os.Getuid(), Username: "fixture", PrefixOwner: "fixture", Home: home, RegisteredHome: home, DarwinAdmin: true}
	deps := owner(home)
	deps.Caller = func() (Caller, error) { return caller, nil }
	deps.Executable = func() (string, error) { return filepath.Join(bin, "managed-machine"), nil }
	deps.Activate = func(string) error { return nil }
	deps.WaitHealthy = func() error { return WaitListening(ChannelSocket(), time.Second) }
	path := filepath.Join(keydDir, "keyd.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	res := run(deps, cli.Context{}, []string{"install"})
	if res.Diagnostic == nil || !strings.Contains(res.Diagnostic.Message, "Machine is listening, but bundled keyd is not ready") {
		t.Fatalf("missing partial-start diagnostic: %#v", res.Diagnostic)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "keep" {
		t.Fatal("changed the existing endpoint")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	sock, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	checked := make(chan error, 1)
	go func() {
		c, err := sock.Accept()
		if err != nil {
			checked <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil && !strings.Contains(line, `"method":"initialize"`) {
			err = errors.New("unexpected request")
		}
		if err == nil {
			_, err = fmt.Fprintln(c, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"agent-bot-keyd","version":"0.2.1"}}}`)
		}
		checked <- err
	}()
	caller.Home = home + "/" // legal spelling of the same registered home
	res = run(deps, cli.Context{}, []string{"start"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	state, _ := res.Records[0].Get("state")
	if state != "running" {
		t.Fatalf("state %v", state)
	}
	if err := <-checked; err != nil {
		t.Fatal(err)
	}

	// A new Machine executable without the helper beside it must preserve
	// the previous registration and stop before activating either unit.
	deps.Executable = func() (string, error) { return filepath.Join(home, "new", "managed-machine"), nil }
	activated := false
	deps.Activate = func(string) error { activated = true; return nil }
	keydPlist, err := keydUnitPath("darwin", home)
	if err != nil {
		t.Fatal(err)
	}
	machinePlist, err := unitPath("darwin", home)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(machinePlist)
	if err != nil {
		t.Fatal(err)
	}
	res = run(deps, cli.Context{}, []string{"start"})
	if res.Diagnostic == nil || !strings.Contains(res.Diagnostic.Message, "restore agent-bot-keyd") || activated {
		t.Fatalf("missing companion reported ready or activated an old unit: %#v", res.Diagnostic)
	}
	if current, err := os.ReadFile(machinePlist); err != nil || !bytes.Equal(current, prior) {
		t.Fatal("changed the existing Machine LaunchAgent before the missing-companion refusal", err)
	}
	body := keydAgent(filepath.Join(home, ".local", "state", "agent-bot"), filepath.Join(bin, "agent-bot-keyd"))
	if current, err := os.ReadFile(keydPlist); err != nil || string(current) != body {
		t.Fatal("changed the existing keyd LaunchAgent", err)
	}

	// An independent plist does not turn a manual binary into a bundle.
	custom := strings.Replace(body, "<string>serve</string>", "<string>custom</string>", 1)
	if err := os.WriteFile(keydPlist, []byte(custom), 0600); err != nil {
		t.Fatal(err)
	}
	deps.Activate = func(path string) error {
		if path != machinePlist {
			t.Fatal("activated a unit from an unrelated registration")
		}
		return nil
	}
	if res := run(deps, cli.Context{}, []string{"start"}); res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	if current, err := os.ReadFile(keydPlist); err != nil || string(current) != custom {
		t.Fatal("changed an unrelated LaunchAgent", err)
	}

}
