package daemon

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

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
	res := run(owner(root), cli.Context{}, []string{"pair"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	dir := stateDir(root)
	pairing, err := loadPairing(dir)
	if err != nil || len(pairing.Terminal) == 0 {
		t.Fatalf("paired terminal key %v %v", pairing, err)
	}
	res = run(owner(root), cli.Context{}, []string{"unpair"})
	if res.Diagnostic != nil {
		t.Fatal(res.Diagnostic.Message)
	}
	pairing, err = loadPairing(dir)
	if err != nil || len(pairing.Terminal) != 0 {
		t.Fatalf("unpaired terminal key %v %v", pairing, err)
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
