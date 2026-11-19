package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This separate test executable exercises the real kernel peer UID, request
// gate, delegation and reply path before a signed release exists. Only the
// distribution-signature launcher is replaced. The signed release job uses
// runDeviceKeyd unchanged. No hook or test flag exists in managed-machine.
func TestHostedNativeDeviceMachine(t *testing.T) {
	if os.Getenv("MM_NATIVE_KEYD_CHANNEL") != "1" {
		t.Skip("separate hosted native device fixture")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getuid() == 0 {
		t.Fatal("requires disposable hosted macOS prefix owner")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	stage := filepath.Dir(binary)
	if filepath.Dir(stage) != "/private/tmp" || !strings.HasPrefix(filepath.Base(stage), "mm-custody.") {
		t.Fatal("expected the private hosted test stage")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal("prefix owner unavailable")
	}
	seed, err := io.ReadAll(io.LimitReader(os.Stdin, ed25519.SeedSize+1))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("synthetic Machine seed unavailable")
	}
	machine := ed25519.NewKeyFromSeed(seed)
	dir := stateDir(account.HomeDir)
	pairing, err := loadPairing(dir)
	if err != nil {
		t.Fatal("fixture pairing unavailable")
	}
	path := filepath.Join(stage, "device.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal("could not open fixture socket")
	}
	defer ln.Close()
	if err = os.Chmod(path, 0666); err != nil {
		t.Fatal("could not publish fixture socket")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	provider := func(ctx context.Context, _ string, d deviceDelegation) ([]byte, error) {
		encoded, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, filepath.Join(stage, "agent-bot-keyd"), "hq-device")
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + account.HomeDir}
		cmd.Stdin = bytes.NewReader(encoded)
		var out keydOutput
		cmd.Stdout = &out
		if err = cmd.Run(); err != nil {
			return nil, err
		}
		return out.buf.Bytes(), nil
	}
	hooks := Hooks{HQDevice: func(req Request) Response {
		return requestHQDevice(ctx, account.HomeDir, machine, req, time.Now, provider)
	}}
	if err = Serve(ctx, ln, &Gate{Dir: dir, Pairing: pairing}, machine, peerCred, hooks); err != nil && ctx.Err() == nil {
		t.Fatal("hosted Machine channel failed")
	}
}
