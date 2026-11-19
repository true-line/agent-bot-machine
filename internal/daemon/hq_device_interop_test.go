//go:build darwin || linux

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/qwts/managed-machine/internal/cli"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDisposableHQKeydInterop(t *testing.T) {
	// The cross-repository conformance runner supplies only synthetic keys and
	// an explicitly chosen software keyd test binary. No production entry point
	// interprets these variables or offers the test account/administrative controls.
	if os.Getenv("MM_HQ_DEVICE_INTEROP") != "1" {
		t.Skip("opt-in cross-repository fixture")
	}
	root := os.Getenv("KEYD_FIXTURE_STATE")
	program := os.Getenv("KEYD_FIXTURE_BIN")
	if !filepath.IsAbs(program) || !filepath.IsAbs(root) {
		t.Fatal("absolute software fixture and disposable state paths are required")
	}
	var err error
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || verifyDirOwner(root, info) != nil {
		t.Fatal("software fixture directory must be private")
	}
	registered, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if home, err := filepath.EvalSymlinks(registered); err != nil || root == home {
		t.Fatal("use a separate disposable fixture home")
	}

	dir := stateDir(root)
	raw, err := os.ReadFile(filepath.Join(root, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inputs struct {
		Machine string `json:"machine_seed"`
		HQ      string `json:"hq_seed"`
		Owner   string `json:"owner"`
		Epoch   string `json:"hq_epoch"`
	}
	if json.Unmarshal(raw, &inputs) != nil {
		t.Fatal("invalid inputs")
	}
	parse := func(s string) ed25519.PrivateKey {
		v, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || len(v) != 32 {
			t.Fatal("bad seed")
		}
		return ed25519.NewKeyFromSeed(v)
	}
	priv := parse(inputs.Machine)
	machine := priv.Public().(ed25519.PublicKey)
	hq := parse(inputs.HQ).Public().(ed25519.PublicKey)
	epoch := inputs.Epoch
	if epoch == "legacy" {
		epoch = ""
	}
	if _, existing := os.Lstat(filepath.Join(root, "pair.json")); os.IsNotExist(existing) {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatal("refusing existing Machine state without a fixture pair")
		}
		if _, err := ensureStateDirAndPeers(dir); err != nil {
			t.Fatal(err)
		}
		if err := (&ownerPairState{Owner: inputs.Owner, Machine: hex.EncodeToString(machine), HQ: hex.EncodeToString(hq), UID: 331, HQEpoch: epoch}).save(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "daemon.pub"), machine, 0600); err != nil {
			t.Fatal(err)
		}
		unlock, err := lockOwnerPairing(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = unlock(); err != nil {
			t.Fatal(err)
		}
		pair, err := json.Marshal(map[string]any{"owner": inputs.Owner, "machine_pub": base64.StdEncoding.EncodeToString(machine), "hq_pub": base64.StdEncoding.EncodeToString(hq), "hq_uid": 331, "hq_epoch": inputs.Epoch})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "pair.json"), pair, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("unix", filepath.Join(root, "machine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Lstat(filepath.Join(root, "revoke")); err == nil {
					deps := owner(root)
					deps.Caller = func() (Caller, error) {
						return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root, PrefixOwner: "admin", DarwinAdmin: true}, nil
					}
					r := run(deps, cli.Context{}, []string{"revoke-hq"})
					if r.Diagnostic != nil {
						t.Error("revoke failed")
						cancel()
						return
					}
					if os.Remove(filepath.Join(root, "revoke")) != nil || os.WriteFile(filepath.Join(root, "revoked"), []byte("ok"), 0600) != nil {
						t.Error("control failed")
						cancel()
						return
					}
				}
				if _, err := os.Lstat(filepath.Join(root, "stop")); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	provider := func(ctx context.Context, _ string, d deviceDelegation) ([]byte, error) {
		raw, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, program, "hq-device")
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Env = []string{"KEYD_FIXTURE_STATE=" + root, "PATH=/usr/bin:/bin"}
		return cmd.Output()
	}
	err = Serve(ctx, ln, &Gate{Dir: dir}, priv, func(net.Conn) (int, error) { return 331, nil }, Hooks{HQDevice: func(req Request) Response { return requestHQDevice(ctx, root, priv, req, time.Now, provider) }})
	if err != nil {
		t.Fatal(err)
	}
}
