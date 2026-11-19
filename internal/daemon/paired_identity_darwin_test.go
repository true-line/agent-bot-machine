package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
)

func TestPairedCustodyNeverRepairsOrMigrates(t *testing.T) {
	for _, scenario := range []string{"valid", "absent item", "denied read", "wrong seed", "missing published pin", "missing private pin", "legacy evidence", "malformed seed"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRecoveryFixture(t)
			channel := t.TempDir()
			privatePin := filepath.Join(f.dir, "daemon.pub")
			published := filepath.Join(channel, "daemon.pub")
			if err := os.WriteFile(published, f.machine, 0644); err != nil {
				t.Fatal(err)
			}
			store := &channelTestStore{rejectRepair: true}
			store.seed = f.signer.Seed()
			// Even matching legacy disk custody must never initialize or repair the paired keychain.
			if err := os.WriteFile(filepath.Join(f.dir, "daemon.key"), f.signer.Seed(), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "absent item":
				store.seed = nil
			case "denied read":
				store.loadErr = errors.New("read denied")
			case "wrong seed":
				_, other := keyPair(t)
				store.seed = other.Seed()
			case "malformed seed":
				store.seed = []byte{1}
			case "missing published pin":
				if err := os.Remove(published); err != nil {
					t.Fatal(err)
				}
			case "missing private pin":
				if err := os.Remove(privatePin); err != nil {
					t.Fatal(err)
				}
			case "legacy evidence":
				if err := os.Mkdir(filepath.Join(channel, "peers"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			key, err := pairedChannelKey(f.dir, channel, channel, store)
			if scenario == "valid" {
				if err != nil || !key.Equal(f.signer) {
					t.Fatal("matching custody refused", err)
				}
			} else if err == nil || len(key) != 0 {
				t.Fatal("invalid custody accepted")
			}
			if store.saves != 0 || store.deletes != 0 {
				t.Fatal("keychain changed")
			}
			if seed, err := os.ReadFile(filepath.Join(f.dir, "daemon.key")); err != nil || !bytes.Equal(seed, f.signer.Seed()) {
				t.Fatal("disk custody changed")
			}
		})
	}
}

func TestPairedIdentityPreflightAndRequiredStartup(t *testing.T) {
	f := newRecoveryFixture(t)
	channel, err := os.MkdirTemp("/tmp", "mm-paired-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(channel) })
	t.Setenv(channelEnv, channel)
	root := filepath.Dir(filepath.Dir(f.dir))
	if err := os.WriteFile(filepath.Join(channel, "daemon.pub"), f.machine, 0644); err != nil {
		t.Fatal(err)
	}
	store := defaultKeyStore(filepath.Join(f.dir, "daemon.key"))
	if err := store.Save(f.signer.Seed()); err != nil {
		t.Fatal(err)
	}
	defer store.Delete()
	deps := owner(root)
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root, PrefixOwner: "admin", DarwinAdmin: true}, nil
	}
	adminCaller := deps.Caller
	deps.Caller = func() (Caller, error) { caller, err := adminCaller(); caller.DarwinAdmin = false; return caller, err }
	if r := run(deps, cli.Context{}, []string{"run", "--require-identity", publicFingerprint(f.machine)}); r.Diagnostic == nil {
		t.Fatal("non-administrator accepted for paired foreground startup")
	}
	if r := run(deps, cli.Context{}, []string{"verify-identity"}); r.Diagnostic == nil {
		t.Fatal("non-administrator accepted for paired preflight")
	}
	deps.Caller = adminCaller
	result := run(deps, cli.Context{}, []string{"verify-identity"})
	if result.Diagnostic != nil || len(result.Records) != 1 {
		t.Fatal("preflight failed", result.Diagnostic)
	}
	data, err := result.Records[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]string
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	fingerprint := publicFingerprint(f.machine)
	if len(record) != 2 || record["state"] != "verified" || record["fingerprint"] != fingerprint {
		t.Fatal("unexpected public verification result")
	}
	if key, err := serviceKey(root, fingerprint); err != nil || !key.Equal(f.signer) {
		t.Fatal("matching required startup refused", err)
	}
	// A successful preflight may run while the released Machine is listening.
	// The foreground switch must leave that listener reachable until it is stopped.
	original, err := net.Listen("unix", ChannelSocket())
	if err != nil {
		t.Fatal(err)
	}
	if err := runService(context.Background(), root, fingerprint); err == nil || !SocketListening(ChannelSocket()) {
		t.Fatal("foreground switch displaced the running daemon")
	}
	original.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runService(ctx, root, fingerprint) }()
	if err := WaitListening(ChannelSocket(), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	other, _ := keyPair(t)
	if err := runService(context.Background(), root, publicFingerprint(other)); !errors.Is(err, errChannelIdentity) {
		t.Fatal("wrong required identity accepted", err)
	}
	if err := os.Remove(filepath.Join(f.dir, ownerPairFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(channel, "daemon.pub")); err != nil {
		t.Fatal(err)
	}
	if err := runService(context.Background(), root, fingerprint); !errors.Is(err, errChannelIdentity) {
		t.Fatal("required identity initialized a new channel", err)
	}
	if _, err := os.Stat(filepath.Join(channel, "daemon.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bound channel on refusal")
	}
	if _, err := os.Stat(filepath.Join(channel, "daemon.pub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published a key on refusal")
	}
	seed, found, err := store.Load(false)
	defer zeroBytes(seed)
	if err != nil || !found || !bytes.Equal(seed, f.signer.Seed()) {
		t.Fatal("custody changed")
	}
}
