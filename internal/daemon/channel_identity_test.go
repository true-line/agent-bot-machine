//go:build unix

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qwts/managed-machine/internal/cli"
)

func TestOrphanChannelRefusesStartupWithoutChangingState(t *testing.T) {
	root, channel := t.TempDir(), t.TempDir()
	t.Setenv(channelEnv, channel)
	pub, _ := keyPair(t)
	pin := filepath.Join(channel, "daemon.pub")
	socket := filepath.Join(channel, "daemon.sock")
	if err := os.WriteFile(pin, pub, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("stale socket marker"), 0600); err != nil {
		t.Fatal(err)
	}
	deps := owner(root)
	deps.Activate = func(string) error { t.Fatal("activated service"); return nil }
	for _, verb := range []string{"install", "start"} {
		result := run(deps, cli.Context{}, []string{verb})
		if result.Diagnostic == nil || result.Diagnostic.Message != errChannelIdentity.Error() {
			t.Fatalf("%s did not explain missing custody: %+v", verb, result.Diagnostic)
		}
	}
	if err := Run(context.Background(), root); !errors.Is(err, errChannelIdentity) {
		t.Fatalf("run: %v", err)
	}
	if _, err := PairTerminal(root); !errors.Is(err, errChannelIdentity) {
		t.Fatalf("pair: %v", err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("changed private home: %v, %v", entries, err)
	}
	if got, err := os.ReadFile(pin); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("changed published pin: %v", err)
	}
	if got, err := os.ReadFile(socket); err != nil || string(got) != "stale socket marker" {
		t.Fatalf("changed socket marker: %v", err)
	}
}

func TestPublishedKeyRequiresMatchingCustody(t *testing.T) {
	channel, dir := t.TempDir(), t.TempDir()
	pin, private := keyPair(t)
	_, other := keyPair(t)
	if err := writeChannelPub(channel, private); err != nil {
		t.Fatal(err)
	}
	if err := writeChannelPub(channel, private); err != nil {
		t.Fatal(err)
	}
	if err := writeChannelPub(channel, other); !errors.Is(err, errChannelIdentity) {
		t.Fatal(err)
	}
	store := &memKeyStore{seed: other.Seed()}
	if err := checkPublishedKey(dir, channel, "", store); !errors.Is(err, errChannelIdentity) {
		t.Fatal(err)
	}
	store.seed = private.Seed()
	if err := checkPublishedKey(dir, channel, "", store); err != nil {
		t.Fatal(err)
	}
	if store.saves != 0 || store.deletes != 0 {
		t.Fatal("inspection mutated the store")
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.key"), private.Seed(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPublishedKey(dir, channel, "", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := readPublishedKey(channel); err != nil || !pin.Equal(got) {
		t.Fatalf("pin changed after inspection: %v", err)
	}
	if err := os.WriteFile(filepath.Join(channel, "daemon.pub"), make([]byte, ed25519.PublicKeySize-1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkPublishedKey(dir, channel, "", store); err == nil {
		t.Fatal("accepted malformed published pin")
	}
}

func TestPublishedPinRetiresOnlyWithLegacyPrivateState(t *testing.T) {
	dir, channel := t.TempDir(), t.TempDir()
	_, private := keyPair(t)
	if err := writeChannelPub(channel, private); err != nil {
		t.Fatal(err)
	}
	store := &memKeyStore{}
	if err := checkPublishedKey(dir, channel, channel, store); !errors.Is(err, errChannelIdentity) {
		t.Fatalf("public-only channel: %v", err)
	}
	if err := os.WriteFile(filepath.Join(channel, "daemon.key"), private.Seed(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPublishedKey(dir, channel, channel, store); err != nil {
		t.Fatal(err)
	}
	if err := purgeLegacySharedState(dir, channel, store); err != nil {
		t.Fatal(err)
	}
	if pin, err := readPublishedKey(channel); err != nil || pin != nil {
		t.Fatalf("old pin remains after documented rotation: %v", err)
	}
	if err := checkPublishedKey(dir, channel, channel, store); err != nil {
		t.Fatalf("fresh identity blocked: %v", err)
	}
}

type channelTestStore struct {
	memKeyStore
	mu           sync.Mutex
	rejectRepair bool
	rejectDelete bool
}

func (s *channelTestStore) Load(repair bool) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectRepair && repair {
		return nil, false, errors.New("unexpected repairing read")
	}
	return s.memKeyStore.Load(repair)
}

func (s *channelTestStore) Save(seed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memKeyStore.Save(seed)
}

func (s *channelTestStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectDelete {
		return errors.New("fixture custody unavailable")
	}
	return s.memKeyStore.Delete()
}

func TestChannelConcurrentInitializationAndPinnedRestart(t *testing.T) {
	dir, channel := t.TempDir(), t.TempDir()
	keyPath := filepath.Join(dir, "daemon.key")
	store := &channelTestStore{}
	const workers = 8
	results := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func(publish bool) {
			<-start
			_, err := establishChannelKey(keyPath, store, channel, publish)
			results <- err
		}(i%2 == 0)
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	pin, err := readPublishedKey(channel)
	if err != nil || store.saves != 1 || !pin.Equal(ed25519.NewKeyFromSeed(store.seed).Public()) {
		t.Fatalf("published identity differs from retained custody: %v", err)
	}
	pubPath := filepath.Join(channel, "daemon.pub")
	if err := os.Chmod(pubPath, 0600); err != nil {
		t.Fatal(err)
	}
	store.rejectRepair = true
	if _, err := establishChannelKey(keyPath, store, channel, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(pubPath)
	if err != nil || info.Mode().Perm() != 0644 || store.saves != 1 || store.deletes != 0 {
		t.Fatalf("restart changed custody or lost channel access: %v", err)
	}
}

func TestLegacyRotationCanRetryWithMalformedPublicPin(t *testing.T) {
	dir, channel := t.TempDir(), t.TempDir()
	marker := filepath.Join(channel, "client.key")
	pin := filepath.Join(channel, "daemon.pub")
	if err := os.WriteFile(marker, []byte("old fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pin, []byte("truncated"), 0644); err != nil {
		t.Fatal(err)
	}
	store := &channelTestStore{rejectDelete: true}
	if err := checkPublishedKey(dir, channel, channel, store); err != nil {
		t.Fatal(err)
	}
	if err := purgeLegacySharedState(dir, channel, store); err == nil {
		t.Fatal("expected interrupted migration")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("lost evidence for retry", err)
	}
	if _, err := os.Stat(pin); err != nil {
		t.Fatal("retired pin before retiring private custody", err)
	}
	store.rejectDelete = false
	if err := purgeLegacySharedState(dir, channel, store); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{marker, pin} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to retire legacy state: %v", err)
		}
	}
}
