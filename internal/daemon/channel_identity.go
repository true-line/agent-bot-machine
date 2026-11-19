package daemon

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/output"
)

var legacyPrivateFiles = []string{"daemon.key", "client.key", "daemon.keychain-db", "peers"}

var errChannelIdentity = errors.New("published Machine identity has no matching private key; restore the prefix owner's matching private daemon state before startup")

// A stopped service can leave its public pin in the channel directory. Read
// private custody without repairing it before install, startup or pairing can
// change any state. A public pin alone cannot authorize another identity.
func checkChannelIdentity(root string) error {
	if runtime.GOOS == "windows" || ChannelDir() == "" {
		return nil
	}
	dir := stateDir(root)
	store := defaultKeyStore(filepath.Join(dir, "daemon.key"))
	key, err := pairedChannelKey(dir, ChannelDir(), defaultLegacySharedDir(root), store)
	if key != nil || err != nil {
		zeroBytes(key)
		return err
	}
	return checkPublishedKey(dir, ChannelDir(), defaultLegacySharedDir(root), store)
}

// A protected macOS enrollment pins its Machine independently of the shared
// channel. Never migrate, repair or create a key when serving that enrollment.
// A nil key means no completed enrollment and allows ordinary initialization.
func pairedChannelKey(dir, channel, legacy string, store keyStore) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	state, err := readOwnerPairState(dir)
	if err != nil || state == nil || state.HQ == "" {
		return nil, err
	}
	for _, path := range []string{filepath.Dir(dir), dir, filepath.Join(dir, "peers")} {
		if err := verifyPrivateDir(path); err != nil {
			return nil, err
		}
	}
	legacyPending, err := legacyRotationPending(dir, legacy)
	if err != nil || legacyPending || channel == "" || store == nil {
		return nil, errChannelIdentity
	}
	privatePub, err := readPublishedKey(dir)
	if err != nil || hex.EncodeToString(privatePub) != state.Machine {
		return nil, errChannelIdentity
	}
	published, err := readPublishedKey(channel)
	if err != nil || !privatePub.Equal(published) {
		return nil, errChannelIdentity
	}

	seed, found, err := store.Load(false)
	defer zeroBytes(seed)
	if err != nil || !found || len(seed) != ed25519.SeedSize {
		return nil, errChannelIdentity
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !privatePub.Equal(key.Public()) {
		zeroBytes(key)
		return nil, errChannelIdentity
	}
	return key, nil
}

// This command and normal foreground startup use the same custody check.
// Success reveals only the fingerprint of the already-public signing key.
func verifyPairedIdentity(deps Deps) cli.Result {
	caller, err := deps.caller()
	if err != nil {
		return ownerPairRefused("cannot identify the prefix owner")
	}
	if why := caller.Refuse(); why != "" {
		return ownerPairRefused(why)
	}
	if hostOS() != "darwin" || caller.PrefixOwner == "" || !caller.DarwinAdmin {
		return ownerPairRefused("verify-identity requires the paired macOS prefix administrator")
	}
	root, err := deps.root()
	if err != nil {
		return serviceFailed(err)
	}
	dir := stateDir(root)
	key, err := pairedChannelKey(dir, ChannelDir(), defaultLegacySharedDir(root), defaultKeyStore(filepath.Join(dir, "daemon.key")))
	if err != nil {
		return serviceFailed(err)
	}
	if key == nil {
		return ownerPairRefused("verify-identity requires an existing owner-approved HQ enrollment")
	}
	defer zeroBytes(key)
	return cli.Result{Records: []*output.Record{output.New().Set("state", "verified").Set("fingerprint", publicFingerprint(key.Public().(ed25519.PublicKey)))}}
}

func readPublishedKey(channel string) (ed25519.PublicKey, error) {
	path := filepath.Join(channel, "daemon.pub")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != ed25519.PublicKeySize {
		return nil, errors.New("invalid published Machine public key")
	}
	return loadPublic(path)
}

func checkPublishedKey(dir, channel, legacy string, store keyStore) error {
	if legacy != "" && filepath.Clean(channel) == filepath.Clean(legacy) {
		pending, err := legacyRotationPending(dir, legacy)
		if err != nil || pending {
			return err
		}
	}
	pin, err := readPublishedKey(channel)
	if err != nil || pin == nil {
		return err
	}
	key, _, err := matchingPrivateKey(dir, store, pin)
	zeroBytes(key)
	return err
}

// The first pin and the signing seed must come from the same initialization,
// including concurrent terminal pairing and service startup.
func establishChannelKey(path string, store keyStore, channel string, publish bool) (key ed25519.PrivateKey, err error) {
	if runtime.GOOS == "windows" || channel == "" {
		return loadOrCreateKeyWithStore(path, store)
	}
	dir := filepath.Dir(path)
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	pin, err := readPublishedKey(channel)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		key, err = loadOrCreateKeyWithStore(path, store)
	} else {
		var disk bool
		key, disk, err = matchingPrivateKey(dir, store, pin)
		if err == nil && disk && store != nil {
			seed := key.Seed()
			err = store.Save(seed)
			zeroBytes(seed)
		}
		if err == nil && store != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = removeErr
			}
		}
		if err == nil {
			err = writeDaemonPub(path, key)
		}
	}
	if err == nil && publish {
		err = writeChannelPub(channel, key)
	}
	if err != nil {
		zeroBytes(key)
		return nil, err
	}
	return key, nil
}

func matchingPrivateKey(dir string, store keyStore, pin ed25519.PublicKey) (ed25519.PrivateKey, bool, error) {
	if err := verifyPrivateDir(filepath.Dir(dir)); err != nil {
		return nil, false, err
	}
	if err := verifyPrivateDir(dir); err != nil {
		return nil, false, err
	}
	var seed []byte
	var found bool
	var err error
	if store != nil {
		seed, found, err = store.Load(false)
		if err != nil {
			zeroBytes(seed)
			return nil, false, err
		}
	}
	if !found {
		seed, err = os.ReadFile(filepath.Join(dir, "daemon.key"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
	}
	defer zeroBytes(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, false, errChannelIdentity
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !pin.Equal(key.Public()) {
		zeroBytes(key)
		return nil, false, errChannelIdentity
	}
	return key, !found, nil
}
