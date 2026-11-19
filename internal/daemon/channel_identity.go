package daemon

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	return checkPublishedKey(dir, ChannelDir(), defaultLegacySharedDir(root), defaultKeyStore(filepath.Join(dir, "daemon.key")))
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
