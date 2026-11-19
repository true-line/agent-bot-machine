package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type keyStore interface {
	Load(repair bool) ([]byte, bool, error)
	Save(seed []byte) error
	Delete() error
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	return establishChannelKey(path, defaultKeyStore(path), ChannelDir(), false)
}

func loadOrCreateKeyWithStore(path string, store keyStore) (ed25519.PrivateKey, error) {
	if store != nil {
		seed, ok, err := store.Load(true)
		if err != nil {
			// Fail closed on locked keychain, denied access, or malformed store entry:
			// never generate a replacement key or fall back to a plaintext file.
			return nil, err
		}
		if ok {
			defer zeroBytes(seed)
			_ = os.Remove(path)
			priv := ed25519.NewKeyFromSeed(seed)
			if err := writeDaemonPub(path, priv); err != nil {
				return nil, err
			}
			return priv, nil
		}
		// Migrate an existing valid on-disk daemon.key into the keychain store
		// before removing the on-disk file, so upgrading from a pre-keychain
		// version preserves the daemon's identity.
		diskSeed, rerr := os.ReadFile(path)
		if rerr == nil {
			defer zeroBytes(diskSeed)
			if len(diskSeed) != ed25519.SeedSize {
				return nil, fmt.Errorf("daemon key file %s has invalid length %d", path, len(diskSeed))
			}
			if err := store.Save(diskSeed); err != nil {
				return nil, err
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			priv := ed25519.NewKeyFromSeed(diskSeed)
			if err := writeDaemonPub(path, priv); err != nil {
				return nil, err
			}
			return priv, nil
		}
		if !os.IsNotExist(rerr) {
			return nil, rerr
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		newSeed := priv.Seed()
		defer zeroBytes(newSeed)
		if err := store.Save(newSeed); err != nil {
			return nil, err
		}
		_ = os.Remove(path)
		if err := writeDaemonPub(path, priv); err != nil {
			return nil, err
		}
		return priv, nil
	}
	seed, err := os.ReadFile(path)
	if err == nil && len(seed) == ed25519.SeedSize {
		defer zeroBytes(seed)
		if err := stripDarwinACL(path); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if err := writeDaemonPub(path, priv); err != nil {
			return nil, err
		}
		return priv, nil
	}
	zeroBytes(seed)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	newSeed := priv.Seed()
	defer zeroBytes(newSeed)
	_ = os.Remove(path)
	if err := os.WriteFile(path, newSeed, 0o600); err != nil {
		return nil, err
	}
	if err := stripDarwinACL(path); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	if err := writeDaemonPub(path, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func writeDaemonPub(keyPath string, priv ed25519.PrivateKey) error {
	pubKey, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return os.ErrInvalid
	}
	dir := filepath.Dir(keyPath)
	pubPath := filepath.Join(dir, "daemon.pub")
	_ = os.Remove(pubPath)
	if err := os.WriteFile(pubPath, pubKey, 0o600); err != nil {
		return err
	}
	if err := stripDarwinACL(pubPath); err != nil {
		return err
	}
	return os.Chmod(pubPath, 0o600)
}

var runKeyHelperCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func stripDarwinACL(path string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return runKeyHelperCmd("/bin/chmod", "-N", path)
}

func verifyPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked daemon directory %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("daemon path %s is not a directory", path)
	}
	return verifyDirOwner(path, info)
}

func legacyRotationPending(dir, shared string) (bool, error) {
	if info, err := os.Lstat(dir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(dir)
		if err != nil {
			return false, err
		}
		if shared == "" || filepath.Clean(target) != filepath.Clean(shared) {
			return false, fmt.Errorf("refusing symlinked daemon directory %s", dir)
		}
		return true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if shared != "" {
		for _, name := range legacyPrivateFiles {
			if _, err := os.Lstat(filepath.Join(shared, name)); err == nil {
				return true, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
		}
	}
	return false, nil
}

// purgeLegacySharedState removes leaked secrets from <prefix>/var/agent-machine
// (v0.11.2/v0.11.3 stored keys there), unlinks a ~/.config/agent-machine
// symlink that pointed at it, and rotates daemon.key, client.key, and peers/
// because those files were readable by other local accounts. The directory
// itself stays: it is the cross-account channel (socket + daemon.pub).
func purgeLegacySharedState(dir, shared string, store keyStore) error {
	pending, err := legacyRotationPending(dir, shared)
	if err != nil || !pending {
		return err
	}
	// A second migration must recheck the evidence after the first finishes;
	// it must never erase custody created after a successful migration.
	if err := os.MkdirAll(shared, 0755); err != nil {
		return err
	}
	unlock, err := lockLegacyChannel(shared)
	if err != nil {
		return err
	}
	defer unlock()
	pending, err = legacyRotationPending(dir, shared)
	if err != nil || !pending {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	linked := info != nil && info.Mode()&os.ModeSymlink != 0
	// Retain the evidence that permits rotation until private custody and
	// the previous pin are both retired. A retry after any partial cleanup
	// must still recognize the authorized migration.
	if !linked {
		for _, name := range []string{"daemon.key", "daemon.pub", "client.key", "daemon.keychain-db"} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := os.RemoveAll(filepath.Join(dir, "peers")); err != nil {
			return err
		}
	} else if err := os.RemoveAll(filepath.Join(shared, "daemon.keychain-db")); err != nil {
		return err
	}
	if store != nil {
		if err := store.Delete(); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(shared, "daemon.pub")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, name := range legacyPrivateFiles {
		if err := os.RemoveAll(filepath.Join(shared, name)); err != nil {
			return err
		}
	}
	if linked {
		return os.Remove(dir)
	}
	return nil
}

func loadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, os.ErrInvalid
	}
	return ed25519.PublicKey(b), nil
}
