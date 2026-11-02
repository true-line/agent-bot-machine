package daemon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// pairingClients are the only live peers. terminal is the Terminal thin
// client. agent-daemon is the local control plane. A later client is not
// accepted by adding a file.
var pairingClients = []string{"terminal", "agent-daemon"}

var pairingSuffixes = []string{".pub", ".next", ".confirm", ".revoked"}

func ensureStateDirAndPeers(dir string) (string, error) {
	if filepath.Base(filepath.Dir(dir)) == ".config" {
		if err := verifyPrivateDir(filepath.Dir(dir)); err != nil {
			return "", err
		}
	}
	if err := verifyPrivateDir(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := verifyPrivateDir(dir); err != nil {
		return "", err
	}
	if err := stripDarwinACL(dir); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	if err := migrateLegacyPairing(dir); err != nil {
		return "", err
	}
	peers := filepath.Join(dir, "peers")
	if err := verifyPrivateDir(peers); err != nil {
		return "", err
	}
	if err := os.MkdirAll(peers, 0o700); err != nil {
		return "", err
	}
	if err := verifyPrivateDir(peers); err != nil {
		return "", err
	}
	if err := stripDarwinACL(peers); err != nil {
		return "", err
	}
	if err := os.Chmod(peers, 0o700); err != nil {
		return "", err
	}
	return peers, nil
}

// PairTerminal creates or loads client.key in the daemon state directory and
// stages peers/terminal.next and peers/terminal.confirm so the next request
// makes the terminal key live. It refuses legacy peer.* files beside peers/
// and unknown files in peers/.
func PairTerminal(root string) (string, error) {
	dir := stateDir(root)
	if err := purgeLegacySharedState(dir, defaultLegacySharedDir(root), defaultKeyStore(filepath.Join(dir, "daemon.key"))); err != nil {
		return "", err
	}
	peers, err := ensureStateDirAndPeers(dir)
	if err != nil {
		return "", err
	}
	if err := checkPairingFiles(peers); err != nil {
		return "", err
	}
	if _, err := loadOrCreateKey(filepath.Join(dir, "daemon.key")); err != nil {
		return "", err
	}
	pub, err := mintClientKey(filepath.Join(dir, "client.key"))
	if err != nil {
		return "", err
	}
	if err := stageClient(peers, "terminal", pub); err != nil {
		return "", err
	}
	if _, err := loadPairing(dir); err != nil {
		return "", err
	}
	return filepath.Join(peers, "terminal.pub"), nil
}

// PairClient mints client.key and client.pub in the caller's state
// directory. It does not write the daemon's peers/ — that is EnrollClient.
func PairClient(root string) (string, error) {
	dir := stateDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := stripDarwinACL(dir); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	clientKeyPath := filepath.Join(dir, "client.key")
	pub, err := mintClientKey(clientKeyPath)
	if err != nil {
		return "", err
	}
	if err := writePublicFile(filepath.Join(dir, "client.pub"), pub, 0o600); err != nil {
		return "", err
	}
	// ~/.config is often 0700, so the enroll copy lives in the account home
	// (0755) where the prefix owner can read it.
	homePub := filepath.Join(root, "agent-machine.client.pub")
	if err := writePublicFile(homePub, pub, 0o644); err != nil {
		return "", err
	}
	if ch := ChannelDir(); ch != "" {
		if src, err := os.ReadFile(filepath.Join(ch, "daemon.pub")); err == nil && len(src) == ed25519.PublicKeySize {
			_ = writePublicFile(filepath.Join(dir, "daemon.pub"), ed25519.PublicKey(src), 0o600)
		}
		if runtime.GOOS != "windows" {
			if err := ensureEnrollDir(ch); err == nil {
				drop := filepath.Join(ch, "enroll", "terminal.pub")
				if err := writePublicFile(drop, pub, 0o644); err == nil {
					return drop, nil
				}
			}
		}
	}
	return homePub, nil
}

func loadPublicForEnroll(pubPath string) (ed25519.PublicKey, error) {
	pub, err := loadPublic(pubPath)
	if err == nil {
		return pub, nil
	}
	if !isDenied(err) {
		return nil, err
	}
	for _, alt := range enrollFallbacks(pubPath) {
		if pub, altErr := loadPublic(alt); altErr == nil {
			return pub, nil
		}
	}
	return nil, err
}

func enrollFallbacks(pubPath string) []string {
	var out []string
	if ch := ChannelDir(); ch != "" {
		out = append(out, filepath.Join(ch, "enroll", "terminal.pub"))
	}
	if filepath.Base(pubPath) == "client.pub" {
		state := filepath.Dir(pubPath)
		if filepath.Base(state) == "agent-machine" && filepath.Base(filepath.Dir(state)) == ".config" {
			out = append(out, filepath.Join(filepath.Dir(filepath.Dir(state)), "agent-machine.client.pub"))
		}
	}
	return out
}

func isDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES)
}

func writePublicFile(path string, pub ed25519.PublicKey, mode os.FileMode) error {
	_ = os.Remove(path)
	if err := os.WriteFile(path, pub, mode); err != nil {
		return err
	}
	if err := stripDarwinACL(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// EnrollClient stages a client public key from pubPath into the daemon
// peers directory. client is terminal or agent-daemon.
func EnrollClient(root, client, pubPath string) (string, error) {
	if client == "" {
		client = "terminal"
	}
	ok := false
	for _, name := range pairingClients {
		if name == client {
			ok = true
			break
		}
	}
	if !ok {
		return "", fmt.Errorf("client must be terminal or agent-daemon")
	}
	pub, err := loadPublicForEnroll(pubPath)
	if err != nil {
		return "", err
	}
	dir := stateDir(root)
	if err := purgeLegacySharedState(dir, defaultLegacySharedDir(root), defaultKeyStore(filepath.Join(dir, "daemon.key"))); err != nil {
		return "", err
	}
	peers, err := ensureStateDirAndPeers(dir)
	if err != nil {
		return "", err
	}
	if err := checkPairingFiles(peers); err != nil {
		return "", err
	}
	if err := stageClient(peers, client, pub); err != nil {
		return "", err
	}
	if _, err := loadPairing(dir); err != nil {
		return "", err
	}
	return filepath.Join(peers, client+".pub"), nil
}

func mintClientKey(clientKeyPath string) (ed25519.PublicKey, error) {
	seed, err := os.ReadFile(clientKeyPath)
	defer zeroBytes(seed)
	var priv ed25519.PrivateKey
	switch {
	case err == nil && len(seed) == ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(seed)
	case errors.Is(err, os.ErrNotExist):
		_, priv, err = ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		newSeed := priv.Seed()
		defer zeroBytes(newSeed)
		_ = os.Remove(clientKeyPath)
		if err := os.WriteFile(clientKeyPath, newSeed, 0o600); err != nil {
			return nil, err
		}
		if err := stripDarwinACL(clientKeyPath); err != nil {
			return nil, err
		}
		if err := os.Chmod(clientKeyPath, 0o600); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		return nil, errors.New("client key has the wrong length")
	}
	return priv.Public().(ed25519.PublicKey), nil
}

func stageClient(peers, client string, pub ed25519.PublicKey) error {
	nextPath := filepath.Join(peers, client+".next")
	confirmPath := filepath.Join(peers, client+".confirm")
	_ = os.Remove(nextPath)
	if err := os.WriteFile(nextPath, pub, 0o600); err != nil {
		return err
	}
	if err := stripDarwinACL(nextPath); err != nil {
		return err
	}
	sum := sha256.Sum256(pub)
	_ = os.Remove(confirmPath)
	if err := os.WriteFile(confirmPath, []byte(hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		return err
	}
	if err := stripDarwinACL(confirmPath); err != nil {
		return err
	}
	return nil
}

// UnpairTerminal revokes the terminal pairing and removes client.key.
func UnpairTerminal(root string) error {
	dir := stateDir(root)
	if err := purgeLegacySharedState(dir, defaultLegacySharedDir(root), defaultKeyStore(filepath.Join(dir, "daemon.key"))); err != nil {
		return err
	}
	peers, err := ensureStateDirAndPeers(dir)
	if err != nil {
		return err
	}
	if err := checkPairingFiles(peers); err != nil {
		return err
	}
	revokedPath := filepath.Join(peers, "terminal.revoked")
	_ = os.Remove(revokedPath)
	if err := os.WriteFile(revokedPath, []byte("revoked\n"), 0o600); err != nil {
		return err
	}
	if err := stripDarwinACL(revokedPath); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(peers, "terminal.next"))
	_ = os.Remove(filepath.Join(peers, "terminal.confirm"))
	if err := os.Remove(filepath.Join(dir, "client.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// loadPairing reads each client's live key from peers/<client>.pub.
// peers/<client>.next does not replace that client's live key unless
// peers/<client>.confirm contains the SHA-256 of the staged key. A wrong
// confirm file leaves the live key in place. peers/<client>.revoked drops
// that client until a confirmed re-registration replaces it. The other
// client stays live. A legacy peer.pub is moved to peers/terminal.pub.
// Old peer.* files beside an existing peers directory are refused.
func loadPairing(dir string) (Pairing, error) {
	if err := migrateLegacyPairing(dir); err != nil {
		return Pairing{}, err
	}
	peers := filepath.Join(dir, "peers")
	if _, err := os.Stat(peers); errors.Is(err, os.ErrNotExist) {
		return Pairing{}, nil
	} else if err != nil {
		return Pairing{}, err
	}
	if err := checkPairingFiles(peers); err != nil {
		return Pairing{}, err
	}
	var keys []ed25519.PublicKey
	var terminal ed25519.PublicKey
	for _, client := range pairingClients {
		key, err := loadClientKey(peers, client)
		if err != nil {
			return Pairing{}, err
		}
		if key != nil {
			keys = append(keys, key)
			if client == "terminal" {
				terminal = append(ed25519.PublicKey(nil), key...)
			}
		}
	}
	pairing, err := pairingFromKeys(keys)
	if err != nil {
		return Pairing{}, err
	}
	pairing.Terminal = terminal
	return pairing, nil
}

func migrateLegacyPairing(dir string) error {
	legacy := []string{"peer.pub", "peer.next", "peer.confirm", "peer.revoked"}
	var present []string
	for _, name := range legacy {
		_, err := os.Stat(filepath.Join(dir, name))
		if err == nil {
			present = append(present, name)
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if len(present) == 0 {
		return nil
	}
	peers := filepath.Join(dir, "peers")
	if _, err := os.Stat(peers); err == nil {
		return errors.New("pairing state is mixed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(peers, 0o700); err != nil {
		return err
	}
	for _, name := range present {
		suffix := strings.TrimPrefix(name, "peer")
		if err := os.Rename(filepath.Join(dir, name), filepath.Join(peers, "terminal"+suffix)); err != nil {
			return err
		}
	}
	return nil
}

func checkPairingFiles(peers string) error {
	entries, err := os.ReadDir(peers)
	if err != nil {
		return err
	}
	allowed := map[string]struct{}{}
	for _, client := range pairingClients {
		for _, suffix := range pairingSuffixes {
			allowed[client+suffix] = struct{}{}
		}
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok || entry.IsDir() {
			return fmt.Errorf("pairing file %s is not a client key", entry.Name())
		}
	}
	return nil
}

func loadClientKey(peers, client string) (ed25519.PublicKey, error) {
	revokedPath := filepath.Join(peers, client+".revoked")
	revoked := false
	if _, err := os.Stat(revokedPath); err == nil {
		revoked = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var live ed25519.PublicKey
	if !revoked {
		pub, err := loadPublic(filepath.Join(peers, client+".pub"))
		if err == nil {
			live = pub
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	next, err := loadPublic(filepath.Join(peers, client+".next"))
	if errors.Is(err, os.ErrNotExist) {
		return live, nil
	}
	if err != nil {
		return nil, err
	}
	confirm, err := os.ReadFile(filepath.Join(peers, client+".confirm"))
	if errors.Is(err, os.ErrNotExist) {
		return live, nil
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(next)
	if strings.TrimSpace(string(confirm)) != hex.EncodeToString(sum[:]) {
		return live, nil
	}
	pubPath := filepath.Join(peers, client+".pub")
	_ = os.Remove(pubPath)
	if err := os.WriteFile(pubPath, next, 0o600); err != nil {
		return nil, err
	}
	if err := stripDarwinACL(pubPath); err != nil {
		return nil, err
	}
	if err := os.Chmod(pubPath, 0o600); err != nil {
		return nil, err
	}
	_ = os.Remove(filepath.Join(peers, client+".next"))
	_ = os.Remove(filepath.Join(peers, client+".confirm"))
	_ = os.Remove(revokedPath)
	return append(ed25519.PublicKey(nil), next...), nil
}

func pairingFromKeys(keys []ed25519.PublicKey) (Pairing, error) {
	var pairing Pairing
	seen := map[string]struct{}{}
	var live []ed25519.PublicKey
	for _, key := range keys {
		if len(key) != ed25519.PublicKeySize {
			continue
		}
		if _, ok := seen[string(key)]; ok {
			return Pairing{}, errors.New("pairing keys are not distinct")
		}
		seen[string(key)] = struct{}{}
		live = append(live, append(ed25519.PublicKey(nil), key...))
	}
	if len(live) == 0 {
		return pairing, nil
	}
	pairing.Live = live[0]
	pairing.Extra = live[1:]
	return pairing, nil
}
