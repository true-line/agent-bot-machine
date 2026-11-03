package daemon

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
)

// TryUpdateForCaller refuses root, agent accounts, agent sessions, and a
// foreign HOME before touching the client key or the daemon socket. The
// prefix owner check is not applied: the thin client runs in the user account.
func TryUpdateForCaller(caller Caller, endpoint, keyPath, flavor string) (bool, Response, error) {
	if caller.RefuseClient() != "" {
		return false, Response{}, nil
	}
	return TryUpdate(endpoint, keyPath, flavor)
}

// TryUpdate sends one signed update request when the daemon is reachable and
// the client key exists. A missing daemon or key returns handled false so the
// legacy --update path can run. The nonce is single-use. Harness is terminal
// so the receipt names this client. The response is accepted only when
// daemon.pub, beside the client key or on the channel, verifies it.
func TryUpdate(endpoint, keyPath, flavor string) (bool, Response, error) {
	return TryRPC(endpoint, keyPath, "update", flavor)
}

// TryRPC sends one signed request on the local channel. A missing daemon or
// key returns handled false.
func TryRPC(endpoint, keyPath, verb, name string) (bool, Response, error) {
	seed, err := os.ReadFile(keyPath)
	defer zeroBytes(seed)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, Response{}, nil
		}
		return false, Response{}, err
	}
	if len(seed) != ed25519.SeedSize {
		return false, Response{}, errors.New("client key has the wrong length")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	conn, err := dialDaemon(endpoint)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, Response{}, nil
		}
		return true, Response{}, err
	}
	defer conn.Close()
	nonce, err := newNonce()
	if err != nil {
		return true, Response{}, err
	}
	req := Request{Verb: verb, Name: name, Harness: "terminal", Timestamp: time.Now().Unix(), Nonce: nonce}
	if err := Sign(priv, &req); err != nil {
		return true, Response{}, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return true, Response{}, err
	}
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return true, Response{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return true, Response{}, err
	}
	var res Response
	if err := json.Unmarshal(line, &res); err != nil {
		return true, Response{}, err
	}
	pub, err := loadDaemonPub(keyPath)
	if err != nil {
		if pub, err = daemonPubFromBody(res.Body); err != nil {
			return true, Response{}, err
		}
	}
	if res.RequestNonce != nonce || !VerifyResponse(pub, res) {
		return true, Response{}, errors.New("daemon response signature does not match")
	}
	if verb == "bootstrap" {
		if err := writePublicFile(filepath.Join(filepath.Dir(keyPath), "daemon.pub"), pub, 0o600); err != nil {
			return true, Response{}, err
		}
	}
	return true, res, nil
}

func daemonPubFromBody(body json.RawMessage) (ed25519.PublicKey, error) {
	var payload struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(payload.PublicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("daemon public key is missing from the bootstrap reply")
	}
	return ed25519.PublicKey(raw), nil
}

func humanThinClient(caller Caller) bool {
	return caller.Refuse() != "" && caller.RefuseClient() == ""
}

// EnsureBootstrap mints a home-directory client key and enrolls it with the
// daemon using the unix-socket UID. The prefix owner and agent sessions skip.
func EnsureBootstrap(caller Caller, endpoint, keyPath string) error {
	if !humanThinClient(caller) {
		return nil
	}
	if endpoint == "" || keyPath == "" {
		return nil
	}
	pub, err := mintClientKey(keyPath)
	if err != nil {
		return err
	}
	if err := writePublicFile(filepath.Join(filepath.Dir(keyPath), "client.pub"), pub, 0o600); err != nil {
		return err
	}
	handled, res, err := TryRPC(endpoint, keyPath, "bootstrap", "")
	if err != nil {
		return err
	}
	if !handled {
		return errors.New("daemon is not listening")
	}
	if !res.OK {
		msg := res.Message
		if msg == "" {
			msg = res.Diagnostic
		}
		if msg == "" {
			msg = "bootstrap refused"
		}
		return errors.New(msg)
	}
	return nil
}

func signedRPC(caller Caller, endpoint, keyPath, verb, name string) (bool, Response, error) {
	handled, res, err := TryRPC(endpoint, keyPath, verb, name)
	if !humanThinClient(caller) {
		return handled, res, err
	}
	need := !handled
	if handled && err == nil && !res.OK && res.Diagnostic == diag.DaemonUnknownKey {
		need = true
	}
	if !need {
		return handled, res, err
	}
	if berr := EnsureBootstrap(caller, endpoint, keyPath); berr != nil {
		if handled {
			return handled, res, err
		}
		return true, Response{}, berr
	}
	return TryRPC(endpoint, keyPath, verb, name)
}

func loadDaemonPub(keyPath string) (ed25519.PublicKey, error) {
	pub, err := loadPublic(filepath.Join(filepath.Dir(keyPath), "daemon.pub"))
	if err == nil {
		return pub, nil
	}
	if ch := ChannelDir(); ch != "" {
		if pub, chErr := loadPublic(filepath.Join(ch, "daemon.pub")); chErr == nil {
			return pub, nil
		}
	}
	return nil, err
}
