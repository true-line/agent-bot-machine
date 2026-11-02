package daemon

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
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
		return true, Response{}, err
	}
	if res.RequestNonce != nonce || !VerifyResponse(pub, res) {
		return true, Response{}, errors.New("daemon response signature does not match")
	}
	return true, res, nil
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
