package daemon

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestListenModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket permissions are not the Windows pipe")
	}
	dir := filepath.Join(t.TempDir(), "state")
	ln, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", info.Mode().Perm())
	}
	sock, err := os.Stat(filepath.Join(dir, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if sock.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o", sock.Mode().Perm())
	}
}

func TestListenChannelModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket permissions are not the Windows pipe")
	}
	base, err := os.MkdirTemp("/tmp", "mm-ch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "channel")
	ln, err := ListenChannel(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("channel dir mode %o", info.Mode().Perm())
	}
	sock, err := os.Stat(filepath.Join(dir, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if sock.Mode().Perm() != 0o666 {
		t.Fatalf("channel socket mode %o", sock.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "enroll")); !os.IsNotExist(err) {
		t.Fatalf("channel must not create a shared enroll drop: %v", err)
	}
}

func TestServeStatusSigned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket permissions are not the Windows pipe")
	}
	pub, priv := keyPair(t)
	dpub, dpriv := keyPair(t)
	now := time.Now()
	g := &Gate{Pairing: Pairing{Live: pub}, PeerUID: 501, Now: func() time.Time { return now }}
	dir := filepath.Join(t.TempDir(), "state")
	ln, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, g, dpriv, func(net.Conn) (int, error) { return 501, nil }, Hooks{}) }()

	conn, err := net.Dial("unix", filepath.Join(dir, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw := signed(t, priv, Request{Verb: "status", Timestamp: now.Unix(), Nonce: "sock-1", Soul: "iron", Harness: "cursor"})
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var res Response
	if err := json.Unmarshal(line, &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.State != "idle" {
		t.Fatalf("response %#v", res)
	}
	if res.RequestNonce != "sock-1" {
		t.Fatalf("request nonce %q", res.RequestNonce)
	}
	if !VerifyResponse(dpub, res) {
		t.Fatal("response signature did not verify")
	}
	res.RequestNonce = "other"
	if VerifyResponse(dpub, res) {
		t.Fatal("a response for another request verified")
	}
	cancel()
	<-done
}

func TestThinClientStatusFromOtherUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket permissions are not the Windows pipe")
	}
	base, err := os.MkdirTemp("/tmp", "mm-thin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	admin := filepath.Join(base, "admin")
	user := filepath.Join(base, "user")
	channel := filepath.Join(base, "channel")
	t.Setenv("AGENT_MACHINE_CHANNEL", channel)
	pubPath, err := PairClient(user)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := loadPublic(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnrollClient(admin, "terminal", hex.EncodeToString(pub), publicFingerprint(pub)); err != nil {
		t.Fatal(err)
	}
	priv, err := loadOrCreateKey(filepath.Join(stateDir(admin), "daemon.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeChannelPub(channel, priv); err != nil {
		t.Fatal(err)
	}
	pairing, err := loadPairing(stateDir(admin))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenChannel(channel)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, &Gate{Pairing: pairing, Dir: stateDir(admin)}, priv, func(net.Conn) (int, error) { return 502, nil }, Hooks{
			Receipts: func() ([]byte, error) { return []byte("[]"), nil },
		})
	}()
	handled, res, err := TryRPC(filepath.Join(channel, "daemon.sock"), filepath.Join(stateDir(user), "client.key"), "status", "")
	if err != nil || !handled || !res.OK || res.State != "idle" {
		t.Fatalf("handled %v res %#v err %v", handled, res, err)
	}
	handled, res, err = TryRPC(filepath.Join(channel, "daemon.sock"), filepath.Join(stateDir(user), "client.key"), "receipts", "")
	if err != nil || !handled || !res.OK || res.State != "listed" || string(res.Body) != "[]" {
		t.Fatalf("receipts handled %v res %#v err %v", handled, res, err)
	}
	cancel()
	<-done
}
