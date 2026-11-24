//go:build darwin

package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
)

func TestDirectT03ChildSocketThenPairedHQForwardAndReplay(t *testing.T) {
	if path := os.Getenv("MM_T03_TEST_SOCKET_HELPER"); path != "" {
		frame, err := base64.RawURLEncoding.DecodeString(os.Getenv("MM_T03_TEST_FRAME"))
		if err != nil {
			os.Exit(2)
		}
		conn, err := net.Dial("unix", path)
		if err != nil {
			os.Exit(2)
		}
		if _, err := conn.Write(append(frame, '\n')); err != nil {
			os.Exit(2)
		}
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	f := newRecoveryFixture(t) // pinned Machine key and approved HQ account fixture
	epoch := strings.Repeat("a", 64)
	pair, err := readOwnerPairState(f.dir)
	if err != nil || pair == nil {
		t.Fatal("owner pairing fixture unavailable", err)
	}
	pair.HQEpoch = epoch
	if err := pair.save(f.dir); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockOwnerPairing(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "mm-t03-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(socketDir, "machine.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	selectors := members.Stage2aStopRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64), InstallationID: "soul-one",
		StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
		PlanID: "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("b", 64), HQEpoch: epoch,
	}
	witness := members.Stage2aT03SiblingCredentialWitness{
		Schema:                   "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1",
		ChallengeBase64URL:       base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		PrimaryReservationSHA256: selectors.ReservationSHA256,
		SiblingReservationSHA256: selectors.ReservationSHA256,
		ChildReceiptSHA256:       selectors.ReservationSHA256,
		MetadataSHA256:           selectors.ReservationSHA256,
		CredentialPath:           "/private/fixture/credential", LeaseSequence: 7,
		ObservedAtMS: time.Now().UnixMilli(),
	}
	q := members.Stage2aT03SiblingCredentialWitnessRequest{Stage2aStopRequest: selectors, Witness: witness}
	active, directObserved, consumed := true, false, false
	hooks := Hooks{Stage2a: func(req Request) Response {
		switch req.Verb {
		case stage2aT03DirectChildWitnessVerb:
			if !active || req.peerUID != os.Getuid() || req.peerPID != os.Getpid() ||
				req.stage2aT03SiblingWitness.Witness != witness {
				return Response{}
			}
			directObserved = true
			return Response{OK: true, State: "t03-sibling-credential-observed"}
		case stage2aT03SiblingWitnessVerb:
			if !active || !directObserved || consumed || req.peerUID != 331 ||
				req.stage2aT03SiblingWitness.Witness != witness {
				return Response{}
			}
			consumed = true
			return Response{OK: true, State: "t03-sibling-credential-witnessed"}
		}
		return Response{}
	}}
	serveOnce := func(peer func(net.Conn) (int, error)) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			conn, acceptErr := listener.Accept()
			if acceptErr == nil {
				handleConn(conn, &f.gate, f.signer, peer, hooks)
			}
			close(done)
		}()
		return done
	}
	exchange := func(frame []byte, peer func(net.Conn) (int, error)) []byte {
		t.Helper()
		done := serveOnce(peer)
		conn, err := net.Dial("unix", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(append(frame, '\n')); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(conn)
		conn.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	paired := func(w members.Stage2aT03SiblingCredentialWitness, nonce string) []byte {
		t.Helper()
		request := members.Stage2aT03SiblingCredentialWitnessRequest{Stage2aStopRequest: selectors, Witness: w}
		inner, _ := json.Marshal(request)
		frame := Request{Verb: stage2aT03SiblingWitnessVerb,
			Stage2aRequest: base64.RawURLEncoding.EncodeToString(inner),
			Timestamp:      time.Now().Unix(), Nonce: nonce}
		if err := Sign(f.client, &frame); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(frame)
		return exchange(raw, func(net.Conn) (int, error) { return 331, nil })
	}
	parsePaired := func(raw []byte) Response {
		t.Helper()
		var response Response
		if err := json.Unmarshal(raw, &response); err != nil || !VerifyResponse(ed25519.PublicKey(f.machine), response) {
			t.Fatalf("paired Machine response is not signed: %v", err)
		}
		return response
	}
	oldInner, _ := json.Marshal(q)
	oldVerb := Request{Verb: stage2aT03SiblingWitnessVerb,
		Stage2aRequest: base64.RawURLEncoding.EncodeToString(oldInner),
		Timestamp:      time.Now().Unix(), Nonce: "runner-old-verb"}
	if err := Sign(f.client, &oldVerb); err != nil {
		t.Fatal(err)
	}
	oldFrame, _ := json.Marshal(oldVerb)
	if res := parsePaired(exchange(oldFrame, peerCred)); res.OK {
		t.Fatal("unpaired R socket peer invoked the old HQ-only witness verb")
	}
	if res := parsePaired(paired(witness, "hq-only")); res.OK {
		t.Fatal("HQ-only witness accepted without a direct child socket observation")
	}
	frame, _ := json.Marshal(members.Stage2aT03DirectChildWitnessRequest{
		Verb: stage2aT03DirectChildWitnessVerb, Stage2aT03SiblingCredentialWitnessRequest: q})
	done := serveOnce(peerCred)
	child := exec.Command(os.Args[0], "-test.run=^TestDirectT03ChildSocketThenPairedHQForwardAndReplay$")
	child.Env = append(os.Environ(),
		"MM_T03_TEST_SOCKET_HELPER="+listener.Addr().String(),
		"MM_T03_TEST_FRAME="+base64.RawURLEncoding.EncodeToString(frame))
	childOutput, err := child.Output()
	<-done
	if err != nil || string(childOutput) != "{\"ok\":false}\n" {
		t.Fatalf("same-UID nonwrapper PID reached direct witness: %q %v", childOutput, err)
	}
	if got := string(exchange(frame, peerCred)); got != "{\"ok\":true}\n" {
		t.Fatalf("direct child socket did not get minimal unsigned receipt: %q", got)
	}
	spoof := witness
	spoof.LeaseSequence++
	if res := parsePaired(paired(spoof, "hq-spoof")); res.OK {
		t.Fatal("HQ-forged later lease accepted")
	}
	if res := parsePaired(paired(witness, "hq-exact")); !res.OK {
		t.Fatalf("exact direct-then-paired witness refused: %+v", res)
	}
	if res := parsePaired(paired(witness, "hq-replay")); res.OK {
		t.Fatal("consumed direct child witness replayed")
	}
	active = false
	if got := string(exchange(frame, peerCred)); got != "{\"ok\":false}\n" {
		t.Fatalf("stopped reservation accepted direct child input: %q", got)
	}
}
