//go:build unix

package daemon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
)

func signedOwnerReply(t *testing.T, key *ecdsa.PrivateKey, challenge ownerPairChallenge) (string, string) {
	t.Helper()
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	sum := sha256.Sum256(challenge.message())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	reply, err := json.Marshal(map[string]string{"public_key": encoded, "signature": base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return encoded, string(reply)
}

func TestMacHQOwnerEnrollment(t *testing.T) {
	root := t.TempDir()
	dir := stateDir(root)
	deps := owner(root)
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root, PrefixOwner: "admin", DarwinAdmin: true}, nil
	}
	lookup := lookupUser
	hqUID := "330"
	lookupUser = func(name string) (*user.User, error) {
		if name != "_agent-bot-hq" {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Username: name, Uid: hqUID}, nil
	}
	t.Cleanup(func() { lookupUser = lookup })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machine, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensureStateDirAndPeers(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.pub"), machine, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) cli.Result { return run(deps, cli.Context{}, append([]string{"pair"}, args...)) }
	requireErr := func(r cli.Result) {
		t.Helper()
		if r.Diagnostic == nil {
			t.Fatalf("expected refusal, got %#v", r.Records)
		}
	}
	requireOK := func(r cli.Result) {
		t.Helper()
		if r.Diagnostic != nil {
			t.Fatal(r.Diagnostic.Message)
		}
	}
	enroll := []string{"--enroll", hex.EncodeToString(public), "--fingerprint", publicFingerprint(public), "--client", "agent-daemon"}
	challenge := func() ownerPairChallenge {
		t.Helper()
		r := command(append(enroll, "--owner-challenge")...)
		requireOK(r)
		data, err := r.Records[0].MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var c ownerPairChallenge
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		if c.Action != "machine-pair" || c.Machine != hex.EncodeToString(machine) || c.HQ != hex.EncodeToString(public) || !exactKey(c.Nonce) || c.Expires <= time.Now().Unix() {
			t.Fatalf("bad challenge %+v", c)
		}
		return c
	}
	submit := func(proof string) cli.Result { return command(append(enroll, "--owner-proof", proof)...) }
	pin, _ := signedOwnerReply(t, key, ownerPairChallenge{})
	otherPin, _ := signedOwnerReply(t, other, ownerPairChallenge{})
	requireErr(command(append(enroll, "--owner-challenge")...))
	current := deps.Caller
	deps.Caller = func() (Caller, error) { c, _ := current(); c.DarwinAdmin = false; return c, nil }
	requireErr(command("--pin-owner", pin))
	deps.Caller = current
	requireOK(command("--pin-owner", pin))
	requireOK(command("--pin-owner", pin))
	requireErr(command("--pin-owner", otherPin))
	requireErr(command(enroll...))
	requireErr(command(append(enroll, "--owner-challenge", "--user", "user")...))
	// A pre-enrollment first-install challenge cannot survive pairing.
	st, err := readOwnerPairState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.FirstHQ = &firstHQChallenge{firstHQAction, hex.EncodeToString(machine), approvePlanID, approveDigest, strings.Repeat("c", 64), time.Now().Unix() + ownerChallengeTTL}
	if err := st.save(dir); err != nil {
		t.Fatal(err)
	}
	_, superseded := signedOwnerReply(t, key, challenge())
	st, err = readOwnerPairState(dir)
	if err != nil || st.FirstHQ != nil || st.Recovery != nil {
		t.Fatal("pairing retained the old first-install challenge", err)
	}
	c := challenge()
	_, valid := signedOwnerReply(t, key, c)
	requireErr(submit(superseded))
	_, wrongSigner := signedOwnerReply(t, other, c)
	requireErr(submit(wrongSigner))
	changed := c
	changed.HQ = c.Machine
	_, wrongScope := signedOwnerReply(t, key, changed)
	requireErr(submit(wrongScope))
	hqUID = "331"
	requireErr(submit(valid))
	hqUID = "330"
	initial, err := loadPairing(dir)
	if err != nil || len(initial.AgentDaemon) != 0 {
		t.Fatalf("a refused proof changed enrollment: %+v %v", initial, err)
	}
	var wg sync.WaitGroup
	results := make(chan cli.Result, 6)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- submit(valid) }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for r := range results {
		if r.Diagnostic == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("%d proofs accepted", accepted)
	}
	requireErr(submit(valid))
	// A valid channel signature alone can only observe status/receipts.
	// Starting a new Gate for every request also verifies restart behavior.
	channel := func(uid int, verb string) bool {
		req := Request{Verb: verb, Timestamp: time.Now().Unix(), Nonce: "new-gate"}
		if err := Sign(private, &req); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		_, code, _ := (&Gate{Dir: dir}).verify(uid, raw)
		return code == ""
	}
	if err := SetDebugClient(root, true); err != nil {
		t.Fatal(err)
	}
	if !channel(330, "status") || !channel(330, "receipts") || channel(331, "status") || channel(330, "apply") || channel(330, "update") || channel(330, "bootstrap") {
		t.Fatal("wrong peer, debug or privilege boundary")
	}
	// A paired HQ signing a well-formed members approval still needs a
	// separate action-specific owner proof. This includes recovery plans.
	membersReq := Request{Verb: approveMembersVerb, PlanID: "plan-20261119T040000Z-abcd",
		PlanDigest: strings.Repeat("a", 64), Timestamp: time.Now().Unix(), Nonce: "fresh-members"}
	if err := Sign(private, &membersReq); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(membersReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, code, _ := (&Gate{Dir: dir}).verify(330, raw); code != diag.DaemonPeerRefused {
		t.Fatalf("paired HQ members approval: %s", code)
	}
	// Older binaries might leave a staged key or UID. Neither supersedes
	// the atomic owner-approved tuple.
	alt, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageClient(filepath.Join(dir, "peers"), "agent-daemon", alt); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentDaemonUIDPath(dir), []byte("333\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reload, err := loadPairing(dir)
	if err != nil || !reload.AgentDaemon.Equal(public) || reload.AgentDaemonUID != 330 {
		t.Fatalf("legacy replacement accepted %+v %v", reload, err)
	}
	// A new enrollment epoch similarly supersedes a post-pair recovery.
	st, err = readOwnerPairState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Recovery = &recoveryChallenge{recoveryVerb, st.Machine, st.HQ, st.Owner, approvePlanID, approveDigest, strings.Repeat("d", 64), time.Now().Unix() + ownerChallengeTTL, st.UID}
	if err := st.save(dir); err != nil {
		t.Fatal(err)
	}
	c = challenge()
	expired, err := readOwnerPairState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if expired.FirstHQ != nil || expired.Recovery != nil {
		t.Fatal("new enrollment retained a previous challenge")
	}
	expired.Pending.Expires = time.Now().Unix() - 1
	if err := expired.save(dir); err != nil {
		t.Fatal(err)
	}
	_, late := signedOwnerReply(t, key, *expired.Pending)
	requireErr(submit(late))
	if !channel(330, "status") {
		t.Fatal("expired proof dropped original pairing")
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.pub"), alt, 0600); err != nil {
		t.Fatal(err)
	}
	if channel(330, "status") {
		t.Fatal("accepted an enrollment for a different Machine")
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.pub"), machine, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "peers", "agent-daemon.revoked"), []byte("revoked"), 0600); err != nil {
		t.Fatal(err)
	}
	if channel(330, "status") {
		t.Fatal("revocation ignored")
	}
}

func TestPinPreservesExistingHQPairing(t *testing.T) {
	dir := t.TempDir()
	peers, err := ensureStateDirAndPeers(dir)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := signedOwnerReply(t, key, ownerPairChallenge{})
	if err := os.WriteFile(filepath.Join(peers, "agent-daemon.next"), []byte(strings.Repeat("k", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pinPairOwner(dir, pin, nil); err == nil {
		t.Fatal("adopted an existing staged HQ enrollment")
	}
	if _, err := os.Stat(filepath.Join(dir, ownerPairFile)); !os.IsNotExist(err) {
		t.Fatal("unexpected owner pin", err)
	}
}

// Generated independently using Node's crypto.sign with SHA-256 and a
// synthetic P-256 key. The verifier must consume the exact public wire bytes.
func TestOwnerPairInteroperability(t *testing.T) {
	c := ownerPairChallenge{
		Action: "machine-pair", Machine: strings.Repeat("ab", 32),
		HQ: strings.Repeat("12", 32), Nonce: strings.Repeat("f0", 32), Expires: 1120,
	}
	const public = "BDjokZqqPh39fjipw1EC8xKwi2eosj6MFX94A/HdkRdd2T+vOg0UHeB+zx+8J+4aaQx1Xc/Eyc9n5sv8v4DkpXs="
	const signature = "MEUCIQCgF9p55vCHM/OCmK8eNuA+0qKayEt2UTewnTV/xmoq3AIgRWwv4nM/Ae+pfNtz2shgRQtSGnt1liS+tHmIJYMJPn0="
	sum := sha256.Sum256(c.message())
	if hex.EncodeToString(sum[:]) != "3e6f1280c032cf910328fc8d054585f605479825312b33862260ed74ab3d6169" {
		t.Fatal("canonical proof bytes changed")
	}
	if err := verifyOwnerProof(public, `{"public_key":"`+public+`","signature":"`+signature+`"}`, c.message()); err != nil {
		t.Fatal(err)
	}
}

func TestFirstPinRacesLegacyEnrollment(t *testing.T) {
	root := t.TempDir()
	deps := owner(root)
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root, PrefixOwner: "admin", DarwinAdmin: true}, nil
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := signedOwnerReply(t, key, ownerPairChallenge{})
	if _, err := ensureStateDirAndPeers(stateDir(root)); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan cli.Result, 2)
	for _, args := range [][]string{
		{"pair", "--pin-owner", pin},
		{"pair", "--enroll", hex.EncodeToString(pub), "--fingerprint", publicFingerprint(pub), "--client", "agent-daemon"},
	} {
		go func() { <-start; results <- run(deps, cli.Context{}, args) }()
	}
	close(start)
	a, b := <-results, <-results
	if (a.Diagnostic == nil) == (b.Diagnostic == nil) {
		t.Fatalf("expected exactly one enrollment: %+v %+v", a.Diagnostic, b.Diagnostic)
	}
	p, err := loadPairing(stateDir(root))
	if err != nil {
		t.Fatal(err)
	}
	if p.OwnerPresenceRequired == p.AgentDaemon.Equal(pub) {
		t.Fatal("racing modes were mixed")
	}
}
