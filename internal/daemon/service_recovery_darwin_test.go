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
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
)

type recoveryFixture struct {
	dir     string
	machine ed25519.PublicKey
	signer  ed25519.PrivateKey
	client  ed25519.PrivateKey
	owner   *ecdsa.PrivateKey
	gate    Gate
	now     time.Time
	check   recoveryPlanCheck
	recover cooperativeRecoveryApply
	count   int
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	testPlanRole(t, "331")
	f := &recoveryFixture{dir: stateDir(t.TempDir()), now: time.Now()}
	f.machine, f.signer = keyPair(t)
	hq, hqKey := keyPair(t)
	f.client = hqKey
	var err error
	f.owner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := f.owner.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensureStateDirAndPeers(f.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "daemon.pub"), f.machine, 0600); err != nil {
		t.Fatal(err)
	}
	p := ownerPairState{Owner: base64.StdEncoding.EncodeToString(pub), Machine: hex.EncodeToString(f.machine), HQ: hex.EncodeToString(hq), UID: 331}
	if err := p.save(f.dir); err != nil {
		t.Fatal(err)
	}
	f.gate = Gate{Dir: f.dir, Now: func() time.Time { return f.now }}
	f.check = func(id, digest string, uid int) (string, error) {
		if id != approvePlanID || digest != approveDigest || uid != 331 {
			return "", errRecoveryPlan
		}
		return "canonical test plan\n", nil
	}
	return f
}

func (f *recoveryFixture) request(option string, c recoveryChallenge, signature string) Request {
	f.count++
	return Request{Verb: recoveryVerb, Option: option, PlanID: approvePlanID, PlanDigest: approveDigest,
		ChallengeNonce: c.Nonce, OwnerSignature: signature, Timestamp: f.now.Unix(), Nonce: fmt.Sprintf("transport-%d", f.count)}
}

func (f *recoveryFixture) hook(req Request) Response {
	if f.recover != nil {
		return recoverHQService(f.dir, f.machine, req, func() time.Time { return f.now }, f.check, f.recover)
	}
	return recoverHQService(f.dir, f.machine, req, func() time.Time { return f.now }, f.check)
}

func TestCooperativeOwnerRecoveryBindsExactStartAndConsumesProof(t *testing.T) {
	f := newRecoveryFixture(t)
	q := members.Stage2aStopRequest{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID: "installation-1", StartID: "st_1234567890abcdef12345678",
		LaunchID: "ln_1234567890abcdef12345678", PlanID: approvePlanID,
		PlanDigest: approveDigest, HQEpoch: strings.Repeat("b", 64)}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	selector := base64.RawURLEncoding.EncodeToString(raw)
	called := 0
	f.recover = func(req Request, paired func(string, func() error) error) Response {
		if req.stage2aCooperativeRecovery != q || req.Stage2aRequest != selector {
			t.Fatal("recovery received a different start")
		}
		state, err := readOwnerPairState(f.dir)
		if err != nil || state == nil {
			t.Fatal("owner pair unavailable during recovery", err)
		}
		if paired(strings.Repeat("f", 64), func() error { called++; return nil }) == nil || called != 0 {
			t.Fatal("recovery accepted a different pair commitment")
		}
		if err := paired(pairCommitment(state), func() error { called++; return nil }); err != nil {
			t.Fatal("exact live pair refused", err)
		}
		return Response{OK: true, State: "cooperative-recovered"}
	}
	challenge := f.request("challenge", recoveryChallenge{}, "")
	challenge.Verb, challenge.Stage2aRequest = stage2aCooperativeRecoveryVerb, selector
	issued := f.run(t, 331, challenge, f.client)
	if !issued.OK || issued.State != "challenged" {
		t.Fatalf("challenge refused: %+v", issued)
	}
	var c recoveryChallenge
	if json.Unmarshal(issued.Body, &c) != nil || c.Request != selector || c.Action != stage2aCooperativeRecoveryVerb {
		t.Fatalf("challenge did not bind exact recovery selectors: %+v", c)
	}
	approve := f.request("approve", c, f.proof(t, c))
	approve.Verb, approve.Stage2aRequest = stage2aCooperativeRecoveryVerb, selector
	altered := approve
	alteredQ := q
	alteredQ.LaunchID = "ln_ffffffffffffffffffffffff"
	other, _ := json.Marshal(alteredQ)
	altered.Stage2aRequest = base64.RawURLEncoding.EncodeToString(other)
	altered.Nonce = "altered-recovery"
	if r := f.run(t, 331, altered, f.client); r.OK || called != 0 {
		t.Fatal("changed start accepted by owner proof")
	}
	if r := f.run(t, 331, approve, f.client); !r.OK || r.State != "cooperative-recovered" || called != 1 {
		t.Fatalf("exact recovery refused: %+v called=%d", r, called)
	}
	approve.Nonce = "replayed-recovery"
	if r := f.run(t, 331, approve, f.client); r.OK || called != 1 {
		t.Fatal("consumed owner proof replayed")
	}
}

// Use the production signed line protocol, gate and response verification.
func (f *recoveryFixture) run(t *testing.T, uid int, q Request, key ed25519.PrivateKey) Response {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go handleConn(server, &f.gate, f.signer, func(net.Conn) (int, error) { return uid, nil }, Hooks{ServiceRecovery: f.hook})
	if _, err := client.Write(append(signed(t, key, q), '\n')); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.NewDecoder(client).Decode(&r); err != nil || r.RequestNonce != q.Nonce || !VerifyResponse(f.machine, r) {
		t.Fatal("invalid signed Machine response", err)
	}
	return r
}

func (f *recoveryFixture) issue(t *testing.T) recoveryChallenge {
	t.Helper()
	r := f.run(t, 331, f.request("challenge", recoveryChallenge{}, ""), f.client)
	if !r.OK || r.State != "challenged" {
		t.Fatalf("issue: %s", r.Message)
	}
	var c recoveryChallenge
	var fields map[string]any
	if json.Unmarshal(r.Body, &c) != nil || json.Unmarshal(r.Body, &fields) != nil || len(fields) != 9 || fields["plan_canonical"] != "canonical test plan\n" || c.Expires != f.now.Unix()+ownerChallengeTTL {
		t.Fatal("invalid handoff")
	}
	return c
}

func (f *recoveryFixture) proof(t *testing.T, c recoveryChallenge) string {
	t.Helper()
	hash := sha256.Sum256(c.message())
	sig, err := ecdsa.SignASN1(rand.Reader, f.owner, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestQualificationOwnerProofRecordsPurposeWithoutLaunching(t *testing.T) {
	f := newRecoveryFixture(t)
	request := f.request("challenge", recoveryChallenge{}, "")
	request.Verb = harnessQualificationVerb
	challenged := f.run(t, 331, request, f.client)
	if !challenged.OK || challenged.State != "challenged" {
		t.Fatalf("qualification challenge: %+v", challenged)
	}
	var c recoveryChallenge
	if err := json.Unmarshal(challenged.Body, &c); err != nil || c.Action != harnessQualificationVerb {
		t.Fatalf("wrong qualification challenge: %+v, %v", c, err)
	}
	request = f.request("approve", c, f.proof(t, c))
	request.Verb = harnessQualificationVerb
	approved := f.run(t, 331, request, f.client)
	if !approved.OK || approved.State != "approved" {
		t.Fatalf("qualification approval: %+v", approved)
	}
	var public map[string]any
	if err := json.Unmarshal(approved.Body, &public); err != nil || len(public) != 4 {
		t.Fatalf("approval acknowledgment must expose only four fields: %v, %v", public, err)
	}
	raw, err := os.ReadFile(members.ApprovalPath(f.dir, approvePlanID))
	if err != nil {
		t.Fatal(err)
	}
	var stored members.Approval
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Purpose != harnessQualificationVerb || stored.PairCommitment == "" || stored.MachineFingerprint == "" {
		t.Fatalf("qualification was not bound to the paired owner proof: %+v, %v", stored, err)
	}
	if again := f.run(t, 331, request, f.client); again.OK {
		t.Fatal("replayed owner proof accepted")
	}
}

func TestCooperativeInstallOwnerProofRecordsPairedPurpose(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.request("challenge", recoveryChallenge{}, "")
	challenge.Verb = members.SoulCooperativeLaunchInstallPurpose
	r := f.run(t, 331, challenge, f.client)
	if !r.OK || r.State != "challenged" {
		t.Fatalf("cooperative install challenge refused: %+v", r)
	}
	var c recoveryChallenge
	if json.Unmarshal(r.Body, &c) != nil || c.Action != members.SoulCooperativeLaunchInstallPurpose {
		t.Fatal("wrong cooperative install challenge")
	}
	approve := f.request("approve", c, f.proof(t, c))
	approve.Verb = members.SoulCooperativeLaunchInstallPurpose
	if r := f.run(t, 331, approve, f.client); !r.OK || r.State != "approved" {
		t.Fatalf("cooperative install owner proof refused: %+v", r)
	}
	raw, err := os.ReadFile(members.ApprovalPath(f.dir, approvePlanID))
	if err != nil {
		t.Fatal(err)
	}
	var stored members.Approval
	if json.Unmarshal(raw, &stored) != nil ||
		stored.Purpose != members.SoulCooperativeLaunchInstallPurpose ||
		stored.PairCommitment == "" || stored.MachineFingerprint == "" {
		t.Fatalf("cooperative install lost paired owner evidence: %+v", stored)
	}
}

func TestHQServiceRecoveryOneUse(t *testing.T) {
	f := newRecoveryFixture(t)
	first := f.issue(t)
	live := f.issue(t)
	if first.Nonce == live.Nonce {
		t.Fatal("reused challenge")
	}
	for _, op := range []string{"cancel", "approve"} {
		proof := ""
		if op == "approve" {
			proof = f.proof(t, first)
		}
		if f.run(t, 331, f.request(op, first, proof), f.client).OK {
			t.Fatal("old request acted on replacement")
		}
	}
	// A valid daemon RPC, a first-provision signature, or a different signer
	// cannot replace the fresh dedicated-purpose owner signature.
	bad := live
	bad.Action = "first-hq-provision"
	if f.run(t, 331, f.request("approve", live, f.proof(t, bad)), f.client).OK {
		t.Fatal("accepted different purpose")
	}
	if _, err := os.Stat(members.ApprovalPath(f.dir, approvePlanID)); !os.IsNotExist(err) {
		t.Fatal("recorded unapproved plan")
	}
	proof := f.proof(t, live)
	if f.run(t, 332, f.request("approve", live, proof), f.client).OK {
		t.Fatal("accepted wrong role UID")
	}
	_, unknown := keyPair(t)
	if f.run(t, 331, f.request("approve", live, proof), unknown).OK {
		t.Fatal("accepted unknown key")
	}
	r := f.run(t, 331, f.request("approve", live, proof), f.client)
	if !r.OK || r.State != "approved" {
		t.Fatal("valid owner proof refused", r.Message)
	}
	var a members.Approval
	if json.Unmarshal(r.Body, &a) != nil || a.PlanDigest != approveDigest || a.PlanID != approvePlanID ||
		a.ExpiresAt != f.now.Add(members.ApprovalTTL).UTC().Format("2006-01-02T15:04:05Z") {
		t.Fatal("unexpected approval body")
	}
	path := members.ApprovalPath(f.dir, approvePlanID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.run(t, 331, f.request("approve", live, proof), f.client).OK {
		t.Fatal("accepted replay")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("replay changed approval")
	}
}

func TestHQServiceRecoveryRefusals(t *testing.T) {
	for _, why := range []string{"cancelled", "expired", "expired during host recheck", "host drift", "revoked", "revoked during host recheck", "replaced", "different machine", "different owner", "record failure"} {
		t.Run(why, func(t *testing.T) {
			f := newRecoveryFixture(t)
			c := f.issue(t)
			proof := f.proof(t, c)
			switch why {
			case "cancelled":
				if r := f.run(t, 331, f.request("cancel", c, ""), f.client); !r.OK || r.State != "cancelled" {
					t.Fatal("matching cancel refused")
				}
			case "expired":
				f.now = time.Unix(c.Expires, 0)
			case "expired during host recheck":
				f.check = func(string, string, int) (string, error) { f.now = time.Unix(c.Expires, 0); return "plan\n", nil }
			case "host drift":
				f.check = func(string, string, int) (string, error) { return "", errRecoveryPlan }
			case "revoked":
				if err := os.WriteFile(filepath.Join(f.dir, "peers", "agent-daemon.revoked"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "revoked during host recheck":
				f.check = func(string, string, int) (string, error) {
					err := os.WriteFile(filepath.Join(f.dir, "peers", "agent-daemon.revoked"), nil, 0600)
					return "plan\n", err
				}
			case "replaced":
				p, err := readOwnerPairState(f.dir)
				if err != nil {
					t.Fatal(err)
				}
				newHQ, _ := keyPair(t)
				p.HQ = hex.EncodeToString(newHQ)
				p.Recovery = nil
				if err := p.save(f.dir); err != nil {
					t.Fatal(err)
				}
			case "different machine":
				other, _ := keyPair(t)
				if err := os.WriteFile(filepath.Join(f.dir, "daemon.pub"), other, 0600); err != nil {
					t.Fatal(err)
				}
			case "different owner":
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				f.owner = other
				proof = f.proof(t, c)
			case "record failure":
				if err := os.MkdirAll(filepath.Dir(members.ApprovalsDir(f.dir)), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(members.ApprovalsDir(f.dir), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if f.run(t, 331, f.request("approve", c, proof), f.client).OK {
				t.Fatal("unexpected approval")
			}
			if why == "record failure" {
				if err := os.Remove(members.ApprovalsDir(f.dir)); err != nil {
					t.Fatal(err)
				}
				if f.run(t, 331, f.request("approve", c, proof), f.client).OK {
					t.Fatal("write failure left reusable consent")
				}
			}
			if _, err := os.Stat(members.ApprovalPath(f.dir, approvePlanID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created an approval")
			}
		})
	}
}

func TestHQServiceRecoveryProofFieldsAndConcurrentConsumption(t *testing.T) {
	f := newRecoveryFixture(t)
	c := f.issue(t)
	proof := f.proof(t, c)
	q := f.request("approve", c, proof)
	if err := Sign(f.client, &q); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.ChallengeNonce = approveDigest },
		func(r *Request) { r.OwnerSignature = f.proof(t, c) },
		func(r *Request) { r.PlanDigest = hex.EncodeToString(make([]byte, 32)) },
		func(r *Request) { r.PlanID = "plan-20260101T000000Z-0001" },
	} {
		r := q
		edit(&r)
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, id, _ := f.gate.verify(331, raw); id == "" {
			t.Fatal("field not signed by HQ")
		}
	}
	for _, r := range []Request{
		f.request("challenge", c, ""), f.request("cancel", c, proof), f.request("approve", c, ""),
		{Verb: "status", ChallengeNonce: c.Nonce, Nonce: "unexpected", Timestamp: f.now.Unix()},
		{Verb: approveMembersVerb, PlanID: approvePlanID, PlanDigest: approveDigest, Nonce: "generic", Timestamp: f.now.Unix()},
	} {
		if f.run(t, 331, r, f.client).OK {
			t.Fatal("accepted undeclared fields or generic approval")
		}
	}
	var approved [2]bool
	var wg sync.WaitGroup
	// Serve serializes on this listener. Separate daemon processes/retries
	// still share the durable state lock.
	for i := range approved {
		r := f.request("approve", c, proof)
		req, id, msg := f.gate.verify(331, signed(t, f.client, r))
		if id != "" {
			t.Fatal(msg)
		}
		wg.Add(1)
		go func() { defer wg.Done(); approved[i] = f.hook(req).OK }()
	}
	wg.Wait()
	if approved[0] == approved[1] {
		t.Fatalf("wanted one winner, got %v", approved)
	}
}

func TestHQServiceUpgradeBindsPriorPurposeAndMachine(t *testing.T) {
	f := newRecoveryFixture(t)
	send := func(verb, option string, c recoveryChallenge, proof string) Response {
		req := f.request(option, c, proof)
		req.Verb = verb
		return f.run(t, 331, req, f.client)
	}
	res := send(upgradeVerb, "challenge", recoveryChallenge{}, "")
	var c recoveryChallenge
	if !res.OK || res.State != "challenged" || json.Unmarshal(res.Body, &c) != nil || c.Action != upgradeVerb {
		t.Fatal("expected signed upgrade challenge", res)
	}
	proof := f.proof(t, c)
	if send(recoveryVerb, "cancel", c, "").OK || send(recoveryVerb, "approve", c, proof).OK {
		t.Fatal("recovery purpose consumed upgrade challenge")
	}
	recovery := c
	recovery.Action = recoveryVerb
	if send(upgradeVerb, "approve", c, f.proof(t, recovery)).OK {
		t.Fatal("recovery proof approved upgrade")
	}
	if r := send(upgradeVerb, "approve", c, proof); !r.OK || r.State != "approved" {
		t.Fatal("valid upgrade refused", r)
	}
	if send(upgradeVerb, "approve", c, proof).OK {
		t.Fatal("upgrade approval replayed")
	}
	raw, e := os.ReadFile(members.ApprovalPath(f.dir, c.ID))
	var a members.Approval
	fp := sha256.Sum256(f.machine)
	if e != nil || json.Unmarshal(raw, &a) != nil || a.Purpose != members.UpgradePurpose || a.MachineFingerprint != hex.EncodeToString(fp[:]) {
		t.Fatal("missing upgrade-only approval and paired Machine", e)
	}
}

func TestHQServiceUpgradeChecksCurrentPairBeforeCutover(t *testing.T) {
	f := newRecoveryFixture(t)
	state, err := readOwnerPairState(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	who, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	unlock, e := lockOwnerPairing(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	unlock()
	commitment := pairCommitment(state)
	if err := CheckHQUpgradePair(f.dir, who.Username, commitment, nil); err != nil {
		t.Fatal(err)
	}
	did := false
	if err := CheckHQUpgradePair(f.dir, who.Username, commitment, func() error { did = true; return nil }); err != nil || !did {
		t.Fatal("approved pair could not publish reviewed change", err)
	}
	state.HQEpoch = fmt.Sprintf("%064x", 11)
	if err := state.save(f.dir); err != nil {
		t.Fatal(err)
	}
	did = false
	if err := CheckHQUpgradePair(f.dir, who.Username, commitment, func() error { did = true; return nil }); err == nil || did {
		t.Fatal("previous epoch published reviewed change")
	}
	commitment = pairCommitment(state)
	if err := os.WriteFile(filepath.Join(f.dir, "peers", "agent-daemon.revoked"), []byte("revoked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckHQUpgradePair(f.dir, who.Username, commitment, nil); err == nil {
		t.Fatal("revoked HQ accepted")
	}
}

// An upgrade can finish preflight while an administrator revokes the role.
// The actual launch submission must pass the live guard after preflight.
func TestHQUpgradeRevocationDuringBootstrapPreflight(t *testing.T) {
	f := newRecoveryFixture(t)
	state, err := readOwnerPairState(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockOwnerPairing(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = unlock(); err != nil {
		t.Fatal(err)
	}
	commitment := pairCommitment(state)
	if err := CheckHQUpgradePair(f.dir, account.Username, commitment, nil); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	result := make(chan error, 1)
	launched := false
	go func() {
		<-ready
		result <- CheckHQUpgradePair(f.dir, account.Username, commitment, func() error { launched = true; return nil })
	}()
	err = revokeHQ(f.dir)
	close(ready)
	admission := <-result
	if err != nil {
		t.Fatal(err)
	}
	if admission == nil || launched {
		t.Fatal("submitted launch after revocation completed")
	}
}

func TestHarnessOwnerProofCannotAuthorizeAnotherAction(t *testing.T) {
	for _, verb := range []string{harnessInstallVerb, harnessRetireVerb, harnessAccountsVerb} {
		t.Run(verb, func(t *testing.T) {
			f := newRecoveryFixture(t)
			fixture := verb
			if verb == harnessAccountsVerb {
				fixture += "-accounts-and-broker"
			}
			canonical, err := os.ReadFile(filepath.Join("..", "members", "testdata", fixture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(canonical)
			digest := hex.EncodeToString(sum[:])
			var plan members.Plan
			if err = json.Unmarshal(canonical, &plan); err != nil {
				t.Fatal(err)
			}
			pairedUID := plan.Steps[0].UID
			if verb != harnessAccountsVerb {
				var policy members.HarnessPolicyRecord
				if err = json.Unmarshal([]byte(plan.Steps[0].Content), &policy); err != nil {
					t.Fatal(err)
				}
				pairedUID = policy.HQUID
			}
			pair, err := readOwnerPairState(f.dir)
			if err != nil {
				t.Fatal(err)
			}
			pair.UID = pairedUID
			if err = pair.save(f.dir); err != nil {
				t.Fatal(err)
			}
			testPlanRole(t, fmt.Sprint(pairedUID))
			f.check = func(id, got string, uid int) (string, error) {
				if uid != pairedUID || id != approvePlanID || got != digest {
					return "", errRecoveryPlan
				}
				return string(canonical), nil
			}
			send := func(op string, c recoveryChallenge, signature string) Response {
				req := f.request(op, c, signature)
				req.Verb, req.PlanDigest = verb, digest
				return f.run(t, pairedUID, req, f.client)
			}
			wrongUID := f.request("challenge", recoveryChallenge{}, "")
			wrongUID.Verb, wrongUID.PlanDigest = verb, digest
			if f.run(t, pairedUID+1, wrongUID, f.client).OK {
				t.Fatal("another UID used the dedicated pairing")
			}
			issued := send("challenge", recoveryChallenge{}, "")
			var c recoveryChallenge
			if !issued.OK || json.Unmarshal(issued.Body, &c) != nil || c.Action != verb {
				t.Fatal("challenge failed", issued.Diagnostic)
			}
			var handoff struct {
				Canonical string `json:"plan_canonical"`
			}
			if json.Unmarshal(issued.Body, &handoff) != nil || handoff.Canonical != string(canonical) || c.Digest != digest {
				t.Fatal("handoff did not bind the exact published canonical bytes")
			}
			for _, old := range []string{recoveryVerb, "hq-service-upgrade", "first-hq-provision", harnessInstallVerb, harnessRetireVerb, harnessAccountsVerb} {
				if old == verb {
					continue
				}
				other := c
				other.Action = old
				if send("approve", c, f.proof(t, other)).OK {
					t.Fatalf("accepted %s proof as %s", old, verb)
				}
			}
			otherVerb := harnessRetireVerb
			if verb == harnessRetireVerb {
				otherVerb = harnessInstallVerb
			}
			cancelOther := f.request("cancel", c, "")
			cancelOther.Verb, cancelOther.PlanDigest = otherVerb, digest
			if f.run(t, pairedUID, cancelOther, f.client).OK {
				t.Fatal("another action cancelled the pending approval")
			}
			if !send("approve", c, f.proof(t, c)).OK {
				t.Fatal("matching purpose refused")
			}
			raw, e := os.ReadFile(members.ApprovalPath(f.dir, approvePlanID))
			var a members.Approval
			if e != nil || json.Unmarshal(raw, &a) != nil || a.Purpose != verb || a.PairCommitment != pairCommitment(pair) || a.PlanDigest != digest || a.MachineFingerprint != fmt.Sprintf("%x", sha256.Sum256(f.machine)) {
				t.Fatal("typed approval not bound to pairing", e)
			}
			if send("approve", c, f.proof(t, c)).OK {
				t.Fatal("replayed owner signature")
			}
			reissued := send("challenge", recoveryChallenge{}, "")
			if !reissued.OK || json.Unmarshal(reissued.Body, &c) != nil {
				t.Fatal("second challenge failed")
			}
			if err := revokeHQ(f.dir); err != nil {
				t.Fatal(err)
			}
			if send("approve", c, f.proof(t, c)).OK {
				t.Fatal("accepted a proof after administrative revocation")
			}
		})
	}
}
