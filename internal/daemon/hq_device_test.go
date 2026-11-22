//go:build darwin || linux

package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
)

func fixtureDeviceKey(t *testing.T) (*ecdsa.PrivateKey, keydIdentity) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := deviceJWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
	return key, keydIdentity{JWK: j, Thumbprint: j.thumbprint(), Storage: "hardware", Generation: 1}
}

func TestBridgeV2DelegationBindsReportFields(t *testing.T) {
	d := deviceDelegation{Option: "qualification-host-report-v2", Epoch: "epoch", ReportBase64URL: "cmVwb3J0", HostID: "host", SignerID: "signer"}
	transcript := string(d.transcript())
	if !strings.Contains(transcript, "qualification-host-report-v2") ||
		!strings.HasSuffix(transcript, "report_base64url\ncmVwb3J0\nhost_id\nhost\nsigner_id\nsigner") {
		t.Fatal("v2 report bytes or host identity are not signed into delegation")
	}
}

func fixtureDeviceProof(t *testing.T, key *ecdsa.PrivateKey, id keydIdentity, at time.Time, audience string) string {
	t.Helper()
	jti, err := newNonce()
	if err != nil {
		t.Fatal(err)
	}
	return fixtureDeviceJWS(t, key, map[string]any{"alg": "ES256", "typ": "ab-enroll+jwt", "jwk": id.JWK}, map[string]any{"aud": audience, "iat": at.Unix(), "jti": jti})
}
func fixtureDeviceJWS(t *testing.T, key *ecdsa.PrivateKey, headerFields, claims map[string]any) string {
	t.Helper()
	pack := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := pack(headerFields)
	body := pack(claims)
	input := header + "." + body
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type observedDeviceWrite struct {
	net.Conn
	started chan struct{}
}

func (c *observedDeviceWrite) Write(p []byte) (int, error) { close(c.started); return c.Conn.Write(p) }

func TestHQDeviceSignedChannel(t *testing.T) {
	testPlanRole(t, "331")
	root := t.TempDir()
	dir := stateDir(root)
	if _, err := ensureStateDirAndPeers(dir); err != nil {
		t.Fatal(err)
	}
	machine, priv := keyPair(t)
	hq, caller := keyPair(t)
	dev, id := fixtureDeviceKey(t)
	ownerPublic, err := dev.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ownerPairState{Owner: base64.StdEncoding.EncodeToString(ownerPublic), Machine: hex.EncodeToString(machine), HQ: hex.EncodeToString(hq), UID: 331}).save(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "daemon.pub"), machine, 0600); err != nil {
		t.Fatal(err)
	}
	// Existing lock created by the administrator's enrollment flow.
	unlock, err := lockOwnerPairing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = unlock(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	calls := 0
	var localPathIssue error
	sessionKey, ephemeral := fixtureDeviceKey(t)
	tokenJTI, err := newNonce()
	if err != nil {
		t.Fatal(err)
	}
	provider := func(ctx context.Context, _ string, d deviceDelegation) ([]byte, error) {
		calls++
		sig, err := base64.StdEncoding.DecodeString(d.Signature)
		if err != nil || !ed25519.Verify(machine, d.transcript(), sig) || d.Machine != base64.StdEncoding.EncodeToString(machine) ||
			d.HQ != base64.StdEncoding.EncodeToString(hq) || d.UID != 331 || !deviceNonce.MatchString(d.Nonce) || d.Timestamp != now.Unix() {
			t.Error("unexpected administrative delegation")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("unbounded provider call")
		}
		if localPathIssue != nil {
			return nil, localPathIssue
		}
		result := id
		switch d.Option {
		case "bind-enrollment":
			raw, _ := deviceSegment(d.ReceiptBody)
			sum := sha256.Sum256(raw)
			result.DeviceID = "device_fixture"
			result.ReceiptJTI = d.ReceiptJTI
			result.ReceiptSHA = hex.EncodeToString(sum[:])
		case "access-assertion":
			result.Assertion = fixtureDeviceJWS(t, dev, map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{"iss": "device_fixture", "sub": "device_fixture", "aud": "https://agents.true-line.ai/oauth/token", "iat": now.Unix(), "exp": now.Unix() + 120, "jti": tokenJTI, "cnf": map[string]any{"jwk": ephemeral.JWK}})
		case "whoami":
			if d.Session != ephemeral.Thumbprint {
				return nil, errHQDevice
			}
			proof := fixtureDeviceJWS(t, sessionKey, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": ephemeral.JWK}, map[string]any{"htm": "GET", "htu": deviceWhoamiURL, "ath": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "iat": now.Unix(), "jti": tokenJTI})
			return json.Marshal(map[string]string{"session": d.Session, "proof": proof})
		case "bind-access":
			return json.Marshal(map[string]any{"expires_at": now.Unix() + 60, "session": ephemeral.Thumbprint})
		case "enrollment-proof":
			result.Proof = fixtureDeviceProof(t, dev, id, now, deviceEnrollmentAudience)
		}
		return json.Marshal(result)
	}
	g := Gate{Dir: dir, Now: func() time.Time { return now }}
	h := Hooks{HQDevice: func(req Request) Response {
		return requestHQDevice(context.Background(), root, priv, req, func() time.Time { return now }, provider)
	}}
	// A net.Pipe carries the normal signed line/response. Only the host peer
	// resolver is replaced with a disposable dedicated-account UID.
	exchange := func(req Request, key ed25519.PrivateKey, uid int) Response {
		client, server := net.Pipe()
		defer client.Close()
		go handleConn(server, &g, priv, func(net.Conn) (int, error) { return uid, nil }, h)
		if _, err := client.Write(append(signed(t, key, req), '\n')); err != nil {
			t.Fatal(err)
		}
		var reply Response
		if err := json.NewDecoder(client).Decode(&reply); err != nil {
			t.Fatal(err)
		}
		if !VerifyResponse(machine, reply) || reply.RequestNonce != req.Nonce {
			t.Fatal("unverified response")
		}
		return reply
	}
	fresh := func(option string) Request {
		n, err := newNonce()
		if err != nil {
			t.Fatal(err)
		}
		r := Request{Verb: deviceVerb, Option: option, Nonce: n, Timestamp: now.Unix()}
		if option == "whoami" {
			r.DeviceSession = ephemeral.Thumbprint
		}
		if option != "identity" {
			r.HQEpoch = "legacy"
		}
		return r
	}
	req := fresh("identity")
	if r := exchange(req, caller, 331); !r.OK || r.State != "identity" || bytes.Contains(r.Body, []byte("proof")) {
		t.Fatal("identity lookup failed or returned a proof")
	}
	if r := exchange(req, caller, 331); r.OK {
		t.Fatal("repeated identity request accepted")
	}
	localPathIssue = errors.New("directory /fixture/Cellar mode 0775 allows group 0 to write")
	if r, want := exchange(fresh("identity"), caller, 331), deviceUnavailable(); r.OK ||
		r.Diagnostic != want.Diagnostic || r.Message != want.Message || len(r.Body) != 0 {
		t.Fatal("paired reply did not retain the bounded custody refusal")
	}
	localPathIssue = nil
	if r := exchange(fresh("enrollment-proof"), caller, 331); !r.OK || r.State != "proved" {
		t.Fatal("enrollment proof failed")
	}
	// The fake admin provider supplies only the production public result shape.
	// Signature/pending-receipt acceptance is the provider's separate boundary.
	for _, step := range []struct{ option, state string }{{"bind-enrollment", "bound"}, {"access-assertion", "asserted"}, {"bind-access", "access-bound"}, {"whoami", "whoami-proved"}} {
		q := fresh(step.option)
		if strings.HasPrefix(q.Option, "bind-") {
			receipt := map[string]any{"token_type": "DPoP", "access_token": "disposable-token", "expires_in": 60}
			q.ReceiptJTI = tokenJTI
			if q.Option == "bind-enrollment" {
				receipt = map[string]any{"device_id": "device_fixture", "jkt": id.Thumbprint}
				q.ReceiptJTI = "enroll-v1:" + strings.Repeat("a", 64)
			}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			q.ReceiptBody = base64.RawURLEncoding.EncodeToString(raw)
			q.ReceiptKID = "fixture"
			q.ReceiptSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}
		r := exchange(q, caller, 331)
		if !r.OK || r.State != step.state || !bytes.Contains(r.Body, []byte(`"hq_epoch":"legacy"`)) || bytes.Contains(r.Body, []byte("disposable-token")) {
			t.Fatalf("failed %s: %s", step.option, r.State)
		}
	}
	_, other := keyPair(t)
	if exchange(fresh("identity"), other, 331).OK || exchange(fresh("identity"), caller, 332).OK {
		t.Fatal("unbound caller accepted")
	}
	for _, option := range []string{"sign", "approval", "dpop", "rotate", "create"} {
		if exchange(fresh(option), caller, 331).OK {
			t.Fatal("undeclared purpose accepted")
		}
	}
	q := fresh("whoami")
	q.Target = "destination"
	if exchange(q, caller, 331).OK || exchange(fresh("whoami"), caller, 332).OK {
		t.Fatal("out-of-contract lookup accepted")
	}
	access := fresh("access-assertion")
	access.Target = "caller-controlled-key"
	if exchange(access, caller, 331).OK {
		t.Fatal("assertion issued for HQ-controlled key")
	}
	deps := owner(root)
	if r := run(deps, cli.Context{}, []string{"revoke-hq"}); r.Diagnostic == nil {
		t.Fatal("non-administrative caller revoked HQ")
	}
	deps.Caller = func() (Caller, error) {
		return Caller{Username: "admin", UID: 501, Home: root, RegisteredHome: root, PrefixOwner: "admin", DarwinAdmin: true}, nil
	}
	queued, code, _ := g.verify(331, signed(t, caller, fresh("whoami")))
	if code != "" {
		t.Fatal(code)
	}
	open, server := net.Pipe()
	defer open.Close()
	go handleConn(server, &g, priv, func(net.Conn) (int, error) { return 331, nil }, h)
	// This response was committed to a still-blocked socket write while
	// authorized. Revocation publishes immediately, then waits for that write.
	delivery, out := net.Pipe()
	defer delivery.Close()
	started := make(chan struct{})
	deliveryReq := fresh("identity")
	go handleConn(&observedDeviceWrite{out, started}, &g, priv, func(net.Conn) (int, error) { return 331, nil }, h)
	if _, err := delivery.Write(append(signed(t, caller, deliveryReq), '\n')); err != nil {
		t.Fatal(err)
	}
	<-started
	entered, finish := make(chan struct{}), make(chan struct{})
	inFlight := make(chan Response, 1)
	go func() {
		inFlight <- requestHQDevice(context.Background(), root, priv, queued, func() time.Time { return now }, func(ctx context.Context, _ string, _ deviceDelegation) ([]byte, error) {
			close(entered)
			select {
			case <-finish:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			result := id
			result.Proof = fixtureDeviceProof(t, dev, id, now, deviceEnrollmentAudience)
			return json.Marshal(result)
		})
	}()
	<-entered
	revoked := make(chan cli.Result, 1)
	go func() { revoked <- run(deps, cli.Context{}, []string{"revoke-hq"}) }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Lstat(filepath.Join(dir, "peers", "agent-daemon.revoked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("revocation blocked behind pending provider")
		}
		time.Sleep(time.Millisecond)
	}
	close(finish)
	if (<-inFlight).OK {
		t.Fatal("released result after revocation")
	}
	select {
	case <-revoked:
		t.Fatal("administrator revoke completed with an authorized write still in progress")
	default:
	}
	var committed Response
	if json.NewDecoder(delivery).Decode(&committed) != nil || !VerifyResponse(machine, committed) || !committed.OK {
		t.Fatal("invalid pre-cutoff response")
	}
	if r := <-revoked; r.Diagnostic != nil {
		t.Fatal(r.Diagnostic.Message)
	}
	if r := h.HQDevice(queued); r.OK {
		t.Fatal("queued work reached provider after revocation")
	}
	deferredReq := fresh("whoami")
	if err := open.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := open.Write(append(signed(t, caller, deferredReq), '\n')); err != nil {
		t.Fatal(err)
	}
	var denied Response
	if json.NewDecoder(open).Decode(&denied) != nil || !VerifyResponse(machine, denied) || denied.OK {
		t.Fatal("preexisting connection bypassed revocation")
	}
	state, err := readOwnerPairState(dir)
	if err != nil || state == nil || state.HQ != "" || state.HQEpoch != "" || state.Owner != base64.StdEncoding.EncodeToString(ownerPublic) {
		t.Fatal("revocation failed to retire HQ while retaining owner")
	}
	if r := run(deps, cli.Context{}, []string{"revoke-hq"}); r.Diagnostic != nil {
		t.Fatal("repeat revocation failed", r.Diagnostic)
	}
	if exchange(fresh("whoami"), caller, 331).OK || calls != 8 {
		t.Fatalf("unexpected custody calls %d", calls)
	}
}

func TestHQDeviceInputAndProviderOutput(t *testing.T) {
	now := time.Now()
	key, id := fixtureDeviceKey(t)
	req := Request{Verb: deviceVerb, Option: "enrollment-proof", HQEpoch: "legacy", Nonce: "abcdefghijklmnop", Timestamp: now.Unix()}
	_, hq := keyPair(t)
	valid := signed(t, hq, req)
	for _, extra := range []string{`,"nonce":"abcdefghijklmnop"`, `,"name":null`, `,"ephemeral_x":""`, `,"message":"raw"`} {
		raw := append(bytes.Clone(valid[:len(valid)-1]), []byte(extra+"}")...)
		if diag, _ := deviceFields(req, raw); diag == "" {
			t.Fatalf("accepted extra or duplicate field %s", extra)
		}
	}
	if diag, _ := deviceFields(req, append(bytes.Clone(valid), []byte("{}")...)); diag == "" {
		t.Fatal("accepted trailing object")
	}
	id.Proof = fixtureDeviceProof(t, key, id, now, "https://unapproved.invalid/oauth/device_authorization")
	raw, _ := json.Marshal(id)
	if _, _, err := deviceResult(req, raw, now, "legacy"); err == nil {
		t.Fatal("accepted proof for a different audience")
	}
	id.Proof = fixtureDeviceProof(t, key, id, now, deviceEnrollmentAudience)
	raw, _ = json.Marshal(id)
	if _, _, err := deviceResult(req, raw, now.Add(time.Minute), "legacy"); err == nil {
		t.Fatal("accepted stale proof")
	}
	pr := bytes.Replace(raw, []byte(`"jwk":{`), []byte(`"jwk":{"d":"private",`), 1)
	if _, _, err := deviceResult(req, pr, now, "legacy"); err == nil {
		t.Fatal("accepted private key field")
	}
	id.Thumbprint = strings.Repeat("A", 43)
	raw, _ = json.Marshal(id)
	if _, _, err := deviceResult(req, raw, now, "legacy"); err == nil {
		t.Fatal("accepted mismatched thumbprint")
	}
}

func TestHQDeviceMissingStateIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := lockDevicePairing(dir); err == nil {
		t.Fatal("missing lock accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "peer.pub"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := currentDevicePairing(dir); err == nil {
		t.Fatal("legacy terminal became HQ")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "peer.pub" {
		t.Fatal("device lookup modified unprovisioned state")
	}
}

func TestWhoamiPurposeAndSessionBoundResult(t *testing.T) {
	now := time.Unix(100, 0)
	key, id := fixtureDeviceKey(t)
	_, other := fixtureDeviceKey(t)
	req := Request{Verb: deviceVerb, Option: "whoami", HQEpoch: "legacy", DeviceSession: id.Thumbprint, Timestamp: now.Unix(), Nonce: "abcdefghijklmnop"}
	_, role := keyPair(t)
	wire := signed(t, role, req)
	if code, _ := deviceFields(req, wire); code != "" {
		t.Fatal("valid selector refused")
	}
	for _, extra := range []string{"device_id", "url", "method", "body", "ath", "jti", "jwk", "proof_nonce"} {
		raw := append(bytes.Clone(wire[:len(wire)-1]), []byte(`,"`+extra+`":"fixture"}`)...)
		if code, _ := deviceFields(req, raw); code == "" {
			t.Errorf("accepted extra field %s", extra)
		}
	}
	want := "\nhq_epoch\nlegacy\nsession\n" + id.Thumbprint
	if !strings.HasSuffix(string(canonical(req)), want) || !strings.HasSuffix(string((deviceDelegation{Option: "whoami", Epoch: "legacy", Session: id.Thumbprint}).transcript()), want) {
		t.Fatal("selector and epoch must be bound on both hops")
	}
	header := map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": id.JWK}
	claims := map[string]any{"htm": "GET", "htu": deviceWhoamiURL, "ath": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "jti": base64.RawURLEncoding.EncodeToString(make([]byte, 16)), "iat": now.Unix()}
	verify := func(request Request, replySelector string) bool {
		t.Helper()
		data, _ := json.Marshal(map[string]string{"session": replySelector, "proof": fixtureDeviceJWS(t, key, header, claims)})
		_, state, err := deviceResult(request, data, now, "legacy")
		return err == nil && state == "whoami-proved"
	}
	if !verify(req, id.Thumbprint) || verify(req, other.Thumbprint) {
		t.Fatal("response selector mismatch")
	}
	otherReq := req
	otherReq.DeviceSession = other.Thumbprint
	if verify(otherReq, other.Thumbprint) {
		t.Fatal("proof key does not match bound session")
	}
	for field, value := range map[string]any{"htm": "HEAD", "htu": deviceWhoamiURL + "?format=json", "ath": "bad", "iat": now.Unix() - 31, "jti": "bad", "extra": "field"} {
		previous, exists := claims[field]
		claims[field] = value
		if verify(req, id.Thumbprint) {
			t.Errorf("accepted invalid %s claim", field)
		}
		if exists {
			claims[field] = previous
		} else {
			delete(claims, field)
		}
	}
}
