//go:build unix

package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/target"
)

// All host lookups and privileged mutations go through the fixture. Only its
// temporary home contains real files, including the production approval store.
type firstHQHost struct {
	home      string
	exists    bool
	lookupErr error
}

func (h *firstHQHost) Account(name string) (members.Account, bool, error) {
	if h.lookupErr != nil {
		return members.Account{}, false, h.lookupErr
	}
	if h.exists && name == members.DarwinHQAccount {
		return members.Account{Name: name, UID: 320, GID: 320, Group: name, Home: members.HQHome("darwin", name), Shell: members.DarwinNoLoginShell, DarwinRole: "Agent Bot HQ"}, true, nil
	}
	return members.Account{}, false, nil
}
func (h *firstHQHost) ReadFile(p string) (string, bool, error) {
	if !strings.HasPrefix(p, h.home+string(filepath.Separator)) {
		return "", false, errors.New("unexpected host file")
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return string(raw), err == nil, err
}
func (h *firstHQHost) Lstat(p string) (members.Entry, bool, error) {
	if p == members.HQHome("darwin", members.DarwinHQAccount) && h.exists {
		return members.Entry{Dir: true, Owner: members.DarwinHQAccount, Mode: 0700}, true, nil
	}
	if !strings.HasPrefix(p, h.home+string(filepath.Separator)) {
		return members.Entry{}, false, nil
	}
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return members.Entry{}, false, nil
	}
	if err != nil {
		return members.Entry{}, false, err
	}
	return members.Entry{Dir: info.IsDir(), Regular: info.Mode().IsRegular(), Owner: "admin", Mode: uint32(info.Mode().Perm())}, true, nil
}
func (h *firstHQHost) List(string) ([]string, error) {
	return nil, errors.New("unexpected directory listing")
}

type firstHQFixture struct {
	deps        Deps
	host        *firstHQHost
	key         *ecdsa.PrivateKey
	id, home    string
	now         time.Time
	membersDeps members.Deps
}

func (f *firstHQFixture) run(t *testing.T, args ...string) cli.Result {
	t.Helper()
	return Command(f.deps).Run(cli.Context{}, append([]string{"first-hq"}, args...))
}
func firstHQContext() cli.Context {
	return cli.Context{Detect: func() (target.Host, error) { return target.Host{Target: target.DarwinARM64}, nil }}
}
func newFirstHQFixture(t *testing.T) *firstHQFixture {
	t.Helper()
	home := t.TempDir()
	f := &firstHQFixture{home: home, deps: owner(home), host: &firstHQHost{home: home}, id: "plan-20261119T020000Z-abcd", now: time.Now().UTC().Truncate(time.Second)}
	f.deps.Caller = func() (Caller, error) {
		return Caller{Username: "admin", UID: 501, PrefixOwner: "admin", DarwinAdmin: true, Home: home, RegisteredHome: home}, nil
	}
	f.deps.Now = func() time.Time { return f.now }
	f.deps.MembersHost = f.host
	var err error
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := signedOwnerReply(t, f.key, ownerPairChallenge{})
	r := Command(f.deps).Run(cli.Context{}, []string{"pair", "--pin-owner", pin})
	requireFirstHQOK(t, r)
	machine, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir(home), "daemon.pub"), machine, 0600); err != nil {
		t.Fatal(err)
	}
	f.membersDeps = members.Deps{Deps: f.deps.Deps, Host: func() members.Host { return f.host }}
	f.membersDeps.Getenv = func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	}
	f.membersDeps.Username = func() (string, error) { return "admin", nil }
	f.membersDeps.NewPlanID = func(time.Time) (string, error) { return f.id, nil }
	requireFirstHQOK(t, members.Command(f.membersDeps).Run(firstHQContext(), []string{"plan"}))
	return f
}
func requireFirstHQOK(t *testing.T, r cli.Result) {
	t.Helper()
	if r.Diagnostic != nil {
		t.Fatal(r.Diagnostic.Message)
	}
}
func requireFirstHQRefused(t *testing.T, r cli.Result) {
	t.Helper()
	if r.Diagnostic == nil {
		t.Fatal("expected refusal", r)
	}
}
func (f *firstHQFixture) export(t *testing.T) firstHQChallenge {
	t.Helper()
	r := f.run(t, "export", f.id)
	requireFirstHQOK(t, r)
	data, err := r.Records[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var c firstHQChallenge
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	canonical, ok := r.Records[0].Get("plan_canonical")
	if !ok {
		t.Fatal("missing canonical plan")
	}
	raw := canonical.(string)
	sum := sha256.Sum256([]byte(raw))
	if !strings.HasSuffix(raw, "\n") || c.Digest != hex.EncodeToString(sum[:]) || !c.valid() {
		t.Fatalf("invalid exported plan or challenge %s", data)
	}
	return c
}
func (f *firstHQFixture) proof(t *testing.T, key *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	sum := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(pub), "signature": base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirstHQTransferRejectsInvalidProofAndConsumesOnce(t *testing.T) {
	f := newFirstHQFixture(t)
	c := f.export(t)
	prove := func(c firstHQChallenge, key *ecdsa.PrivateKey) cli.Result {
		return f.run(t, "approve", f.id, "--proof-file", f.proof(t, key, c.message()))
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requireFirstHQRefused(t, prove(c, other))
	for _, change := range []func(*firstHQChallenge){
		func(c *firstHQChallenge) { c.Action = "machine-pair" },
		func(c *firstHQChallenge) { c.Machine = strings.Repeat("0", 64) },
		func(c *firstHQChallenge) { c.ID = "plan-20261119T020000Z-beef" },
		func(c *firstHQChallenge) { c.Digest = strings.Repeat("1", 64) },
		func(c *firstHQChallenge) { c.Nonce = strings.Repeat("2", 64) },
		func(c *firstHQChallenge) { c.Expires-- },
	} {
		changed := c
		change(&changed)
		requireFirstHQRefused(t, prove(changed, f.key))
	}
	c2 := f.export(t)
	requireFirstHQRefused(t, prove(c, f.key))
	requireFirstHQOK(t, f.run(t, "cancel", f.id))
	requireFirstHQRefused(t, prove(c2, f.key))
	c = f.export(t)
	f.now = f.now.Add(ownerChallengeTTL * time.Second)
	requireFirstHQRefused(t, prove(c, f.key))
	c = f.export(t)
	p := f.proof(t, f.key, c.message())
	var wg sync.WaitGroup
	out := make(chan cli.Result, 4)
	for i := 0; i < cap(out); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); out <- f.run(t, "approve", f.id, "--proof-file", p) }()
	}
	wg.Wait()
	close(out)
	count := 0
	for r := range out {
		if r.Diagnostic == nil {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("successful concurrent approvals = %d", count)
	}
	raw, err := os.ReadFile(members.ApprovalPath(stateDir(f.home), f.id))
	if err != nil {
		t.Fatal(err)
	}
	var a members.Approval
	if err := json.Unmarshal(raw, &a); err != nil || a.PlanID != f.id || a.PlanDigest != c.Digest {
		t.Fatalf("approval %#v, %v", a, err)
	}
}

func TestFirstHQTransferRevalidatesPlanHostAndPin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *firstHQFixture)
	}{
		{"account exists", func(t *testing.T, f *firstHQFixture) { f.host.exists = true }},
		{"account lookup error", func(t *testing.T, f *firstHQFixture) { f.host.lookupErr = errors.New("directory unavailable") }},
		{"machine key changed", func(t *testing.T, f *firstHQFixture) {
			if err := os.WriteFile(filepath.Join(stateDir(f.home), "daemon.pub"), make([]byte, 32), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"owner pin absent", func(t *testing.T, f *firstHQFixture) {
			if err := os.Remove(filepath.Join(stateDir(f.home), ownerPairFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"HQ was revoked", func(t *testing.T, f *firstHQFixture) {
			if err := os.WriteFile(filepath.Join(stateDir(f.home), "peers", "agent-daemon.revoked"), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed saved plan", func(t *testing.T, f *firstHQFixture) {
			requireFirstHQOK(t, members.Command(f.membersDeps).Run(firstHQContext(), []string{"plan", "--members", "_abm-other"}))
		}},
		{"foreign prefix", func(t *testing.T, f *firstHQFixture) {
			caller, _ := f.deps.Caller()
			caller.PrefixOwner = "other"
			f.deps.Caller = func() (Caller, error) { return caller, nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFirstHQFixture(t)
			c := f.export(t)
			p := f.proof(t, f.key, c.message())
			tc.change(t, f)
			requireFirstHQRefused(t, f.run(t, "approve", f.id, "--proof-file", p))
			if _, err := os.Stat(members.ApprovalPath(stateDir(f.home), f.id)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unexpected approval", err)
			}
		})
	}
}

func TestFirstHQApprovalWriteFailureConsumesChallenge(t *testing.T) {
	f := newFirstHQFixture(t)
	c := f.export(t)
	p := f.proof(t, f.key, c.message())
	blocker := filepath.Join(stateDir(f.home), "members")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	requireFirstHQRefused(t, f.run(t, "approve", f.id, "--proof-file", p))
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	requireFirstHQRefused(t, f.run(t, "approve", f.id, "--proof-file", p))
}

// The embedded nil interface makes an unexpected privileged operation fail the
// test. The expected operations only change the synthetic host and receipt.
type firstHQRoot struct {
	members.Root
	host    *firstHQHost
	receipt members.Receipt
}

func (r *firstHQRoot) CreateHQAccount(name string) error {
	if name != members.DarwinHQAccount || r.host.exists {
		return errors.New("unexpected account creation")
	}
	r.host.exists = true
	return nil
}
func (r *firstHQRoot) PasswordField(string) (string, bool, error) { return "*", true, nil }
func (r *firstHQRoot) SetMode(path string, mode uint32) error {
	if path != members.HQHome("darwin", members.DarwinHQAccount) || mode != 0700 {
		return errors.New("unexpected account permissions")
	}
	return nil
}
func (r *firstHQRoot) Claim(id string, raw []byte) (bool, error) {
	if r.receipt.PlanID != "" {
		return false, nil
	}
	return true, r.Finish(id, raw)
}
func (r *firstHQRoot) Finish(_ string, raw []byte) error { return json.Unmarshal(raw, &r.receipt) }

func TestFirstHQTransferFeedsHumanMembersApply(t *testing.T) {
	f := newFirstHQFixture(t)
	c := f.export(t)
	root := &firstHQRoot{host: f.host}
	d := f.membersDeps
	d.Euid = func() int { return 0 }
	d.ProcessEnv = func() []string { return []string{"SUDO_UID=501"} }
	d.Ancestors = func() []map[string]string { return nil }
	d.LookupUID = func(string) (string, string, error) { return "admin", f.home, nil }
	d.DaemonState = func(owner, home string) (string, string, error) { return stateDir(home), owner, nil }
	d.Root = func() members.Root { return root }
	apply := func() cli.Result { return members.Command(d).Run(firstHQContext(), []string{"apply", f.id}) }
	requireFirstHQRefused(t, apply())
	requireFirstHQOK(t, f.run(t, "approve", f.id, "--proof-file", f.proof(t, f.key, c.message())))
	if f.host.exists || root.receipt.PlanID != "" {
		t.Fatal("approval mutated the host or claimed a receipt")
	}
	f.host.exists = true
	requireFirstHQRefused(t, apply())
	if root.receipt.PlanID != "" {
		t.Fatal("changed host reached privileged operations")
	}
	f.host.exists = false
	requireFirstHQOK(t, apply())
	if !f.host.exists || root.receipt.Result != "applied" || root.receipt.PlanDigest != c.Digest {
		t.Fatalf("missing applied role or receipt: %+v", root.receipt)
	}
	f.host.exists = false
	requireFirstHQRefused(t, apply())
	if f.host.exists {
		t.Fatal("a used approval recreated a removed role")
	}
}

func TestFirstHQUsesDefaultCLITransferJSON(t *testing.T) {
	f := newFirstHQFixture(t)
	var stdout, stderr bytes.Buffer
	app := cli.App{Name: "managed-machine", Version: "test", GOOS: "darwin", Commands: []cli.Command{Command(f.deps)}, Stdout: &stdout, Stderr: &stderr}
	if code := app.Run([]string{"daemon", "first-hq", "export", f.id}); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	wire := stdout.Bytes()
	var c firstHQChallenge
	var env map[string]json.RawMessage
	if bytes.Count(wire, []byte("\n")) != 1 || json.Unmarshal(wire, &env) != nil || len(env) != 7 || json.Unmarshal(wire, &c) != nil || !c.valid() {
		t.Fatalf("default command must export one flat JSON object: %q", wire)
	}
	var canonical string
	if err := json.Unmarshal(env["plan_canonical"], &canonical); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(canonical)); hex.EncodeToString(sum[:]) != c.Digest || !strings.HasSuffix(canonical, "\n") {
		t.Fatal("rendered canonical bytes do not match the exported digest")
	}
	stdout.Reset()
	if code := app.Run([]string{"daemon", "first-hq", "approve", f.id, "--proof-file", f.proof(t, f.key, c.message())}); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
}
func TestFirstHQProofRequiresBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "large")
	if err := os.WriteFile(big, make([]byte, 1025), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link")
	if err := os.Symlink(big, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, fifo, big, symlink} {
		if _, err := readFirstHQProof(path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
}
