//go:build darwin || linux

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/statedir"
	"golang.org/x/sys/unix"
)

func testPlanRole(t *testing.T, uid string) {
	t.Helper()
	role := members.DefaultHQAccount
	if runtime.GOOS == "darwin" {
		role = members.DarwinHQAccount
	}
	before := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		if name != role {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Username: role, Uid: uid}, nil
	}
	t.Cleanup(func() { lookupUser = before })
}

func TestMembersPlansBoundClient(t *testing.T) {
	testPlanRole(t, "777")
	hq, key := keyPair(t)
	terminal, terminalKey := keyPair(t)
	pairing := Pairing{Live: hq, Extra: []ed25519.PublicKey{terminal}, Terminal: terminal, AgentDaemon: hq, AgentDaemonBound: true, AgentDaemonUID: 777, OwnerPresenceRequired: true}
	now := time.Now()
	req := Request{Verb: membersPlansVerb, Option: "list", Timestamp: now.Unix(), Nonce: "lookup"}
	unbound := pairing
	unbound.AgentDaemonBound = false
	revoked := pairing
	revoked.Live = nil
	unknown, unknownKey := keyPair(t)
	staged := pairing
	staged.Staged = unknown
	for _, tc := range []struct {
		name   string
		p      Pairing
		caller ed25519.PrivateKey
		uid    int
		ok     bool
	}{
		{"enrolled", pairing, key, 777, true}, {"wrong-uid", pairing, key, 778, false},
		{"terminal", pairing, terminalKey, 777, false}, {"unknown", pairing, unknownKey, 777, false},
		{"unbound", unbound, key, 777, false}, {"revoked", revoked, key, 777, false}, {"staged", staged, unknownKey, 777, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := Gate{Pairing: tc.p}
			_, diagnostic, _ := gate.verify(tc.uid, signed(t, tc.caller, req))
			if (diagnostic == "") != tc.ok {
				t.Fatalf("unexpected verdict %q", diagnostic)
			}
		})
	}
	t.Run("legacy binding for custom account", func(t *testing.T) {
		// The legacy administrator may bind the same key to an arbitrary UID.
		// Matching the socket and enrollment UID still cannot identify HQ.
		testPlanRole(t, "778")
		legacy := pairing
		legacy.OwnerPresenceRequired = false
		if _, id, _ := (&Gate{Pairing: legacy}).verify(777, signed(t, key, req)); id == "" {
			t.Fatal("accepted legacy key bound to a different OS account")
		}
	})
	t.Run("missing role", func(t *testing.T) {
		before := lookupUser
		lookupUser = func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }
		defer func() { lookupUser = before }()
		if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, req)); id == "" {
			t.Fatal("accepted missing dedicated role")
		}
	})
	for _, tc := range []struct{ option, id string }{{"get", ""}, {"list", "../../private"}, {"get", "missing"}, {"delete", approvePlanID}} {
		r := req
		r.Option, r.PlanID = tc.option, tc.id
		if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, r)); id == "" {
			t.Fatalf("accepted %s %s", tc.option, tc.id)
		}
	}
	for _, extra := range []string{`"target":null`, `"plan_digest":null`, `"floor":null`, `"plan_id":null`, `"Name":""`} {
		b := signed(t, key, req)
		b = []byte("{" + extra + "," + string(b[1:]))
		if _, id, _ := (&Gate{Pairing: pairing}).verify(777, b); id == "" {
			t.Fatal("accepted an undeclared field")
		}
	}
	gate := Gate{Pairing: pairing}
	r := Request{Verb: approveMembersVerb, PlanID: approvePlanID, PlanDigest: approveDigest, Timestamp: now.Unix(), Nonce: "approval"}
	if _, id, _ := gate.verify(777, signed(t, key, r)); id == "" {
		t.Fatal("lookup enabled approval")
	}
}

func TestMembersPlansReadOnly(t *testing.T) {
	testPlanRole(t, "777")
	home := t.TempDir()
	raw, err := readMembersPlans(home, "list", "")
	if err != nil || string(raw) != `{"plan_ids":[]}` {
		t.Fatalf("empty list: %s %v", raw, err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatal("listing created state")
	}
	state, err := statedir.Path(runtime.GOOS, func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := approvePlanID
	file := filepath.Join(dir, id+".json")
	saved := members.Saved{PlanID: id, CreatedAt: "unshared-metadata", Plan: members.Plan{HQAccount: "_agent-bot-hq", Steps: []members.Step{{Content: "<plist>\n"}}}}
	saved.PlanDigest, err = saved.Plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	write := func(p string, b []byte) {
		t.Helper()
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	write(file, data)
	canonical, _ := saved.Plan.Canonical()
	response := signedMembersPlan(t, home, id)
	if !response.OK || bytes.Contains(response.Body, []byte(saved.CreatedAt)) {
		t.Fatal("invalid signed response or leaked saved metadata")
	}
	var body struct {
		ID        string `json:"plan_id"`
		Digest    string `json:"plan_digest"`
		Canonical string `json:"plan_canonical"`
	}
	if err := json.Unmarshal(response.Body, &body); err != nil || body.ID != id || body.Digest != saved.PlanDigest || body.Canonical != string(canonical) {
		t.Fatal("unexpected fetched plan")
	}
	if after, err := os.ReadFile(file); err != nil || !bytes.Equal(after, data) {
		t.Fatal("fetch changed plan")
	}
	if entries, err := os.ReadDir(filepath.Dir(dir)); err != nil || len(entries) != 1 {
		t.Fatal("fetch created an approval or other state")
	}
	ancestor := filepath.Dir(dir)
	if err := os.Chmod(ancestor, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := readMembersPlans(home, "get", id); err == nil {
		t.Fatal("accepted writable ancestor")
	}
	if err := os.Chmod(ancestor, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(statedir.Override, t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if _, err := readMembersPlans(home, "get", id); err != nil {
		t.Fatal("environment override changed the default root apply store")
	}
	for i := 0; i < planPageSize+1; i++ {
		write(filepath.Join(dir, fmt.Sprintf("plan-20260101T000000Z-%04x.json", i)), []byte("{}"))
	}
	write(filepath.Join(dir, "not-a-plan.json"), []byte("private"))
	for _, cursor := range []string{"", "plan-20260101T000000Z-003f"} {
		pageRaw, err := readMembersPlans(home, "list", cursor)
		if err != nil {
			t.Fatal(err)
		}
		var page planPage
		if err := json.Unmarshal(pageRaw, &page); err != nil {
			t.Fatal(err)
		}
		if cursor == "" && (len(page.IDs) != planPageSize || page.Next != "plan-20260101T000000Z-003f") {
			t.Fatal("incorrect list page")
		}
		if cursor != "" && (len(page.IDs) != 2 || page.Next != "" || page.IDs[0] <= cursor) {
			t.Fatal("incorrect continuation")
		}
	}
	refused := func(label string) {
		t.Helper()
		b, err := readMembersPlans(home, "get", id)
		if err == nil || len(b) != 0 {
			t.Fatalf("returned %s", label)
		}
	}
	write(file, bytes.Replace(data, []byte(id), []byte("plan-20260101T000000Z-ffff"), 1))
	refused("mismatched saved plan ID")
	write(file, bytes.Replace(data, []byte(saved.PlanDigest), []byte(strings.Repeat("a", 64)), 1))
	refused("mismatched digest")
	write(file, []byte("private malformed data"))
	refused("malformed plan")
	write(file, bytes.Repeat([]byte{'x'}, maxSavedPlanBytes+1))
	refused("oversized file")
	saved.Plan.Steps[0].Content = strings.Repeat("<", maxMessage/4)
	saved.PlanDigest, _ = saved.Plan.Digest()
	escaped, _ := json.Marshal(saved)
	write(file, escaped)
	refused("oversized signed frame")
	write(file, data)
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	refused("nonprivate file")
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	refused("missing plan")
	private := filepath.Join(home, "private")
	write(private, data)
	if err := os.Symlink(private, file); err != nil {
		t.Fatal(err)
	}
	refused("symlink")
	later, err := readMembersPlans(home, "list", "plan-20260101T000000Z-0040")
	if err != nil || string(later) != `{"plan_ids":[]}` {
		t.Fatal("listing disclosed a symlinked plan")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(private, file); err != nil {
		t.Fatal(err)
	}
	refused("hard link")
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(file, 0600); err != nil {
		t.Fatal(err)
	}
	refused("nonregular file")
	if err := os.Rename(dir, dir+"-displaced"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir+"-displaced", dir); err != nil {
		t.Fatal(err)
	}
	refused("symlinked plans directory")
}

func TestMembersPlansLimitsDirectoryScan(t *testing.T) {
	home := t.TempDir()
	state, err := statedir.Path(runtime.GOOS, func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxPlanEntries; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if raw, err := readMembersPlans(home, "list", ""); err == nil || len(raw) != 0 {
		t.Fatal("returned a partial listing from an oversized directory")
	}
}

// Fetch from the saved-plan store through the normal signed paired channel.
func signedMembersPlan(t *testing.T, home, id string) Response {
	t.Helper()
	hq, key := keyPair(t)
	machine, machineKey := keyPair(t)
	g := Gate{Pairing: Pairing{Live: hq, AgentDaemon: hq, AgentDaemonBound: true, AgentDaemonUID: 777, OwnerPresenceRequired: true}}
	client, server := net.Pipe()
	defer client.Close()
	go handleConn(server, &g, machineKey, func(net.Conn) (int, error) { return 777, nil }, Hooks{MembersPlans: func(op, id string) ([]byte, error) { return readMembersPlans(home, op, id) }})
	q := Request{Verb: membersPlansVerb, Option: "get", PlanID: id, Nonce: "read-only", Timestamp: time.Now().Unix()}
	if _, err := client.Write(append(signed(t, key, q), '\n')); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.RequestNonce != q.Nonce || !VerifyResponse(machine, response) {
		t.Fatal("unverified read-only response")
	}
	return response
}

func TestPairedReadsExactHarnessPlans(t *testing.T) {
	testPlanRole(t, "777")
	home := t.TempDir()
	state, err := statedir.Path(runtime.GOOS, func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct{ action, digest string }{
		{"install", "0b8ecd3ce5241a20da07502c396b36d65e60cf8e6c3312733ca31d84df9f0d09"},
		{"retire", "e790b19de136ebf7f843c27c3520515738ed3cff36ad08fc02179a827edf1f19"},
	} {
		t.Run(fixture.action, func(t *testing.T) {
			// Canonical bytes from the independent native Darwin grant renderer.
			canonical, err := os.ReadFile(filepath.Join("..", "members", "testdata", "harness-launch-"+fixture.action+".json"))
			if err != nil {
				t.Fatal(err)
			}
			s := members.Saved{PlanID: approvePlanID, PlanDigest: fixture.digest, HarnessLaunch: new(members.HarnessPolicyRecord)}
			if err := json.Unmarshal(canonical, &s.Plan); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(s.Plan.Steps[0].Content), s.HarnessLaunch); err != nil {
				t.Fatal(err)
			}
			fetch := func() Response {
				t.Helper()
				raw, err := json.Marshal(s)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, s.PlanID+".json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				return signedMembersPlan(t, home, s.PlanID)
			}
			reply := fetch()
			var body struct {
				Canonical string `json:"plan_canonical"`
				Digest    string `json:"plan_digest"`
				ID        string `json:"plan_id"`
			}
			if !reply.OK || json.Unmarshal(reply.Body, &body) != nil || body.ID != s.PlanID || body.Digest != fixture.digest || body.Canonical != string(canonical) {
				t.Fatal("signed review differs from the saved plan")
			}
			if fixture.action == "retire" {
				installDigest := s.HarnessLaunch.InstalledDigest
				other := strings.Repeat("f", 64)
				s.HarnessLaunch.InstalledDigest = other
				original := s.Plan.Steps[0].Content
				s.Plan.Steps[0].Content = strings.Replace(original, installDigest, other, 1)
				s.PlanDigest, err = s.Plan.Digest()
				if err != nil {
					t.Fatal(err)
				}
				if reply := fetch(); reply.OK || len(reply.Body) != 0 {
					t.Fatal("retirement named an installation with different canonical bytes")
				}
				s.HarnessLaunch.InstalledDigest = installDigest
				s.Plan.Steps[0].Content = original
				s.PlanDigest = fixture.digest
			}
			s.HarnessLaunch.Adapters[0].Args = []string{"--different"}
			reply = fetch()
			if reply.OK || len(reply.Body) != 0 {
				t.Fatal("inconsistent request returned a plan")
			}
			s.HarnessLaunch = nil
			if reply := fetch(); reply.OK || len(reply.Body) != 0 {
				t.Fatal("harness launch files without their saved request returned a plan")
			}
		})
	}
}
