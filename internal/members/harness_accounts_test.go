package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/target"
)

type provisionHost struct{ *brokerHost }

func (h provisionHost) PrivateDarwinRoleGroup(name string, id int) (bool, error) {
	return h.accounts[name].GID == id, nil
}
func provisionFixture() (*brokerHost, Input) {
	h, in := brokerFixture()
	for _, p := range pathAncestry("/private/var") {
		h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	}
	return h, in
}

func (h provisionHost) PlanHarnessIDs(names []string) (map[string]int, error) {
	return map[string]int{"_spec": 323}, nil
}
func TestHarnessAccountCanonicalFixtures(t *testing.T) {
	for _, tc := range []struct{ name, dir string }{{"accounts", DarwinDir}, {"accounts-and-broker", DarwinBrokerDir}} {
		h, in := provisionFixture()
		in.HarnessAccounts = true
		in.Dir = tc.dir
		delete(h.accounts, "_spec")
		delete(h.entries, darwinHarnessHome("_spec"))
		p, err := Build(in, provisionHost{h})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := p.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join("testdata", "harness-account-provision-"+tc.name+".json")
		want, err := os.ReadFile(dest)
		if err != nil || string(raw) != string(want) {
			t.Fatalf("canonical fixture changed: %s", dest)
		}
	}
}

type provisionRoot struct {
	*fakeRoot
	failLast bool
}

func (r *provisionRoot) CreateReviewedHarness(name string, id int) error {
	a := member(name, id)
	a.DarwinRole = darwinHarnessRoleName
	a.Home = darwinHarnessHome(name)
	a.Shell = DarwinNoLoginShell
	r.h.accounts[name] = a
	r.h.entries[a.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	r.shadow[name] = "*"
	r.log = append(r.log, "create "+name)
	return nil
}
func (r *provisionRoot) RepairReviewedHarnessHome(name string, id int, before uint32) error {
	if r.h.accounts[name].UID != id || r.h.entries[darwinHarnessHome(name)].Mode != before {
		return errors.New("wrong UID")
	}
	return r.SetMode(darwinHarnessHome(name), 0700)
}
func (r *provisionRoot) CreateReviewedBrokerDirectory(p, owner, group string, mode uint32, uid, gid int) error {
	if p != DarwinBrokerDir && (uid != r.h.accounts[owner].UID || gid != r.h.accounts[group].GID) {
		return errors.New("changed numeric directory mapping")
	}
	if r.failLast && group == "_spec" {
		return errors.New("injected final directory failure")
	}
	return r.fakeRoot.EnsureDir(p, owner, group, mode)
}

func TestHarnessAccountProtectedApply(t *testing.T) {
	for _, scenario := range []string{"success", "partial", "pair revoked before apply", "pair revoked after claim", "legacy proof", "launch proof", "tampered IDs", "scope expands", "existing account has login", "occupied home", "HQ repair", "changed ACL", "no-op replay", "expired during preflight", "home drift", "directory ID drift"} {
		t.Run(scenario, func(t *testing.T) {
			h, in := provisionFixture()
			host := provisionHost{h}
			in.HarnessAccounts = true
			if scenario != "no-op replay" {
				delete(h.accounts, "_spec")
				delete(h.entries, darwinHarnessHome("_spec"))
				home := h.entries[darwinHarnessHome("_lead")]
				home.Mode = 0750
				h.entries[darwinHarnessHome("_lead")] = home
			} else {
				in.Dir = DarwinDir
			}
			w := newWorld(h.fakeHost)
			r := &provisionRoot{fakeRoot: w.r}
			for name := range h.accounts {
				r.shadow[name] = "*"
			}
			w.deps.Host = func() Host { return host }
			w.deps.Root = func() Root { return r }
			const peer = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			nPair := 0
			w.deps.CheckUpgradePair = func(dir, account, commitment string, run func() error) error {
				nPair++
				if scenario == "expired during preflight" && nPair == 2 {
					w.now = w.now.Add(time.Hour)
				}
				if scenario == "home drift" && nPair == 3 {
					e := h.entries[darwinHarnessHome("_lead")]
					e.Mode = 0777
					h.entries[darwinHarnessHome("_lead")] = e
				}
				if scenario == "directory ID drift" && nPair == 6 {
					a := h.accounts["_lead"]
					a.UID = 325
					a.GID = 325
					h.accounts["_lead"] = a
				}
				if dir != machineDir || account != "machine" || commitment != peer || scenario == "pair revoked before apply" || (scenario == "pair revoked after claim" && nPair >= 3) {
					return errors.New("retired pairing")
				}
				if run != nil {
					return run()
				}
				return nil
			}
			store := func(id string) Saved {
				t.Helper()
				p, err := Build(in, host)
				if err != nil {
					t.Fatal(err)
				}
				d, _ := p.Digest()
				s := Saved{PlanID: id, PlanDigest: d, Plan: p}
				if err := checkDarwinHarnessAccounts(s, "owner", 320, host); err != nil {
					t.Fatal(err)
				}
				if err := checkDarwinHarnessAccounts(s, "owner", 319, host); err == nil {
					t.Fatal("accepted another paired HQ UID")
				}
				w.approved(t, id, p)
				ap := ApprovalPath(machineDir, id)
				var a Approval
				if err := json.Unmarshal([]byte(w.h.files[ap]), &a); err != nil {
					t.Fatal(err)
				}
				a.Purpose = HarnessAccountsPurpose
				a.PairCommitment = peer
				a.MachineFingerprint = peer
				switch scenario {
				case "legacy proof":
					a.Purpose = ""
				case "launch proof":
					a.Purpose = HarnessInstall
				case "tampered IDs":
					s.Plan.Steps[1].UID++
				case "scope expands":
					s.Plan.Members = append(s.Plan.Members, "_other")
				}
				b, _ := json.Marshal(a)
				w.h.files[ap] = string(b)
				b, _ = json.Marshal(s)
				h.files[filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", id+".json")] = string(b)
				return s
			}
			store(applyID)
			switch scenario {
			case "existing account has login":
				r.shadow["_lead"] = "set"
			case "occupied home":
				h.entries[darwinHarnessHome("_spec")] = Entry{Dir: true}
			case "HQ repair":
				a := h.entries[HQHome(PlatformDarwin, DarwinHQAccount)]
				a.Mode = 0755
				h.entries[HQHome(PlatformDarwin, DarwinHQAccount)] = a
			case "changed ACL":
				h.denied = darwinHarnessHome("_lead")
			case "partial":
				r.failLast = true
			}
			apply := func(id string) cli.Result { return Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id}) }
			res := apply(applyID)
			switch scenario {
			case "success", "no-op replay":
				if res.Diagnostic != nil || r.receipts[applyID].Result != "applied" {
					t.Fatal(res.Diagnostic, r.receipts)
				}
			case "partial":
				if res.Diagnostic == nil || r.receipts[applyID].Result != "failed" || h.accounts["_spec"].UID != 323 {
					t.Fatal(res.Diagnostic, r.receipts)
				}
				r.failLast = false
				const retry = "plan-20261110T030001Z-cdef"
				s := store(retry)
				if s.Plan.Changes() != 1 {
					t.Fatal("did not isolate remaining step", s.Plan)
				}
				if got := apply(retry); got.Diagnostic != nil {
					t.Fatal(got.Diagnostic)
				}
			case "directory ID drift":
				if res.Diagnostic == nil || r.receipts[applyID].Result != "failed" {
					t.Fatal(res.Diagnostic, r.receipts)
				}
				if _, ok := h.entries[DarwinBrokerDir+"/_lead"]; ok {
					t.Fatal("created directory for changed ID")
				}
			case "home drift", "pair revoked after claim":
				if res.Diagnostic == nil || r.receipts[applyID].Result != "failed" || len(r.log) != 0 {
					t.Fatal(res.Diagnostic, r.receipts, r.log)
				}
			default:
				if res.Diagnostic == nil || len(r.receipts) != 0 || len(r.log) != 0 {
					t.Fatal(res.Diagnostic, r.receipts, r.log)
				}
			}
			before := len(r.log)
			if got := apply(applyID); got.Diagnostic == nil || len(r.log) != before {
				t.Fatal("replay changed host", got, r.log)
			}
		})
	}
}

func TestHarnessAccountCLIPlanScope(t *testing.T) {
	h, _ := provisionFixture()
	d, state := deps(t, h.fakeHost)
	d.Host = func() Host { return provisionHost{h} }
	for _, tc := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"accounts", []string{"--members", "_spec,_lead"}, true},
		{"empty", []string{"--members"}, false}, {"shared HQ", []string{"--members", "_spec", "--hq-account", "other"}, false},
		{"operator", []string{"--members", "admin"}, false}, {"arbitrary dir", []string{"--members", "_spec", "--dir", "/tmp/elsewhere"}, false},
		{"launch", []string{"--members", "_spec", "--harness-launch-install", "/not-read"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Command(d).Run(on(target.DarwinARM64), append([]string{"plan", "--harness-account-provision"}, tc.args...))
			if tc.valid {
				if res.Diagnostic != nil {
					t.Fatal(res.Diagnostic)
				}
				id, _ := res.Records[0].Get("plan_id")
				raw, err := os.ReadFile(filepath.Join(state, "members", "plans", id.(string)+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var saved Saved
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				if err := checkDarwinHarnessAccounts(saved, "owner", 320, provisionHost{h}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if res.Diagnostic == nil {
				t.Fatal("unexpected eligible request")
			}
		})
	}
}
