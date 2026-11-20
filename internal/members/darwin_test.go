package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/target"
)

func emptyHost() *fakeHost {
	return &fakeHost{accounts: map[string]Account{}, entries: map[string]Entry{}, files: map[string]string{}, lists: map[string][]string{}}
}

func TestDarwinPlanIsTheHQAccountAlone(t *testing.T) {
	p, err := Build(Input{HQAccount: DarwinHQAccount, Invoker: "owner", Platform: PlatformDarwin}, emptyHost())
	if err != nil {
		t.Fatal(err)
	}
	if got := actions(p); got != "hq-account _agent-bot-hq create" {
		t.Fatalf("steps: %s", got)
	}
	if p.Dir != DarwinDir || len(p.Members) != 0 {
		t.Fatalf("dir %q members %v", p.Dir, p.Members)
	}
	for _, want := range []string{"hidden role account", "/var/agent-bot-hq", DarwinNoLoginShell} {
		if !strings.Contains(p.Steps[0].Detail, want) {
			t.Errorf("detail %q lacks %q", p.Steps[0].Detail, want)
		}
	}

}

func TestDarwinHarnessAccounts(t *testing.T) {
	in := Input{HQAccount: DarwinHQAccount, Members: []string{"_abm-b", "_abm-a"}, Invoker: "owner", Platform: PlatformDarwin}
	h := emptyHost()
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	if got := actions(p); got != "hq-account _agent-bot-hq create\naccount _abm-a create\naccount _abm-b create" {
		t.Fatalf("unexpected actions %q", got)
	}
	for i, name := range p.Members {
		id := 310 + i
		h.accounts[name] = Account{Name: name, Group: name, UID: id, GID: id, Home: darwinHarnessHome(name), Shell: DarwinNoLoginShell, DarwinRole: darwinHarnessRoleName}
		h.entries[darwinHarnessHome(name)] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	}
	p, err = Build(in, h)
	if err != nil || p.Changes() != 1 {
		t.Fatalf("existing private accounts: %+v %v", p, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Account)
	}{
		{"existing system account", func(a *Account) { a.DarwinRole = "" }},
		{"another home", func(a *Account) { a.Home = "/Users/owner" }},
		{"interactive shell", func(a *Account) { a.Shell = "/bin/zsh" }},
		{"same uid as second role", func(a *Account) { a.UID = 311; a.GID = 311 }},
		{"shared group", func(a *Account) { a.PrimaryUsers = []string{"another"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := h.accounts["_abm-a"]
			changed := a
			tc.change(&changed)
			h.accounts[a.Name] = changed
			defer func() { h.accounts[a.Name] = a }()
			_, err := Build(in, h)
			var r *Refusal
			if !errors.As(err, &r) || r.Code != RefusedAccount {
				t.Fatalf("wanted account refusal; got %v", err)
			}
		})
	}
	delete(h.accounts, "_abm-a")
	if _, err := Build(in, h); err == nil {
		t.Fatal("accepted a pre-existing home without its role")
	}
}

func TestDarwinPlanNamesASharedAccountAndTheDedicatedOne(t *testing.T) {
	h := emptyHost()
	h.accounts["owner"] = Account{Name: "owner", UID: 501, GID: 20, Group: "staff", PrimaryUsers: []string{"admin", "owner"}, Groups: []string{"staff"}, Home: "/Users/owner"}
	p, err := Build(Input{HQAccount: "owner", Platform: PlatformDarwin}, h)
	if err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Action != ActionNone || p.Steps[0].Mode != "" {
		t.Fatalf("a shared account is not left alone: %+v", p.Steps[0])
	}
	if advice := p.SharedHQAdvice(); !strings.Contains(advice, "dedicated account "+DarwinHQAccount) {
		t.Fatalf("advice %q", advice)
	}
}

func TestDarwinPlanAndApplyCommands(t *testing.T) {
	d, _ := deps(t, emptyHost())
	res := Command(d).Run(on(target.DarwinARM64), []string{"plan"})
	if res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	if len(res.Records) != 2 {
		t.Fatalf("%d records, want the summary and the HQ account", len(res.Records))
	}
	if got, _ := res.Records[0].Get("hq_account"); got != DarwinHQAccount {
		t.Errorf("hq_account = %v", got)
	}
	if got, _ := res.Records[0].Get("dir"); got != DarwinDir {
		t.Errorf("dir = %v", got)
	}
	for _, args := range [][]string{{"plan", "--dir", "/run/x"}} {
		res := Command(d).Run(on(target.DarwinARM64), args)
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.MembersUnsupported {
			t.Fatalf("%v: %+v", args, res.Diagnostic)
		}
	}

	w := newWorld(emptyHost())
	w.r.sudoers = new(string) // a foreign rule would refuse a Linux plan; macOS installs none
	*w.r.sudoers = "someone else's rule\n"
	p, err := Build(Input{HQAccount: DarwinHQAccount, Invoker: "owner", Platform: PlatformDarwin}, w.h)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := p.Digest()
	raw, _ := json.Marshal(Saved{PlanID: applyID, PlanDigest: digest, Plan: p})
	// macOS keeps the owner's state in Application Support.
	w.h.files[filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", applyID+".json")] = string(raw)
	w.approved(t, applyID, p)
	res = Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", applyID})
	if res.Diagnostic != nil {
		t.Fatalf("apply: %+v", res.Diagnostic)
	}
	if got := strings.Join(w.r.log, "\n"); got != "useradd --system "+DarwinHQAccount {
		t.Fatalf("steps:\n%s", got)
	}
	// The same saved plan is not what a Linux host would build.
	w2 := newWorld(emptyHost())
	w2.h.files[planFile(applyID)] = string(raw)
	w2.approved(t, applyID, p)
	if res := w2.apply(applyID); res.Diagnostic == nil {
		t.Fatal("a macOS plan was applied on Linux")
	}
}

func TestDarwinPlanGuidesFirstHQExport(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		exists bool
		want   string
	}{
		{"dedicated first HQ", []string{"plan"}, false, "daemon first-hq export "},
		{"includes harness", []string{"plan", "--members", "_abm-one"}, false, "without harness accounts"},
		{"dedicated role exists", []string{"plan"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := emptyHost()
			if tc.exists {
				h.accounts[DarwinHQAccount] = Account{Name: DarwinHQAccount, UID: 320, GID: 320, Group: DarwinHQAccount, Home: HQHome(PlatformDarwin, DarwinHQAccount)}
				h.entries[h.accounts[DarwinHQAccount].Home] = Entry{Dir: true, Owner: DarwinHQAccount, Mode: 0700}
			}
			d, _ := deps(t, h)
			result := Command(d).Run(on(target.DarwinARM64), tc.args)
			if result.Diagnostic != nil {
				t.Fatal(result.Diagnostic.Message)
			}
			value, ok := result.Records[0].Get("advice")
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected advice: %v", value)
				}
			} else if !ok || !strings.Contains(value.(string), tc.want) {
				t.Fatalf("wrong first-HQ advice: %v", value)
			}
		})
	}
}

func TestDarwinBrokerConfigAndDigestApproval(t *testing.T) {
	h, in := brokerFixture()
	d, state := deps(t, h)
	d.ReadFile = func(string) ([]byte, error) {
		return json.Marshal(map[string]any{"harnesses": map[string]any{"dir": in.Dir,
			"accounts": map[string]string{"adapter-a": "_lead", "adapter-b": "_spec", "shared": "_lead"}}})
	}
	ctx := on(target.DarwinARM64)
	result := Command(d).Run(ctx, []string{"plan", "--hq-config", "fixture.json"})
	if result.Diagnostic != nil {
		t.Fatal(result.Diagnostic)
	}
	const id = "plan-20261110T040000Z-abcd"
	raw, err := os.ReadFile(filepath.Join(state, "members", "plans", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved Saved
	if err = json.Unmarshal(raw, &saved); err != nil || saved.Plan.Dir != in.Dir || len(saved.Plan.Members) != 2 {
		t.Fatal(saved, err)
	}
	w := newWorld(h.fakeHost)
	w.deps.Host = func() Host { return h }
	for n := range h.accounts {
		w.r.shadow[n] = "*"
	}
	h.files[filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", id+".json")] = string(raw)
	run := func() bool { return Command(w.deps).Run(ctx, []string{"apply", id}).Diagnostic == nil }
	if run() || len(w.r.log) != 0 {
		t.Fatal("applied without approval")
	}
	if _, _, err := FirstHQPlan("/home/owner", "owner", id, h); err == nil {
		t.Fatal("accepted for first HQ")
	}
	w.approved(t, id, saved.Plan)
	h.entries[in.Dir] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	if run() || len(w.r.log) != 0 {
		t.Fatal("accepted changed digest")
	}
	delete(h.entries, in.Dir)
	if !run() || w.r.receipts[id].Result != "applied" || w.r.receipts[id].PlanDigest != saved.PlanDigest {
		t.Fatal(w.r.log, w.r.receipts)
	}
	if run() {
		t.Fatal("replayed a previously applied plan")
	}
}

func TestDarwinSharedConfigPreservesAccountOnlyDigest(t *testing.T) {
	h, _ := brokerFixture()
	ctx := on(target.DarwinARM64)
	var accountDigest string
	for _, dir := range []string{"", "/var/run/agent-bot-hq/members", "/opt/custom-shared-brokers", DarwinBrokerDir} {
		d, _ := deps(t, h)
		d.ReadFile = func(string) ([]byte, error) {
			config := map[string]any{"accounts": map[string]string{"fixture": "_lead"}}
			if dir != "" {
				config["dir"] = dir
			}
			return json.Marshal(map[string]any{"harnesses": config})
		}
		res := Command(d).Run(ctx, []string{"plan", "--hq-config", "shared.json"})
		if res.Diagnostic != nil {
			t.Fatal(dir, res.Diagnostic)
		}
		actualDir, _ := res.Records[0].Get("dir")
		digest, _ := res.Records[0].Get("plan_digest")
		if dir == DarwinBrokerDir {
			if actualDir != DarwinBrokerDir || digest == accountDigest || len(res.Records) != 5 {
				t.Fatal("fixed Darwin path did not select both broker directories")
			}
			continue
		}
		if actualDir != DarwinDir || len(res.Records) != 3 {
			t.Fatal("shared config changed account-only plan", dir)
		}
		if dir == "" {
			accountDigest = digest.(string)
			continue
		}
		if digest != accountDigest {
			t.Fatal("shared config changed account-only digest", dir)
		}
		if Command(d).Run(ctx, []string{"plan", "--members", "_lead", "--dir", dir}).Diagnostic == nil {
			t.Fatal("explicit directory flag accepted unmanaged location", dir)
		}
	}
}

func TestIncompleteHarnessPlanRefusedBeforeApprovalLookup(t *testing.T) {
	for _, targetPath := range []string{HarnessPolicy, HarnessRule} {
		w := newWorld(emptyHost())
		s := Saved{PlanID: applyID, Plan: Plan{Steps: []Step{{Kind: KindFile, Target: targetPath}}}}
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		w.h.files[filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", applyID+".json")] = string(raw)
		w.deps.DaemonState = func(string, string) (string, string, error) {
			t.Fatal("read-only launch plan reached the approval store")
			return "", "", nil
		}
		result := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", applyID})
		wantRefused(t, w, result, diag.MembersNotApproved)
		if len(w.r.receipts) != 0 {
			t.Fatal("read-only launch plan acquired a root receipt")
		}
	}
}

func TestReadOnlyHarnessPlanCannotApply(t *testing.T) {
	for _, action := range []string{"install", "retire"} {
		t.Run(action, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "harness-launch-"+action+".json"))
			if err != nil {
				t.Fatal(err)
			}
			s := Saved{PlanID: applyID, HarnessLaunch: new(HarnessPolicyRecord)}
			if err := json.Unmarshal(data, &s.Plan); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(s.Plan.Steps[0].Content), s.HarnessLaunch); err != nil {
				t.Fatal(err)
			}
			s.PlanDigest, err = s.Plan.Digest()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			w := newWorld(emptyHost())
			w.h.files[filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", applyID+".json")] = string(raw)
			w.approved(t, applyID, s.Plan)
			res := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", applyID})
			wantRefused(t, w, res, diag.MembersNotApproved)
			if len(w.r.receipts) != 0 {
				t.Fatal("refused apply created a receipt")
			}
		})
	}
}
