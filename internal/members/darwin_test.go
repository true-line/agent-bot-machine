package members

import (
	"encoding/json"
	"errors"
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
	_, err = Build(Input{HQAccount: DarwinHQAccount, Members: []string{"abm-a"}, Platform: PlatformDarwin}, emptyHost())
	var r *Refusal
	if !errors.As(err, &r) || r.Code != RefusedList {
		t.Fatalf("members on macOS: %v", err)
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
	for _, args := range [][]string{{"plan", "--members", "abm-a"}, {"plan", "--hq-config", "/etc/hq/config.json"}, {"plan", "--dir", "/run/x"}} {
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
	w.h.files["/home/owner/Library/Application Support/managed-machine/members/plans/"+applyID+".json"] = string(raw)
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
