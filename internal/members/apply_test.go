package members

import (
	"encoding/json"
	"errors"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/target"
)

// fakeRoot applies changes to a fakeHost and records them.
type fakeRoot struct {
	h        *fakeHost
	shadow   map[string]string
	sudoers  *string
	log      []string
	receipts map[string]Receipt
	// brokenRule makes the sudoers check fail.
	brokenRule bool
	nextUID    int
}

func newRoot(h *fakeHost) *fakeRoot {
	r := &fakeRoot{h: h, shadow: map[string]string{}, receipts: map[string]Receipt{}, nextUID: 2000}
	if _, ok := h.accounts["agent-bot-hq"]; ok {
		r.shadow["agent-bot-hq"] = "!"
	}
	return r
}

func (r *fakeRoot) PasswordField(a string) (string, bool, error) {
	f, ok := r.shadow[a]
	return f, ok, nil
}

func (r *fakeRoot) ReadSudoers() (string, bool, error) {
	if r.sudoers == nil {
		return "", false, nil
	}
	return *r.sudoers, true, nil
}

func (r *fakeRoot) CreateAccount(name string) error {
	r.log = append(r.log, "useradd "+name)
	r.nextUID++
	r.h.accounts[name] = member(name, r.nextUID)
	r.h.entries["/home/"+name] = Entry{Dir: true, Mode: 0o700, Owner: name, Group: name}
	r.shadow[name] = "!"
	return nil
}

func (r *fakeRoot) CreateHQAccount(name string) error {
	r.log = append(r.log, "useradd --system "+name)
	r.nextUID++
	a := member(name, r.nextUID)
	a.Home = HQHomeBase + "/" + name
	r.h.accounts[name] = a
	r.h.entries[a.Home] = Entry{Dir: true, Mode: 0o700, Owner: name, Group: name}
	r.shadow[name] = "!"
	return nil
}

func (r *fakeRoot) SetMode(p string, mode uint32) error {
	r.log = append(r.log, "chmod "+p)
	e := r.h.entries[p]
	e.Mode = mode
	r.h.entries[p] = e
	return nil
}

func (r *fakeRoot) EnsureDir(p, owner, group string, mode uint32) error {
	r.log = append(r.log, "dir "+p)
	if _, ok := r.h.entries[p]; !ok && path.Dir(p) == DefaultDir {
		r.h.lists[DefaultDir] = append(r.h.lists[DefaultDir], path.Base(p))
	}
	r.h.entries[p] = Entry{Dir: true, Mode: mode, Owner: owner, Group: group}
	return nil
}

func (r *fakeRoot) RemoveDir(p string) error {
	r.log = append(r.log, "rmdir "+p)
	delete(r.h.entries, p)
	var keep []string
	for _, n := range r.h.lists[path.Dir(p)] {
		if n != path.Base(p) {
			keep = append(keep, n)
		}
	}
	r.h.lists[path.Dir(p)] = keep
	return nil
}

func (r *fakeRoot) WriteFile(p string, mode uint32, content string, validate bool) error {
	if validate && r.brokenRule {
		r.log = append(r.log, "visudo refused "+p)
		return errors.New("the rule was not installed: syntax error")
	}
	r.log = append(r.log, "write "+p)
	if p == SudoersPath {
		if !validate {
			return errors.New("the sudoers file was written unchecked")
		}
		r.sudoers = &content
		return nil
	}
	r.h.entries[p] = Entry{Regular: true, Mode: mode, Owner: "root", Group: "root"}
	r.h.files[p] = content
	return nil
}

func (r *fakeRoot) Claim(id string, raw []byte) (bool, error) {
	if _, ok := r.receipts[id]; ok {
		return false, nil
	}
	return true, r.Finish(id, raw)
}

func (r *fakeRoot) Finish(id string, raw []byte) error {
	var rc Receipt
	if err := json.Unmarshal(raw, &rc); err != nil {
		return err
	}
	r.receipts[id] = rc
	return nil
}

const (
	applyID     = "plan-20261110T040000Z-abcd"
	machineDir  = "/home/machine/.config/agent-machine"
	applyMoment = "2026-11-10T04:05:00Z"
)

// planFile is where members plan saves a plan for the owner, spelled with
// the separator of the system the test runs on.
func planFile(id string) string {
	return filepath.Join("/home/owner", ".local", "share", "managed-machine", "members", "plans", id+".json")
}

// world is a host, a root and the dependencies of one apply.
type world struct {
	h    *fakeHost
	r    *fakeRoot
	deps Deps
	env  []string
	euid int
	up   []map[string]string
	now  time.Time
}

func newWorld(h *fakeHost) *world {
	w := &world{h: h, r: newRoot(h), env: []string{"SUDO_UID=1000", "SUDO_USER=owner"}}
	w.now, _ = time.Parse(approvalTime, applyMoment)
	w.deps = Deps{
		Deps: command.Deps{Now: func() time.Time { return w.now }},
		Host: func() Host { return w.h },
		ApplyDeps: ApplyDeps{
			Euid:       func() int { return w.euid },
			ProcessEnv: func() []string { return w.env },
			Ancestors:  func() []map[string]string { return w.up },
			LookupUID: func(uid string) (string, string, error) {
				switch uid {
				case "1000":
					return "owner", "/home/owner", nil
				case "1500":
					return "claude-code-agent", "/home/claude-code-agent", nil
				}
				return "", "", errors.New("no such uid")
			},
			DaemonState: func(owner, home string) (string, string, error) { return machineDir, "machine", nil },
			Root:        func() Root { return w.r },
		},
	}
	return w
}

// planned saves the plan for request under id, as members plan does.
func (w *world) planned(t *testing.T, id string) Plan {
	t.Helper()
	p, err := Build(request, w.h)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := p.Digest()
	raw, _ := json.Marshal(Saved{PlanID: id, PlanDigest: digest, Plan: p})
	w.h.files[planFile(id)] = string(raw)
	return p
}

// approved records the approval of p under id, as agent-machine does.
func (w *world) approved(t *testing.T, id string, p Plan) {
	t.Helper()
	digest, _ := p.Digest()
	a := Approval{PlanID: id, PlanDigest: digest, ApprovedAt: "2026-11-10T04:00:00Z", ExpiresAt: "2026-11-10T04:10:00Z"}
	raw, _ := json.Marshal(a)
	w.h.entries[ApprovalsDir(machineDir)] = Entry{Dir: true, Mode: 0o700, Owner: "machine", Group: "machine"}
	w.h.entries[ApprovalPath(machineDir, id)] = Entry{Regular: true, Mode: 0o600, Owner: "machine", Group: "machine"}
	w.h.files[ApprovalPath(machineDir, id)] = string(raw)
}

func (w *world) apply(args ...string) cli.Result {
	return Command(w.deps).Run(on(target.LinuxAMD64), append([]string{"apply"}, args...))
}

func wantRefused(t *testing.T, w *world, res cli.Result, id string) {
	t.Helper()
	if res.Diagnostic == nil || res.Diagnostic.ID != id {
		t.Fatalf("diagnostic %+v, want %s", res.Diagnostic, id)
	}
	if len(w.r.log) != 0 {
		t.Fatalf("a refused apply changed the host: %v", w.r.log)
	}
}

func TestApplyRunsAnApprovedPlanOnce(t *testing.T) {
	w := newWorld(bare())
	p := w.planned(t, applyID)
	w.approved(t, applyID, p)
	res := w.apply(applyID)
	if res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	if applied, _ := res.Records[0].Get("applied"); applied != true {
		t.Errorf("applied = %v", applied)
	}
	want := []string{
		"useradd abm-lead", "useradd abm-spec",
		"dir " + DefaultDir, "dir " + DefaultDir + "/abm-lead", "dir " + DefaultDir + "/abm-spec",
		"write " + TmpfilesPath, "write " + SudoersPath,
	}
	if strings.Join(w.r.log, "\n") != strings.Join(want, "\n") {
		t.Fatalf("steps:\n%s", strings.Join(w.r.log, "\n"))
	}
	if rc := w.r.receipts[applyID]; rc.Result != "applied" || rc.Owner != "owner" || rc.Changes != 6 || rc.FinishedAt == "" {
		t.Fatalf("receipt %+v", rc)
	}
	in, _ := Normalize(request)
	if w.r.sudoers == nil || *w.r.sudoers != Sudoers(in) {
		t.Fatal("the launch rule is not the planned one")
	}

	// The same approval does not allow a second apply.
	w.r.log = nil
	wantRefused(t, w, w.apply(applyID), diag.MembersNotApproved)

	// A new plan on the provisioned host changes nothing but rewrites the rule.
	const next = "plan-20261110T040600Z-0001"
	again := w.planned(t, next)
	if again.Changes() != 0 {
		t.Fatalf("a provisioned host still plans %d changes:\n%s", again.Changes(), actions(again))
	}
	w.approved(t, next, again)
	if res := w.apply(next); res.Diagnostic != nil {
		t.Fatalf("second apply: %+v", res.Diagnostic)
	}
	if strings.Join(w.r.log, "\n") != "write "+SudoersPath {
		t.Fatalf("second apply did: %v", w.r.log)
	}
}

func TestApplyRefusesTheWrongCaller(t *testing.T) {
	cases := []struct {
		name string
		edit func(*world)
		want string
	}{
		{"not root", func(w *world) { w.euid = 1000 }, diag.MembersRootRequired},
		{"root login", func(w *world) { w.env = nil }, diag.MembersRootRequired},
		{"sudo from root", func(w *world) { w.env = []string{"SUDO_UID=0"} }, diag.MembersRootRequired},
		{"unknown uid", func(w *world) { w.env = []string{"SUDO_UID=77"} }, diag.MembersRootRequired},
		{"agent account", func(w *world) { w.env = []string{"SUDO_UID=1500"} }, diag.MembersCallerRefused},
		{"agent account variable", func(w *world) { w.env = append(w.env, "AGENT_BOT_ACCOUNT=claude-code-agent") }, diag.MembersCallerRefused},
		{"agent marker", func(w *world) { w.env = append(w.env, "CLAUDECODE=1") }, diag.MembersCallerRefused},
		{"agent session above sudo", func(w *world) {
			w.up = []map[string]string{{"SHELL": "/bin/bash"}, {"CLAUDE_CODE_ENTRYPOINT": "cli"}}
		}, diag.MembersCallerRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(bare())
			p := w.planned(t, applyID)
			w.approved(t, applyID, p)
			tc.edit(w)
			wantRefused(t, w, w.apply(applyID), tc.want)
			if len(w.r.receipts) != 0 {
				t.Fatal("a refused caller used the approval")
			}
		})
	}
}

func TestApplyNeedsAMatchingUnexpiredApproval(t *testing.T) {
	approval := ApprovalPath(machineDir, applyID)
	cases := []struct {
		name string
		edit func(*world)
		want string
	}{
		{"no plan", func(w *world) { delete(w.h.files, planFile(applyID)) }, diag.MembersPlanFailed},
		{"plan for another id", func(w *world) {
			w.h.files[planFile(applyID)] = strings.Replace(w.h.files[planFile(applyID)], applyID, "plan-20261110T040000Z-ffff", 1)
		}, diag.MembersPlanFailed},
		{"no approval", func(w *world) { delete(w.h.entries, approval); delete(w.h.files, approval) }, diag.MembersNotApproved},
		{"expired", func(w *world) { w.now = w.now.Add(5 * time.Minute) }, diag.MembersNotApproved},
		{"group can write the approval", func(w *world) {
			e := w.h.entries[approval]
			e.Mode = 0o660
			w.h.entries[approval] = e
		}, diag.MembersNotApproved},
		{"approval owned by the owner", func(w *world) {
			e := w.h.entries[approval]
			e.Owner = "owner"
			w.h.entries[approval] = e
		}, diag.MembersNotApproved},
		{"approval is a link", func(w *world) {
			e := w.h.entries[approval]
			e.Regular = false
			w.h.entries[approval] = e
		}, diag.MembersNotApproved},
		{"others can write the directory", func(w *world) {
			e := w.h.entries[ApprovalsDir(machineDir)]
			e.Mode = 0o777
			w.h.entries[ApprovalsDir(machineDir)] = e
		}, diag.MembersNotApproved},
		{"approval for another digest", func(w *world) {
			w.h.files[approval] = strings.Replace(w.h.files[approval], `"plan_digest":"`, `"plan_digest":"0000`, 1)
		}, diag.MembersNotApproved},
		{"host changed after approval", func(w *world) {
			w.h.entries[DefaultDir] = Entry{Dir: true, Mode: 0o777, Owner: "root", Group: "root"}
		}, diag.MembersNotApproved},
		{"request changed after approval", func(w *world) {
			w.h.files[planFile(applyID)] = strings.Replace(w.h.files[planFile(applyID)], `"abm-spec"`, `"abm-evil"`, 1)
		}, diag.MembersNotApproved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(bare())
			p := w.planned(t, applyID)
			w.approved(t, applyID, p)
			tc.edit(w)
			wantRefused(t, w, w.apply(applyID), tc.want)
			if len(w.r.receipts) != 0 {
				t.Fatal("a refused apply used the approval")
			}
		})
	}
}

func TestApplyCreatesTheHQAccountBeforeAnythingThatNamesIt(t *testing.T) {
	h := bare()
	delete(h.accounts, "agent-bot-hq")
	delete(h.entries, "/var/lib/agent-bot-hq")
	w := newWorld(h)
	p := w.planned(t, applyID)
	w.approved(t, applyID, p)
	if res := w.apply(applyID); res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	if len(w.r.log) == 0 || w.r.log[0] != "useradd --system agent-bot-hq" {
		t.Fatalf("steps:\n%s", strings.Join(w.r.log, "\n"))
	}
	if a := h.accounts["agent-bot-hq"]; a.Home != "/var/lib/agent-bot-hq" {
		t.Fatalf("HQ account = %+v", a)
	}
	if rc := w.r.receipts[applyID]; rc.Result != "applied" || rc.Changes != 7 {
		t.Fatalf("receipt %+v", rc)
	}
}

func TestApplyChecksWhatOnlyRootCanSee(t *testing.T) {
	t.Run("dedicated HQ account with a password", func(t *testing.T) {
		w := newWorld(bare())
		w.r.shadow["agent-bot-hq"] = "$6$salt$hash"
		w.approved(t, applyID, w.planned(t, applyID))
		wantRefused(t, w, w.apply(applyID), diag.MembersAccountRefused)
	})
	t.Run("shared HQ account keeps its password", func(t *testing.T) {
		h := bare()
		a := h.accounts["agent-bot-hq"]
		a.Groups = append(a.Groups, "sudo")
		h.accounts["agent-bot-hq"] = a
		w := newWorld(h)
		w.r.shadow["agent-bot-hq"] = "$6$salt$hash"
		w.approved(t, applyID, w.planned(t, applyID))
		if res := w.apply(applyID); res.Diagnostic != nil {
			t.Fatalf("diagnostic: %+v", res.Diagnostic)
		}
	})
	t.Run("member with a password", func(t *testing.T) {
		w := newWorld(provisioned())
		w.r.shadow["abm-lead"], w.r.shadow["abm-spec"] = "!", "$6$salt$hash"
		w.approved(t, applyID, w.planned(t, applyID))
		wantRefused(t, w, w.apply(applyID), diag.MembersAccountRefused)
	})
	t.Run("member with an empty password", func(t *testing.T) {
		w := newWorld(provisioned())
		w.r.shadow["abm-lead"], w.r.shadow["abm-spec"] = "", "*"
		w.approved(t, applyID, w.planned(t, applyID))
		wantRefused(t, w, w.apply(applyID), diag.MembersAccountRefused)
	})
	t.Run("member with no shadow entry", func(t *testing.T) {
		w := newWorld(provisioned())
		w.approved(t, applyID, w.planned(t, applyID))
		wantRefused(t, w, w.apply(applyID), diag.MembersAccountRefused)
	})
	t.Run("a rule someone else wrote", func(t *testing.T) {
		w := newWorld(bare())
		foreign := "agent-bot-hq ALL=(ALL) NOPASSWD: ALL\n"
		w.r.sudoers = &foreign
		w.approved(t, applyID, w.planned(t, applyID))
		wantRefused(t, w, w.apply(applyID), diag.MembersPathRefused)
		if *w.r.sudoers != foreign {
			t.Fatal("the foreign rule was replaced")
		}
	})
}

func TestApplyNeverInstallsABrokenRule(t *testing.T) {
	w := newWorld(bare())
	w.r.brokenRule = true
	w.approved(t, applyID, w.planned(t, applyID))
	res := w.apply(applyID)
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.MembersApplyFailed {
		t.Fatalf("diagnostic %+v", res.Diagnostic)
	}
	if w.r.sudoers != nil {
		t.Fatal("a rule visudo refused was installed")
	}
	rc := w.r.receipts[applyID]
	if rc.Result != "failed" || rc.FailedAt != "file "+SudoersPath {
		t.Fatalf("receipt %+v", rc)
	}
}

func TestApplyRepairsAndRemoves(t *testing.T) {
	w := newWorld(provisioned())
	w.r.shadow["abm-lead"], w.r.shadow["abm-spec"] = "!", "*"
	w.h.entries["/home/abm-lead"] = Entry{Dir: true, Mode: 0o755, Owner: "abm-lead", Group: "abm-lead"}
	w.h.entries[DefaultDir+"/abm-old"] = Entry{Dir: true, Mode: 0o2750, Owner: "agent-bot-hq", Group: "abm-old"}
	w.h.lists[DefaultDir] = append(w.h.lists[DefaultDir], "abm-old")
	w.approved(t, applyID, w.planned(t, applyID))
	if res := w.apply(applyID); res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	want := "chmod /home/abm-lead\nrmdir " + DefaultDir + "/abm-old\nwrite " + SudoersPath
	if strings.Join(w.r.log, "\n") != want {
		t.Fatalf("steps:\n%s", strings.Join(w.r.log, "\n"))
	}
}

func TestApplyTakesAPlanIDAndNothingElse(t *testing.T) {
	w := newWorld(bare())
	for _, args := range [][]string{{}, {"../x"}, {applyID, "--force"}, {"--members", "abm-x"}, {applyID, applyID}} {
		res := w.apply(args...)
		if res.Diagnostic == nil || res.Diagnostic.ID != diag.Usage {
			t.Fatalf("%v: %+v", args, res.Diagnostic)
		}
	}
	res := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", applyID})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.MembersUnsupported {
		t.Fatalf("darwin: %+v", res.Diagnostic)
	}
}
