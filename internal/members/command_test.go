package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/target"
)

func on(tg target.Target) cli.Context {
	return cli.Context{Detect: func() (target.Host, error) { return target.Host{Target: tg}, nil }}
}

func deps(t *testing.T, h Host) (Deps, string) {
	t.Helper()
	state := t.TempDir()
	return Deps{
		Deps: command.Deps{
			StateDir:  func() (string, error) { return state, nil },
			Username:  func() (string, error) { return "owner", nil },
			Now:       func() time.Time { return time.Date(2026, 11, 10, 4, 0, 0, 0, time.UTC) },
			NewPlanID: func(time.Time) (string, error) { return "plan-20261110T040000Z-abcd", nil },
		},
		Host: func() Host { return h },
		ReadFile: func(p string) ([]byte, error) {
			if p != "/etc/hq/config.json" {
				return nil, errors.New("no such file")
			}
			return []byte(`{"leaseTtlMs": 1000, "members": {"dir": "/run/hq-m", "accounts": {
				"agent_3d9ab2ac-9c97-442c-9bfa-8fcf497ded66": {"m_spec": "abm-spec", "m_lead": "abm-lead"}}}}`), nil
		},
	}, state
}

func TestPlanSavesThePlanAndReportsItsDigest(t *testing.T) {
	d, state := deps(t, bare())
	res := Command(d).Run(on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-spec, abm-lead"})
	if res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	head := res.Records[0]
	digest, _ := head.Get("plan_digest")
	if id, _ := head.Get("plan_id"); id != "plan-20261110T040000Z-abcd" {
		t.Errorf("plan_id = %v", id)
	}
	if applied, _ := head.Get("applied"); applied != false {
		t.Errorf("applied = %v", applied)
	}
	if len(res.Records) != 8 {
		t.Fatalf("%d records, want the summary and 7 steps", len(res.Records))
	}
	// The owner is shown the exact rule.
	rule, _ := res.Records[7].Get("content")
	if !strings.Contains(rule.(string), "agent-bot-hq ALL = (ABHQ_MEMBERS) NOPASSWD: NOSETENV: ALL") {
		t.Errorf("the sudoers record does not carry the rule: %v", rule)
	}

	file := filepath.Join(state, "members", "plans", "plan-20261110T040000Z-abcd.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var saved Saved
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	// The saved digest is the digest of the saved plan, and of a rebuild.
	if got, _ := saved.Plan.Digest(); got != digest || saved.PlanDigest != digest {
		t.Errorf("saved digest %s, plan digest %s, reported %v", saved.PlanDigest, got, digest)
	}
	rebuilt, _ := Build(Input{HQAccount: saved.Plan.HQAccount, Dir: saved.Plan.Dir, Members: saved.Plan.Members, Invoker: "owner"}, bare())
	if got, _ := rebuilt.Digest(); got != digest {
		t.Errorf("a rebuild from the saved request has digest %s, want %v", got, digest)
	}
	// Windows has no Unix mode bits; the command itself is Linux only.
	if fi, _ := os.Stat(file); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("plan file mode %o", fi.Mode().Perm())
	}
}

func TestPlanReadsTheMembersFromHQsConfig(t *testing.T) {
	d, _ := deps(t, bare())
	res := Command(d).Run(on(target.LinuxARM64), []string{"plan", "--hq-account=agent-bot-hq", "--hq-config", "/etc/hq/config.json"})
	if res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	if got, _ := res.Records[0].Get("members"); got != "abm-lead,abm-spec" {
		t.Errorf("members = %v", got)
	}
	if got, _ := res.Records[0].Get("dir"); got != "/run/hq-m" {
		t.Errorf("dir = %v", got)
	}
}

func TestPlanRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx  cli.Context
		args []string
		host func() *fakeHost
		want string
	}{
		"macOS":                 {on(target.DarwinARM64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-a"}, bare, diag.MembersUnsupported},
		"Windows":               {on(target.WindowsAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-a"}, bare, diag.MembersUnsupported},
		"no action":             {on(target.LinuxAMD64), nil, bare, diag.Usage},
		"apply is not built":    {on(target.LinuxAMD64), []string{"apply", "plan-1"}, bare, diag.Usage},
		"no HQ account named":   {on(target.LinuxAMD64), []string{"plan", "--members", "abm-a"}, bare, diag.Usage},
		"no list":               {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq"}, bare, diag.Usage},
		"two lists":             {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-a", "--hq-config", "/etc/hq/config.json"}, bare, diag.Usage},
		"--dir with a config":   {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--hq-config", "/etc/hq/config.json", "--dir", "/run/x"}, bare, diag.Usage},
		"an unknown option":     {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-a", "--yes"}, bare, diag.Usage},
		"an unreadable config":  {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--hq-config", "/nowhere.json"}, bare, diag.MembersListInvalid},
		"a bad member name":     {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-a;reboot"}, bare, diag.MembersListInvalid},
		"the invoker as member": {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "owner"}, bare, diag.MembersListInvalid},
		"no HQ account on host": {on(target.LinuxAMD64), []string{"plan", "--hq-account", "nobody-hq", "--members", "abm-a"}, bare, diag.MembersAccountRefused},
		"a member already in sudo": {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-lead,abm-spec"}, func() *fakeHost {
			h := provisioned()
			a := h.accounts["abm-lead"]
			a.Groups = append(a.Groups, "sudo")
			h.accounts["abm-lead"] = a
			return h
		}, diag.MembersAccountRefused},
		"a path held by something else": {on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", "abm-lead,abm-spec"}, func() *fakeHost {
			h := provisioned()
			h.entries[DefaultDir] = Entry{Regular: true}
			return h
		}, diag.MembersPathRefused},
	} {
		d, state := deps(t, tc.host())
		res := Command(d).Run(tc.ctx, tc.args)
		if res.Diagnostic == nil || res.Diagnostic.ID != tc.want {
			t.Errorf("%s: diagnostic %+v, want %s", name, res.Diagnostic, tc.want)
		}
		if len(res.Records) != 0 {
			t.Errorf("%s: records with a refusal", name)
		}
		// A refused plan saves nothing.
		if entries, _ := os.ReadDir(filepath.Join(state, "members", "plans")); len(entries) != 0 {
			t.Errorf("%s: a plan was saved", name)
		}
	}
}

func TestAnEmptyListIsAPlanThatGrantsNothing(t *testing.T) {
	d, _ := deps(t, provisioned())
	res := Command(d).Run(on(target.LinuxAMD64), []string{"plan", "--hq-account", "agent-bot-hq", "--members", ""})
	if res.Diagnostic != nil {
		t.Fatalf("diagnostic: %+v", res.Diagnostic)
	}
	var removed int
	for _, r := range res.Records[1:] {
		if a, _ := r.Get("action"); a == ActionRemove {
			removed++
		}
		if c, ok := r.Get("content"); ok && strings.Contains(c.(string), "NOPASSWD") {
			t.Errorf("a rule is still granted: %v", c)
		}
	}
	if removed != 2 {
		t.Errorf("%d directories removed, want 2", removed)
	}
}
