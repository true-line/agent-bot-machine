package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwts/managed-machine/internal/target"
)

type soulAccountHost struct{ *brokerHost }

func (h soulAccountHost) PrivateDarwinRoleGroup(name string, id int) (bool, error) {
	return h.accounts[name].GID == id, nil
}
func (h soulAccountHost) PlanHarnessIDs(names []string) (map[string]int, error) {
	ids := map[string]int{}
	for i, name := range names {
		ids[name] = 334 + i
	}
	return ids, nil
}

func soulAccountFixture() (soulAccountHost, []SoulRunnerAccount) {
	h, _ := provisionFixture()
	runners := []SoulRunnerAccount{
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_0000000000000001", Account: soulRunnerName("inst_0000000000000001")},
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_existing", Account: soulRunnerName("inst_existing")},
	}
	return soulAccountHost{h}, runners
}

func TestSoulRunnerAccountPlanBindsInstallationAndDistinctRoles(t *testing.T) {
	h, runners := soulAccountFixture()
	in := Input{SoulRunnerAccounts: runners, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	if p.Purpose != SoulRunnerAccountsPurpose || len(p.SoulRunners) != 2 || p.Members[0] == p.Members[1] || p.Steps[1].UID == p.Steps[2].UID {
		t.Fatalf("not one reviewed account per installation: %+v", p)
	}
	digest, _ := p.Digest()
	s := Saved{SoulRunnerAccounts: runners, PlanID: "plan-20261121T140000Z-abcd", PlanDigest: digest, Plan: p}
	if _, err := s.CanonicalForReview(); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinSoulRunnerAccounts(s, "owner", p.Steps[0].UID, h); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinSoulRunnerAccounts(s, "owner", p.Steps[0].UID+1, h); err == nil {
		t.Fatal("other HQ UID accepted")
	}
	tampered := s
	tampered.Plan.SoulRunners = append([]SoulRunnerAccount(nil), p.SoulRunners...)
	tampered.Plan.SoulRunners[0].SoulID = "agent_ffffffff-ffff-ffff-ffff-ffffffffffff"
	if _, err := tampered.CanonicalForReview(); err == nil {
		t.Fatal("changed Soul identity accepted")
	}
	for name, edit := range map[string]func([]SoulRunnerAccount){
		"shared install": func(r []SoulRunnerAccount) { r[1].InstallationID = r[0].InstallationID; r[1].Account = r[0].Account },
		"chosen account": func(r []SoulRunnerAccount) { r[1].Account = "_abm-sr-arbitrary" },
		"bad identity":   func(r []SoulRunnerAccount) { r[1].SoulID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			r := append([]SoulRunnerAccount(nil), runners...)
			edit(r)
			if _, err := Build(Input{SoulRunnerAccounts: r, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin}, h); err == nil {
				t.Fatal("unreviewed role mapping accepted")
			}
		})
	}
}

type soulAccountRoot struct{ *fakeRoot }

func (r *soulAccountRoot) CreateReviewedSoulRunner(name string, id int) error {
	a := member(name, id)
	a.DarwinRole, a.Home, a.Shell = darwinSoulRunnerRoleName, darwinSoulRunnerHome(name), DarwinNoLoginShell
	r.h.accounts[name] = a
	r.h.entries[a.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	r.shadow[name] = "*"
	r.log = append(r.log, "create "+name)
	return nil
}
func (r *soulAccountRoot) RepairReviewedSoulRunnerHome(name string, id int, before uint32) error {
	if r.h.accounts[name].UID != id || r.h.entries[darwinSoulRunnerHome(name)].Mode != before {
		return errors.New("changed runner home")
	}
	return r.SetMode(darwinSoulRunnerHome(name), 0700)
}

func TestSoulRunnerAccountApplyUsesPairedExactPlan(t *testing.T) {
	h, runners := soulAccountFixture()
	w := newWorld(h.fakeHost)
	r := &soulAccountRoot{fakeRoot: w.r}
	for name := range h.accounts {
		r.shadow[name] = "*"
	}
	w.deps.Host = func() Host { return h }
	w.deps.Root = func() Root { return r }
	w.deps.CheckUpgradePair = func(_, _, commitment string, run func() error) error {
		if commitment != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			return errors.New("pair changed")
		}
		if run != nil {
			return run()
		}
		return nil
	}
	p, err := Build(Input{SoulRunnerAccounts: runners, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil {
		t.Fatal(err)
	}
	const id = "plan-20261121T140001Z-abcd"
	digest, _ := p.Digest()
	s := Saved{SoulRunnerAccounts: runners, PlanID: id, PlanDigest: digest, Plan: p}
	w.approved(t, id, p)
	aPath := ApprovalPath(machineDir, id)
	var approval Approval
	if err := json.Unmarshal([]byte(w.h.files[aPath]), &approval); err != nil {
		t.Fatal(err)
	}
	approval.Purpose, approval.PairCommitment, approval.MachineFingerprint = SoulRunnerAccountsPurpose,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	w.h.files[aPath] = string(mustJSON(t, approval))
	planPath := filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", id+".json")
	w.h.files[planPath] = string(mustJSON(t, s))
	result := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id})
	if result.Diagnostic != nil || r.receipts[id].Result != "applied" || len(r.log) != 2 {
		t.Fatalf("paired runner provision failed: %v, receipt %+v, steps %v", result.Diagnostic, r.receipts[id], r.log)
	}
	for _, runner := range runners {
		if h.accounts[runner.Account].DarwinRole != darwinSoulRunnerRoleName {
			t.Fatal("runner role not created")
		}
	}
}

func TestSoulRunnerAccountCLIPlanSavesExactRequest(t *testing.T) {
	h, runners := soulAccountFixture()
	w := newWorld(h.fakeHost)
	w.deps.Host = func() Host { return h }
	w.deps.Deps.Username = func() (string, error) { return "owner", nil }
	state := t.TempDir()
	w.deps.Deps.StateDir = func() (string, error) { return state, nil }
	w.deps.ReadFile = func(string) ([]byte, error) {
		return mustJSON(t, struct {
			Runners []SoulRunnerAccount `json:"runners"`
		}{runners}), nil
	}
	result := Command(w.deps).Run(on(target.DarwinARM64), []string{"plan", "--soul-runner-provision", "/tmp/runner-request.json"})
	if result.Diagnostic != nil {
		t.Fatal(result.Diagnostic)
	}
	entries, err := os.ReadDir(filepath.Join(state, "members", "plans"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("saved plan: %v, %v", entries, err)
	}
	raw, err := os.ReadFile(filepath.Join(state, "members", "plans", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var saved Saved
	if err := json.Unmarshal(raw, &saved); err != nil || len(saved.SoulRunnerAccounts) != 2 || saved.Plan.Purpose != SoulRunnerAccountsPurpose {
		t.Fatalf("saved request lost installation binding: %+v, %v", saved, err)
	}
	if _, err := saved.CanonicalForReview(); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
