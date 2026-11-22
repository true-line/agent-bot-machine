package members

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/target"
)

type bridgeAccountHost struct{ *brokerHost }

func (h bridgeAccountHost) PrivateDarwinRoleGroup(name string, id int) (bool, error) {
	return h.accounts[name].GID == id, nil
}
func (h bridgeAccountHost) PlanHarnessIDs(names []string) (map[string]int, error) {
	ids := map[string]int{}
	for i, name := range names {
		ids[name] = 334 + i
	}
	return ids, nil
}

func bridgeAccountFixture() (bridgeAccountHost, []SoulBridgeAccount) {
	h, _ := provisionFixture()
	bridges := []SoulBridgeAccount{
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_0000000000000001", Account: SoulBridgeName("inst_0000000000000001")},
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_existing", Account: SoulBridgeName("inst_existing")},
	}
	for i, bridge := range bridges {
		name := soulRunnerName(bridge.InstallationID)
		a := member(name, 340+i)
		a.DarwinRole, a.Home, a.Shell = darwinSoulRunnerRoleName, darwinSoulRunnerHome(name), DarwinNoLoginShell
		h.accounts[name] = a
		h.entries[a.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	}
	return bridgeAccountHost{h}, bridges
}

func TestSoulBridgeAccountPlanBindsInstallationAndDistinctRoles(t *testing.T) {
	h, bridges := bridgeAccountFixture()
	in := Input{SoulBridgeAccounts: bridges, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	if p.Purpose != SoulBridgeAccountsPurpose || len(p.SoulBridges) != 2 || len(p.Steps) != 15 ||
		p.Members[0] == p.Members[1] || p.Steps[1].UID == p.Steps[2].UID {
		t.Fatalf("not one reviewed account per installation: %+v", p)
	}
	digest, _ := p.Digest()
	s := Saved{SoulBridgeAccounts: bridges, PlanID: "plan-20261121T140000Z-abcd", PlanDigest: digest, Plan: p}
	if _, err := s.CanonicalForReview(); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinSoulBridgeAccounts(s, "owner", p.Steps[0].UID, h); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinSoulBridgeAccounts(s, "owner", p.Steps[0].UID+1, h); err == nil {
		t.Fatal("other HQ UID accepted")
	}
	tampered := s
	tampered.Plan.SoulBridges = append([]SoulBridgeAccount(nil), p.SoulBridges...)
	tampered.Plan.SoulBridges[0].SoulID = "agent_ffffffff-ffff-ffff-ffff-ffffffffffff"
	if _, err := tampered.CanonicalForReview(); err == nil {
		t.Fatal("changed Soul identity accepted")
	}
	tampered = s
	tampered.SoulBridgeAccounts = append([]SoulBridgeAccount(nil), bridges...)
	tampered.SoulBridgeAccounts[0].InstallationID = "inst_other"
	if _, err := tampered.CanonicalForReview(); err == nil {
		t.Fatal("changed request installation accepted")
	}
	for name, edit := range map[string]func([]SoulBridgeAccount){
		"shared install": func(r []SoulBridgeAccount) { r[1].InstallationID = r[0].InstallationID; r[1].Account = r[0].Account },
		"chosen account": func(r []SoulBridgeAccount) { r[1].Account = "_abm-sr-arbitrary" },
		"bad identity":   func(r []SoulBridgeAccount) { r[1].SoulID = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			r := append([]SoulBridgeAccount(nil), bridges...)
			edit(r)
			if _, err := Build(Input{SoulBridgeAccounts: r, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin}, h); err == nil {
				t.Fatal("unreviewed role mapping accepted")
			}
		})
	}
	for name, corrupt := range map[string]func(bridgeAccountHost, []SoulBridgeAccount){
		"runner missing": func(host bridgeAccountHost, request []SoulBridgeAccount) {
			delete(host.accounts, soulRunnerName(request[0].InstallationID))
		},
		"runner shared UID": func(host bridgeAccountHost, request []SoulBridgeAccount) {
			a := host.accounts[soulRunnerName(request[0].InstallationID)]
			a.UID, a.GID = 320, 320
			host.accounts[a.Name] = a
		},
		"foreign endpoint parent": func(host bridgeAccountHost, request []SoulBridgeAccount) {
			host.entries[path.Join(launchRuntimeDir, "m", soulEndpointInstallationSlot(request[0].InstallationID))] =
				Entry{Dir: true, Owner: request[0].Account, Group: soulRunnerName(request[0].InstallationID), Mode: 02750}
		},
	} {
		t.Run(name, func(t *testing.T) {
			host, request := bridgeAccountFixture()
			corrupt(host, request)
			if _, err := Build(Input{SoulBridgeAccounts: request, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin}, host); err == nil {
				t.Fatal("unreviewed endpoint principal accepted")
			}
		})
	}
}

type bridgeAccountRoot struct {
	*fakeRoot
	finishGuard *bool
}

func (r *bridgeAccountRoot) Finish(id string, raw []byte) error {
	if r.finishGuard != nil && !*r.finishGuard {
		return errors.New("applied bridge receipt escaped the paired guard")
	}
	return r.fakeRoot.Finish(id, raw)
}

func (r *bridgeAccountRoot) CreateReviewedSoulBridge(name string, id int) error {
	a := member(name, id)
	a.DarwinRole, a.Home, a.Shell = darwinSoulBridgeRoleName, darwinSoulBridgeHome(name), DarwinNoLoginShell
	r.h.accounts[name] = a
	r.h.entries[a.Home] = Entry{Dir: true, Owner: name, Group: name, Mode: 0700}
	r.shadow[name] = "*"
	r.log = append(r.log, "create "+name)
	return nil
}
func (r *bridgeAccountRoot) RepairReviewedSoulBridgeHome(name string, id int, before uint32) error {
	if r.h.accounts[name].UID != id || r.h.entries[darwinSoulBridgeHome(name)].Mode != before {
		return errors.New("changed bridge home")
	}
	return r.SetMode(darwinSoulBridgeHome(name), 0700)
}
func (r *bridgeAccountRoot) CreateReviewedSoulEndpointDirectory(p, owner, group string, mode uint32, uid, gid int) error {
	if uid != 0 && (r.h.accounts[owner].UID != uid || r.h.accounts[group].GID != gid) {
		return errors.New("changed endpoint role identity")
	}
	return r.EnsureDir(p, owner, group, mode)
}

func TestSoulBridgeAccountApplyUsesPairedExactPlan(t *testing.T) {
	h, bridges := bridgeAccountFixture()
	w := newWorld(h.fakeHost)
	r := &bridgeAccountRoot{fakeRoot: w.r}
	for name := range h.accounts {
		r.shadow[name] = "*"
	}
	w.deps.Host = func() Host { return h }
	w.deps.Root = func() Root { return r }
	guardActive := false
	r.finishGuard = &guardActive
	w.deps.CheckUpgradePair = func(_, _, commitment string, run func() error) error {
		if commitment != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
			return errors.New("pair changed")
		}
		if run != nil {
			guardActive = true
			defer func() { guardActive = false }()
			return run()
		}
		return nil
	}
	p, err := Build(Input{SoulBridgeAccounts: bridges, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil {
		t.Fatal(err)
	}
	const id = "plan-20261121T140001Z-abcd"
	digest, _ := p.Digest()
	s := Saved{SoulBridgeAccounts: bridges, PlanID: id, PlanDigest: digest, Plan: p}
	w.approved(t, id, p)
	aPath := ApprovalPath(machineDir, id)
	var approval Approval
	if err := json.Unmarshal([]byte(w.h.files[aPath]), &approval); err != nil {
		t.Fatal(err)
	}
	approval.Purpose, approval.PairCommitment, approval.MachineFingerprint = SoulBridgeAccountsPurpose,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	w.h.files[aPath] = string(mustJSON(t, approval))
	planPath := filepath.Join("/home/owner", "Library", "Application Support", "managed-machine", "members", "plans", id+".json")
	w.h.files[planPath] = string(mustJSON(t, s))
	wrong := approval
	wrong.Purpose = HarnessAccountsPurpose
	w.h.files[aPath] = string(mustJSON(t, wrong))
	if refused := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id}); refused.Diagnostic == nil || len(r.log) != 0 {
		t.Fatal("foreign paired purpose created a bridge")
	}
	wrong = approval
	wrong.PairCommitment = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	w.h.files[aPath] = string(mustJSON(t, wrong))
	if refused := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id}); refused.Diagnostic == nil || len(r.log) != 0 {
		t.Fatal("changed HQ pairing created a bridge")
	}
	w.h.files[aPath] = string(mustJSON(t, approval))
	result := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id})
	if result.Diagnostic != nil || r.receipts[id].Result != "applied" || len(r.log) != 14 {
		t.Fatalf("paired bridge provision failed: %v, receipt %+v, steps %v", result.Diagnostic, r.receipts[id], r.log)
	}
	if again := Command(w.deps).Run(on(target.DarwinARM64), []string{"apply", id}); again.Diagnostic == nil || len(r.log) != 14 {
		t.Fatal("spent approval created or changed another bridge account")
	}
	for _, bridge := range bridges {
		if h.accounts[bridge.Account].DarwinRole != darwinSoulBridgeRoleName {
			t.Fatal("bridge role not created")
		}
	}
}

func TestSoulBridgeApplyRevokedBeforeAppliedReceiptKeepsSpentClaim(t *testing.T) {
	h, bridges := bridgeAccountFixture()
	w := newWorld(h.fakeHost)
	r := &bridgeAccountRoot{fakeRoot: w.r}
	for name := range h.accounts {
		r.shadow[name] = "*"
	}
	w.deps.Host = func() Host { return h }
	w.deps.Root = func() Root { return r }
	p, err := Build(Input{SoulBridgeAccounts: bridges, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "owner"}, h)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := p.Digest()
	const id = "plan-20261121T140002Z-abcd"
	s := Saved{SoulBridgeAccounts: bridges, PlanID: id, PlanDigest: digest, Plan: p}
	a := Approval{Purpose: SoulBridgeAccountsPurpose, PlanID: id, PlanDigest: digest,
		PairCommitment: strings.Repeat("a", 64), MachineFingerprint: strings.Repeat("a", 64),
		ApprovedAt: w.now.Format(approvalTime), ExpiresAt: w.now.Add(ApprovalTTL).Format(approvalTime)}
	postSteps := 0
	paired := func(_ Approval, run func() error) error {
		if run == nil {
			return nil
		}
		if len(r.log) == 14 {
			postSteps++
			if postSteps == 2 {
				return errors.New("pair revoked before applied receipt")
			}
		}
		return run()
	}
	result := runSoulBridgeAccountApply(s, a, "owner", h, w.deps, paired)
	if result.Diagnostic == nil || postSteps != 2 || r.receipts[id].Result != "started" {
		t.Fatalf("revoked pair published affirmative receipt: %+v; post-step checks %d; receipt %+v", result.Diagnostic, postSteps, r.receipts[id])
	}
}

func TestSoulBridgeAccountCLIPlanSavesExactRequest(t *testing.T) {
	h, bridges := bridgeAccountFixture()
	w := newWorld(h.fakeHost)
	w.deps.Host = func() Host { return h }
	w.deps.Deps.Username = func() (string, error) { return "owner", nil }
	state := t.TempDir()
	w.deps.Deps.StateDir = func() (string, error) { return state, nil }
	w.deps.ReadFile = func(string) ([]byte, error) {
		return mustJSON(t, struct {
			Bridges []SoulBridgeAccount `json:"bridges"`
		}{bridges}), nil
	}
	result := Command(w.deps).Run(on(target.DarwinARM64), []string{"plan", "--soul-bridge-provision", "/tmp/bridge-request.json"})
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
	if err := json.Unmarshal(raw, &saved); err != nil || len(saved.SoulBridgeAccounts) != 2 || saved.Plan.Purpose != SoulBridgeAccountsPurpose {
		t.Fatalf("saved request lost installation binding: %+v, %v", saved, err)
	}
	if _, err := saved.CanonicalForReview(); err != nil {
		t.Fatal(err)
	}
}
