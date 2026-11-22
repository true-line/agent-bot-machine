package members

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
)

const SoulBridgeAccountsPurpose = "soul-bridge-provision"

// SoulBridgeAccount requests a dedicated credential-sidecar role for one
// installed Soul. Numeric identity is selected and covered by the plan digest.
type SoulBridgeAccount struct {
	SoulID         string `json:"soul_id"`
	InstallationID string `json:"installation_id"`
	Account        string `json:"account"`
}

func validateSoulBridgeAccounts(request []SoulBridgeAccount) ([]SoulBridgeAccount, []string, error) {
	invalid := errors.New("invalid per-installation Soul bridge accounts")
	if len(request) == 0 || len(request) > 64 {
		return nil, nil, invalid
	}
	bridges := slices.Clone(request)
	sort.Slice(bridges, func(i, j int) bool { return bridges[i].InstallationID < bridges[j].InstallationID })
	accounts := make([]string, 0, len(bridges))
	previous := ""
	seenAccounts := map[string]bool{}
	for _, b := range bridges {
		if !soulIdentity.MatchString(b.SoulID) || !soulInstallationID.MatchString(b.InstallationID) ||
			b.InstallationID <= previous || b.Account != SoulBridgeName(b.InstallationID) ||
			!accountName.MatchString(b.Account) || seenAccounts[b.Account] {
			return nil, nil, invalid
		}
		accounts = append(accounts, b.Account)
		seenAccounts[b.Account] = true
		previous = b.InstallationID
	}
	sort.Strings(accounts)
	return bridges, accounts, nil
}

func soulBridgeAccountStep(name string, h Host, uids map[int]string) (Step, error) {
	home := darwinSoulBridgeHome(name)
	want := Step{Kind: KindAccount, Target: name, Group: name, Mode: "0700",
		Detail: fmt.Sprintf("Soul bridge home %s, shell %s, private group, no password, no other groups", home, DarwinNoLoginShell)}
	a, exists, err := h.Account(name)
	if err != nil {
		return Step{}, err
	}
	if !exists {
		if _, occupied, err := h.Lstat(home); err != nil {
			return Step{}, err
		} else if occupied {
			return Step{}, refuse(RefusedPath, "Soul bridge home already exists without its account")
		}
		want.Action = ActionCreate
		return want, nil
	}
	if a.DarwinRole != darwinSoulBridgeRoleName || a.Home != home || a.Shell != DarwinNoLoginShell ||
		a.UID != a.GID || a.Group != name || a.UID < 300 || a.UID > 399 || uids[a.UID] != "" {
		return Step{}, refuse(RefusedAccount, "existing Soul bridge is not a dedicated managed role")
	}
	if others, extra := sharing(a); len(others) > 0 || len(extra) > 0 {
		return Step{}, refuse(RefusedAccount, "Soul bridge has a shared primary group or another group")
	}
	uids[a.UID] = name
	e, ok, err := h.Lstat(home)
	if err != nil {
		return Step{}, err
	}
	if !ok || !e.Dir || e.Owner != name || e.Group != name {
		return Step{}, refuse(RefusedPath, "Soul bridge home is not private to its managed role")
	}
	want.Action, want.Detail = ActionNone, fmt.Sprintf("exists; Soul bridge home %s; its password is checked at apply", home)
	if e.Mode != 0700 {
		want.Action = ActionRepair
		want.Detail = accountHomeRepairDetail(home, e.Mode&07777)
	}
	return want, nil
}

func buildSoulBridgeAccounts(in Input, h Host) (Plan, error) {
	if in.Platform != PlatformDarwin || in.HQAccount != DarwinHQAccount || in.SoulRunnerAccounts != nil ||
		in.HarnessLaunch != nil || in.HQService != nil || in.UpgradeFrom != nil || in.HarnessAccounts ||
		in.Dir != DarwinDir || len(in.Members) != 0 {
		return Plan{}, refuse(RefusedList, "Soul bridges require a separate dedicated Darwin account plan")
	}
	bridges, accounts, err := validateSoulBridgeAccounts(in.SoulBridgeAccounts)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: accounts, SoulBridges: bridges, Purpose: SoulBridgeAccountsPurpose}
	uids := map[int]string{}
	hq, err := hqAccountStep(in, h, uids)
	if err != nil {
		return Plan{}, err
	}
	if hq.Action != ActionNone || hq.Mode == "" {
		return Plan{}, refuse(RefusedAccount, "Soul bridges need an existing dedicated HQ account")
	}
	p.Steps = append(p.Steps, hq)
	for _, name := range accounts {
		step, err := soulBridgeAccountStep(name, h, uids)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, step)
	}
	if err := bindHarnessAccounts(&p, h); err != nil {
		return Plan{}, err
	}
	if err := appendSoulBridgeDirectories(&p, h); err != nil {
		return Plan{}, err
	}
	p.Purpose = SoulBridgeAccountsPurpose
	raw, err := p.Canonical()
	if err != nil || len(raw) > 32*1024 {
		return Plan{}, errors.New("Soul bridge account plan exceeds the paired review limit")
	}
	return p, nil
}

// Endpoint parents are fixed per installation and installed under the same
// paired review as B. Their socket basenames change on each start. This keeps
// the target-UID launcher from needing root or a foreign private group.
func appendSoulBridgeDirectories(p *Plan, h Host) error {
	if err := checkBrokerParent(h, launchRuntimeDir); err != nil {
		return err
	}
	inspector, ok := h.(interface{ CheckDarwinACLs([]string) error })
	if !ok {
		return errors.New("Darwin endpoint ACL inspection unavailable")
	}
	paths := pathAncestry(launchRuntimeDir)
	roles := map[string]int{}
	uidOwners := map[int]string{}
	for _, step := range p.Steps {
		roles[step.Target] = step.UID
		uidOwners[step.UID] = step.Target
	}
	seenSlots := map[string]bool{}
	for _, bridge := range p.SoulBridges {
		slot := soulEndpointInstallationSlot(bridge.InstallationID)
		if seenSlots[slot] {
			return errors.New("Soul endpoint installation slot collision")
		}
		seenSlots[slot] = true
		runnerName := soulRunnerName(bridge.InstallationID)
		runner, err := soulRunnerAccountStep(runnerName, h, uidOwners)
		if err != nil || runner.Action != ActionNone {
			return errors.New("Soul bridge requires an existing dedicated runner role")
		}
		account, exists, err := h.Account(runnerName)
		if err != nil || !exists || account.UID < 300 || account.UID > 399 {
			return errors.New("Soul runner identity disappeared during bridge review")
		}
		roles[runnerName] = account.UID
	}
	for _, base := range []string{DarwinBrokerDir, path.Join(launchRuntimeDir, "m"), path.Join(launchRuntimeDir, "s"), path.Join(launchRuntimeDir, "r")} {
		step, err := brokerDirectoryStep(h, base, "root", "wheel", 0755)
		if err != nil {
			return err
		}
		if step.Action == ActionNone {
			paths = append(paths, base)
		}
		p.Steps = append(p.Steps, step)
	}
	for _, bridge := range p.SoulBridges {
		bridgeUID := roles[bridge.Account]
		runnerName := soulRunnerName(bridge.InstallationID)
		runnerUID := roles[runnerName]
		slot := soulEndpointInstallationSlot(bridge.InstallationID)
		for _, target := range []struct {
			path, owner, group string
			uid, gid           int
		}{
			{path.Join(DarwinBrokerDir, bridge.Account), DarwinHQAccount, bridge.Account, roles[DarwinHQAccount], bridgeUID},
			{path.Join(launchRuntimeDir, "m", slot), runnerName, bridge.Account, runnerUID, bridgeUID},
			{path.Join(launchRuntimeDir, "s", slot), bridge.Account, runnerName, bridgeUID, runnerUID},
			{path.Join(launchRuntimeDir, "r", slot), DarwinHQAccount, runnerName, roles[DarwinHQAccount], runnerUID},
		} {
			step, err := brokerDirectoryStep(h, target.path, target.owner, target.group, 02750)
			if err != nil {
				return err
			}
			step.UID, step.GID = target.uid, target.gid
			if step.Action == ActionNone {
				paths = append(paths, target.path)
			}
			p.Steps = append(p.Steps, step)
		}
	}
	return inspector.CheckDarwinACLs(paths)
}

func CheckDarwinSoulBridgeAccounts(s Saved, owner string, uid int) error {
	return checkDarwinSoulBridgeAccounts(s, owner, uid, OSHost{})
}

func checkDarwinSoulBridgeAccounts(s Saved, owner string, uid int, h Host) error {
	if s.SoulBridgeAccounts == nil || s.SoulRunnerAccounts != nil || s.HarnessLaunch != nil ||
		s.HQService != nil || s.UpgradeFrom != nil || s.QualificationRun != nil ||
		!ValidApproval(s.PlanID, s.PlanDigest) || s.Plan.Purpose != SoulBridgeAccountsPurpose ||
		len(s.Plan.Steps) == 0 || s.Plan.Steps[0].UID != uid {
		return errors.New("saved plan is not this paired Soul bridge operation")
	}
	canonical, err := s.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != s.PlanDigest {
		return errors.New("saved Soul bridge plan digest mismatch")
	}
	rebuilt, err := Build(Input{SoulBridgeAccounts: s.SoulBridgeAccounts, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
	if err != nil {
		return err
	}
	actual, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(actual, canonical) {
		return errors.New("reviewed Soul bridge accounts differ from current host")
	}
	return nil
}
