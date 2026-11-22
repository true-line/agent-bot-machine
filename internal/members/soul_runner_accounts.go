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

const SoulRunnerAccountsPurpose = "soul-runner-provision"

// SoulRunnerAccount binds a local role name to an installation, before a
// package and its fixed launch rule are reviewed. The account name is derived
// from the installation ID, so a plan cannot select a shared or HQ principal.
type SoulRunnerAccount struct {
	SoulID         string `json:"soul_id"`
	InstallationID string `json:"installation_id"`
	Account        string `json:"account"`
}

func CheckDarwinSoulRunnerAccounts(s Saved, owner string, uid int) error {
	return checkDarwinSoulRunnerAccounts(s, owner, uid, OSHost{})
}

func checkDarwinSoulRunnerAccounts(s Saved, owner string, uid int, h Host) error {
	if s.SoulRunnerAccounts == nil || s.SoulBridgeAccounts != nil || s.HarnessLaunch != nil || s.HQService != nil || s.UpgradeFrom != nil || s.QualificationRun != nil ||
		!ValidApproval(s.PlanID, s.PlanDigest) || s.Plan.Purpose != SoulRunnerAccountsPurpose || len(s.Plan.Steps) == 0 || s.Plan.Steps[0].UID != uid {
		return errors.New("saved plan is not this paired Soul runner operation")
	}
	canonical, err := s.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != s.PlanDigest {
		return errors.New("saved Soul runner plan digest mismatch")
	}
	rebuilt, err := Build(Input{SoulRunnerAccounts: s.SoulRunnerAccounts, HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
	if err != nil {
		return err
	}
	actual, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(actual, canonical) {
		return errors.New("reviewed Soul runner accounts differ from current host")
	}
	return nil
}

func soulRunnerName(installationID string) string {
	sum := sha256.Sum256([]byte(installationID))
	return fmt.Sprintf("_abm-sr-%x", sum[:10])
}

func darwinSoulRunnerHome(name string) string {
	return path.Join(DarwinHQHomeBase, "agent-bot-soul-runner-"+name)
}

func validateSoulRunnerAccounts(request []SoulRunnerAccount) ([]SoulRunnerAccount, []string, error) {
	invalid := errors.New("invalid per-installation Soul runner accounts")
	if len(request) == 0 || len(request) > 64 {
		return nil, nil, invalid
	}
	runners := slices.Clone(request)
	sort.Slice(runners, func(i, j int) bool { return runners[i].InstallationID < runners[j].InstallationID })
	accounts := make([]string, 0, len(runners))
	previous := ""
	seenAccounts := map[string]bool{}
	for _, r := range runners {
		if !soulIdentity.MatchString(r.SoulID) || !soulInstallationID.MatchString(r.InstallationID) ||
			r.InstallationID <= previous || r.Account != soulRunnerName(r.InstallationID) || !accountName.MatchString(r.Account) || seenAccounts[r.Account] {
			return nil, nil, invalid
		}
		accounts = append(accounts, r.Account)
		seenAccounts[r.Account] = true
		previous = r.InstallationID
	}
	sort.Strings(accounts)
	return runners, accounts, nil
}

func soulRunnerAccountStep(name string, h Host, uids map[int]string) (Step, error) {
	home := darwinSoulRunnerHome(name)
	want := Step{Kind: KindAccount, Target: name, Group: name, Mode: "0700",
		Detail: fmt.Sprintf("Soul runner home %s, shell %s, private group, no password, no other groups", home, DarwinNoLoginShell)}
	a, exists, err := h.Account(name)
	if err != nil {
		return Step{}, err
	}
	if !exists {
		if _, occupied, err := h.Lstat(home); err != nil {
			return Step{}, err
		} else if occupied {
			return Step{}, refuse(RefusedPath, "Soul runner home already exists without its account")
		}
		want.Action = ActionCreate
		return want, nil
	}
	if a.DarwinRole != darwinSoulRunnerRoleName || a.Home != home || a.Shell != DarwinNoLoginShell || a.UID != a.GID || a.Group != name || a.UID < 300 || a.UID > 399 || uids[a.UID] != "" {
		return Step{}, refuse(RefusedAccount, "existing Soul runner is not a dedicated managed role")
	}
	if others, extra := sharing(a); len(others) > 0 || len(extra) > 0 {
		return Step{}, refuse(RefusedAccount, "Soul runner has a shared primary group or another group")
	}
	uids[a.UID] = name
	e, ok, err := h.Lstat(home)
	if err != nil {
		return Step{}, err
	}
	if !ok || !e.Dir || e.Owner != name || e.Group != name {
		return Step{}, refuse(RefusedPath, "Soul runner home is not private to its managed role")
	}
	want.Action, want.Detail = ActionNone, fmt.Sprintf("exists; Soul runner home %s; its password is checked at apply", home)
	if e.Mode != 0700 {
		want.Action = ActionRepair
		want.Detail = accountHomeRepairDetail(home, e.Mode&07777)
	}
	return want, nil
}

func buildSoulRunnerAccounts(in Input, h Host) (Plan, error) {
	if in.Platform != PlatformDarwin || in.HQAccount != DarwinHQAccount || in.SoulBridgeAccounts != nil || in.HarnessLaunch != nil || in.HQService != nil || in.UpgradeFrom != nil || in.HarnessAccounts || in.Dir != DarwinDir || len(in.Members) != 0 {
		return Plan{}, refuse(RefusedList, "Soul runners require a separate dedicated Darwin account plan")
	}
	runners, accounts, err := validateSoulRunnerAccounts(in.SoulRunnerAccounts)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: accounts, SoulRunners: runners, Purpose: SoulRunnerAccountsPurpose}
	uids := map[int]string{}
	hq, err := hqAccountStep(in, h, uids)
	if err != nil {
		return Plan{}, err
	}
	if hq.Action != ActionNone || hq.Mode == "" {
		return Plan{}, refuse(RefusedAccount, "Soul runners need an existing dedicated HQ account")
	}
	p.Steps = append(p.Steps, hq)
	for _, name := range accounts {
		step, err := soulRunnerAccountStep(name, h, uids)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, step)
	}
	if err := bindHarnessAccounts(&p, h); err != nil {
		return Plan{}, err
	}
	p.Purpose = SoulRunnerAccountsPurpose
	raw, err := p.Canonical()
	if err != nil || len(raw) > 32*1024 {
		return Plan{}, errors.New("Soul runner account plan exceeds the paired review limit")
	}
	return p, nil
}
