package members

import (
	"errors"
	"slices"
)

const HarnessAccountsPurpose = "harness-account-provision"

// bindHarnessAccounts pins the identities the ordinary account planner referred to
// by name. The first free local/directory service ID is selected again under the
// role creation lock and must still match, otherwise no record is created.
func bindHarnessAccounts(p *Plan, h Host) error {
	if p.Steps[0].Action != ActionNone || p.Steps[0].Group != DarwinHQAccount {
		return refuse(RefusedAccount, "paired provisioning requires an unchanged dedicated HQ account")
	}
	if err := trustedPath(h, "/private/var", true); err != nil {
		return err
	}
	inspector, ok := h.(interface {
		CheckDarwinACLs([]string) error
		PrivateDarwinRoleGroup(string, int) (bool, error)
	})
	if !ok {
		return errors.New("Darwin account privacy inspection unavailable")
	}
	var fresh []string
	homes := pathAncestry("/private/var")
	for i := range p.Steps {
		s := &p.Steps[i]
		if s.Action == ActionCreate {
			fresh = append(fresh, s.Target)
			continue
		}
		a, ok, err := h.Account(s.Target)
		if err != nil {
			return err
		}
		if !ok || a.Name != s.Target || a.UID < 300 || a.UID > 399 || a.GID != a.UID {
			return refuse(RefusedAccount, "unexpected dedicated identity for %s", s.Target)
		}
		if i == 0 && (a.Home != HQHome(PlatformDarwin, DarwinHQAccount) || a.DarwinRole != darwinHQRoleName || a.Shell != DarwinNoLoginShell) {
			return refuse(RefusedAccount, "unexpected dedicated HQ role")
		}
		if i == 0 {
			private, err := inspector.PrivateDarwinRoleGroup(a.Name, a.GID)
			if err != nil {
				return err
			}
			if !private {
				return refuse(RefusedAccount, "HQ must have its own private group")
			}
		}
		e, ok, err := h.Lstat(a.Home)
		if err != nil {
			return err
		}
		if !ok || !e.Dir || e.Owner != s.Target || e.Group != s.Target {
			return refuse(RefusedPath, "unexpected dedicated home for %s", s.Target)
		}
		homes = append(homes, a.Home)
		s.UID, s.GID = a.UID, a.GID
	}
	if err := inspector.CheckDarwinACLs(homes); err != nil {
		return err
	}
	if len(fresh) > 0 {
		source, ok := h.(interface {
			PlanHarnessIDs([]string) (map[string]int, error)
		})
		if !ok {
			return errors.New("Darwin role ID inspection unavailable")
		}
		ids, err := source.PlanHarnessIDs(fresh)
		if err != nil {
			return err
		}
		for i := range p.Steps {
			s := &p.Steps[i]
			if s.Action == ActionCreate {
				s.UID = ids[s.Target]
				s.GID = s.UID
			}
		}
	}
	seen := map[int]bool{}
	for _, s := range p.Steps {
		if s.UID < 300 || s.UID > 399 || seen[s.UID] {
			return refuse(RefusedAccount, "unexpected or duplicate dedicated role ID")
		}
		seen[s.UID] = true
	}
	p.Purpose = HarnessAccountsPurpose
	return nil
}

func CheckDarwinHarnessAccounts(s Saved, owner string, uid int) error {
	return checkDarwinHarnessAccounts(s, owner, uid, OSHost{})
}

func checkDarwinHarnessAccounts(s Saved, owner string, uid int, h Host) error {
	p := s.Plan
	if s.HQService != nil || s.UpgradeFrom != nil || s.HarnessLaunch != nil || !ValidApproval(s.PlanID, s.PlanDigest) || p.Purpose != HarnessAccountsPurpose || len(p.Steps) == 0 || p.Steps[0].UID != uid {
		return errors.New("saved plan is not for this paired HQ and account operation")
	}
	digest, err := p.Digest()
	if err != nil || digest != s.PlanDigest {
		return errors.New("saved account plan digest mismatch")
	}
	rebuilt, err := Build(Input{HarnessAccounts: true, HQAccount: p.HQAccount, Dir: p.Dir, Members: p.Members, Invoker: owner, Platform: PlatformDarwin}, h)
	if err != nil {
		return err
	}
	if rebuilt.Version != p.Version || !slices.Equal(rebuilt.Steps, p.Steps) || !slices.Equal(rebuilt.Members, p.Members) || rebuilt.Dir != p.Dir {
		return errors.New("saved harness account plan differs from current host")
	}
	return nil
}
