package members

import (
	"bytes"
	"errors"
	"strconv"
)

// CheckDarwinHQRecovery verifies the saved service-only plan as ordinary
// root apply will rebuild it. No service is started and no account changed.
func CheckDarwinHQRecovery(saved Saved, owner string, uid int) error {
	return checkDarwinHQRecovery(saved, owner, uid, OSHost{}, loadedLaunchDaemon)
}

func checkDarwinHQRecovery(saved Saved, owner string, uid int, host Host, loaded func(HQService, string) (bool, string, error)) error {
	p := saved.Plan
	invalid := errors.New("service recovery requires the existing dedicated role and its exact stopped service plan")
	if saved.HQService == nil || p.Version != PlanVersion || p.HQAccount != DarwinHQAccount || p.Dir != DarwinDir || p.Members == nil || len(p.Members) != 0 || len(p.Steps) != 2 {
		return invalid
	}
	role, service := p.Steps[0], p.Steps[1]
	if role.Kind != KindHQAccount || role.Action != ActionNone || role.Target != DarwinHQAccount || role.Group != DarwinHQAccount || role.Mode != "0700" ||
		service.Kind != KindService || service.Target != launchLabel || (service.Action != ActionCreate && service.Action != ActionWrite) || service.Owner != owner {
		return invalid
	}
	actual, exists, err := host.Account(DarwinHQAccount)
	if err != nil || !exists || actual.Name != DarwinHQAccount || actual.UID != uid || uid < 300 || uid > 399 || actual.GID != uid || actual.DarwinRole != darwinHQRoleName ||
		actual.Shell != DarwinNoLoginShell || actual.Home != HQHome(PlatformDarwin, DarwinHQAccount) {
		return invalid
	}
	rebuilt, err := Build(Input{Platform: PlatformDarwin, HQAccount: DarwinHQAccount, Dir: DarwinDir, Invoker: owner, HQService: saved.HQService}, host)
	if err != nil {
		return invalid
	}
	want, err := p.Canonical()
	if err != nil {
		return invalid
	}
	got, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(want, got) {
		return invalid
	}
	running, pid, err := loaded(*saved.HQService, owner)
	if err != nil {
		return invalid
	}
	if running && pid != "" {
		n, err := strconv.Atoi(pid)
		if err != nil || n != 0 {
			return invalid
		}
	}
	return nil
}
