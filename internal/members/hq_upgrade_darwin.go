package members

import (
	"bytes"
	"errors"
	"golang.org/x/sys/unix"
	"os/user"
	"strconv"
)

func inspectUpgradeJob(s HQService, owner string) (bool, string, error) {
	kernel, err := unix.Sysctl("kern.osrelease")
	if err != nil || !supportsGuardedUpgrade(kernel) {
		return false, "", errors.New("this kernel cannot guarantee guarded cleanup of the stopped HQ endpoint")
	}
	running, pid, err := loadedLaunchDaemon(s, owner)
	if err != nil || !running {
		return running, pid, err
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return false, "", err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return false, "", err
	}
	report, err := observedSigner(launchRecord{Service: s, OwnerUID: uid}, owner)
	if err != nil {
		return false, "", err
	}
	if report.Backend != "machine" || report.Storage != "hardware" {
		return false, "", errors.New("the current HQ signer requires a separate custody migration before a service-only upgrade")
	}
	return true, pid, nil
}
func CheckDarwinHQUpgrade(saved Saved, owner string, uid int) error {
	h := OSHost{}
	role, ok, err := h.Account(DarwinHQAccount)
	if err != nil || !ok || role.UID != uid || uid < 300 || uid > 399 || role.GID != uid || role.DarwinRole != darwinHQRoleName || saved.UpgradeFrom == nil || saved.HQService == nil {
		return errors.New("upgrade requires the paired dedicated HQ role and prior applied plan")
	}
	p, err := Build(Input{Platform: PlatformDarwin, Invoker: owner, HQAccount: DarwinHQAccount, HQService: saved.HQService, UpgradeFrom: saved.UpgradeFrom}, h)
	if err != nil {
		return err
	}
	a, err := p.Canonical()
	if err != nil {
		return err
	}
	b, err := saved.Plan.Canonical()
	if err != nil || !bytes.Equal(a, b) {
		return errors.New("saved upgrade no longer matches the active service")
	}
	return nil
}
