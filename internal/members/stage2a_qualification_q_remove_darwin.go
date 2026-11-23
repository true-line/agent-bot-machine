package members

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// RunStage2aQualificationQRemove withdraws the exact Q job first, then
// reverses the witnessed install once the dedicated Q role is idle. It never
// modifies approvals, qualification claims or per-start reservations.
func RunStage2aQualificationQRemove(deps ApplyDeps, args []string) error {
	if len(args) != 1 || !stage2aQualificationDigest(args[0]) || deps.DaemonState == nil {
		return errStage2aReservationAuthority
	}
	owner, home, diagnostic := membersSudoOwner(Deps{ApplyDeps: deps}, "stage2a-qualification-remove")
	if diagnostic != nil {
		return errStage2aReservationAuthority
	}
	_, account, err := deps.DaemonState(owner, home)
	if err != nil || account == owner {
		return errStage2aReservationAuthority
	}
	install, err := loadStage2aQualificationQInstall()
	if err != nil || install.Review.Owner != owner {
		return errStage2aReservationAuthority
	}
	pin := filepath.Join(stage2aQualificationQHome, "installed.json")
	raw, err := os.ReadFile(pin)
	if err != nil || stage2aQualificationSHA256(raw) != args[0] {
		return errStage2aReservationAuthority
	}
	if err := withdrawStage2aQualificationQLaunchd(install); err != nil {
		return err
	}
	if err := requireIdleHarnessRoles([]HarnessAdapter{{Account: stage2aQualificationQAccount, UID: install.UID}}, unix.SysctlKinfoProcSlice); err != nil {
		return err
	}
	role, found, err := (OSHost{}).Account(stage2aQualificationQAccount)
	if err != nil || !found || role.UID != install.UID || role.GID != install.GID ||
		role.Group != stage2aQualificationQAccount || role.Home != stage2aQualificationQRoleHome ||
		role.Shell != DarwinNoLoginShell {
		return errStage2aReservationAuthority
	}
	private, err := (OSHost{}).PrivateDarwinRoleGroup(stage2aQualificationQAccount, install.GID)
	if err != nil || !private {
		return errStage2aReservationAuthority
	}
	var socket unix.Stat_t
	if unix.Lstat(stage2aQualificationQSocket, &socket) != nil ||
		socket.Uid != uint32(install.AdminUID) || socket.Gid != uint32(install.GID) ||
		socket.Mode != unix.S_IFDIR|unix.S_ISGID|0710 {
		return errStage2aReservationAuthority
	}
	if err := os.Remove(stage2aQualificationQSocket); err != nil {
		return err
	}
	if err := os.Remove(stage2aQualificationQRoleHome); err != nil {
		return err
	}
	if err := runProgram(dsclPath, ".", "-delete", "/Users/"+stage2aQualificationQAccount); err != nil {
		return err
	}
	if err := runProgram(dsclPath, ".", "-delete", "/Groups/"+stage2aQualificationQAccount); err != nil {
		return err
	}
	for _, path := range []string{stage2aQualificationQPlanPath, install.Source.Path, install.PS.Path, stage2aQualificationQProfile, pin, stage2aQualificationQHome} {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return syncUpgradeDir(filepath.Dir(stage2aQualificationQHome))
}

func withdrawStage2aQualificationQLaunchd(install stage2aQualificationQInstall) error {
	if _, err := os.Lstat(stage2aQualificationQPlist); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if trustedPath(OSHost{}, stage2aQualificationQPlist, false) != nil ||
		checkDarwinACLs(pathAncestry(stage2aQualificationQPlist)) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := os.ReadFile(stage2aQualificationQPlist)
	if err != nil || string(raw) != string(renderStage2aQualificationQLaunchd(install)) {
		return errStage2aReservationAuthority
	}
	label := "system/" + stage2aQualificationQLabel
	loaded, err := stage2aQualificationQLaunchdLoaded()
	if err != nil {
		return err
	}
	if loaded {
		if err := runProgram("/bin/launchctl", "bootout", label); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(stage2aQualificationQTrigger); err == nil {
		if err := checkStage2aQualificationQTrigger(install); err != nil {
			return err
		}
		if err := os.Remove(stage2aQualificationQTrigger); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(stage2aQualificationQPlist); err != nil {
		return err
	}
	return syncUpgradeDir(filepath.Dir(stage2aQualificationQPlist))
}
