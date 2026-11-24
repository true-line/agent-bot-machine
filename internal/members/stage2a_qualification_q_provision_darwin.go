package members

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const (
	stage2aQualificationQFirst     = 450
	stage2aQualificationQLast      = 479
	stage2aQualificationQRoleHome  = "/private/var/db/managed-machine/qualification-q-home"
	stage2aQualificationQRoleLabel = "Agent Bot independent qualification observer"
)

func stage2aQualificationQID(id int) bool {
	return id >= stage2aQualificationQFirst && id <= stage2aQualificationQLast
}

func freeStage2aQualificationQID(users, groups map[string]string, directoryUsed func(string) (bool, error)) (int, error) {
	used := make(map[string]bool)
	for _, records := range []map[string]string{users, groups} {
		for _, id := range records {
			used[id] = true
		}
	}
	for id := stage2aQualificationQFirst; id <= stage2aQualificationQLast; id++ {
		num := strconv.Itoa(id)
		if used[num] {
			continue
		}
		reserved, err := directoryUsed(num)
		if err != nil {
			return 0, err
		}
		if !reserved {
			return id, nil
		}
	}
	return 0, errors.New("no unused Stage 2a qualification Q identity")
}

// provisionStage2aQualificationQ must be called only by reviewed owner apply.
// Its private directory and rule are new; no existing paths are adopted.
// A successful transaction leaves independently identifiable rollback inputs.
func provisionStage2aQualificationQ(machineAccount, launcherSHA, planID string,
	config, source, observer, saved []byte, install stage2aQualificationQInstall) (result error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !stage2aQualificationQID(install.UID) ||
		install.UID != install.GID || len(config) == 0 || len(config) > 8192 || len(source) == 0 ||
		len(source) > 256<<10 || len(observer) == 0 || len(observer) > 256<<10 ||
		stage2aQualificationSHA256(source) != "sha256:"+install.Source.SHA256 ||
		stage2aQualificationSHA256(observer) != "sha256:"+install.PS.SHA256 {
		return errStage2aReservationAuthority
	}
	if install.LauncherSHA256 != launcherSHA || !ValidApproval(planID, install.Review.PlanDigest) {
		return errStage2aReservationAuthority
	}
	admin, ok, err := (OSHost{}).Account(machineAccount)
	if err != nil || !ok || admin.UID != install.AdminUID || admin.GID != install.AdminGID || admin.UID <= 0 || stage2aQualificationQID(admin.UID) {
		return errStage2aReservationAuthority
	}
	for _, path := range []string{stage2aQualificationQRule, stage2aQualificationQPlist, stage2aQualificationQTrigger, stage2aQualificationQHome,
		stage2aQualificationQSocket, stage2aQualificationQRoleHome} {
		if err := trustedPath(OSHost{}, filepath.Dir(path), true); err != nil {
			return err
		}
		if err := checkDarwinACLs(pathAncestry(filepath.Dir(path))); err != nil {
			return err
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("qualification install destination already occupied: %s", path)
		}
	}
	if loaded, err := stage2aQualificationQLaunchdLoaded(); err != nil || loaded {
		return errStage2aReservationAuthority
	}
	if err := verifyHarnessExecutableLimit(SoulLauncher, launcherSHA, 512<<20); err != nil {
		return err
	}
	if err := darwinCreateRoleAccountUsing(stage2aQualificationQAccount, stage2aQualificationQRoleHome,
		stage2aQualificationQRoleLabel, install.UID, freeStage2aQualificationQID); err != nil {
		return err
	}
	var undo []func() error
	undo = append(undo, func() error {
		return errors.Join(runProgram(dsclPath, ".", "-delete", "/Users/"+stage2aQualificationQAccount),
			runProgram(dsclPath, ".", "-delete", "/Groups/"+stage2aQualificationQAccount),
			os.Remove(stage2aQualificationQRoleHome))
	})
	defer func() {
		if result != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				result = errors.Join(result, undo[i]())
			}
		}
	}()
	stockNames := map[int]string{12: "everyone", 61: "localaccounts", 100: "_lpoperator", 701: "com.apple.sharepoint.group.1"}
	for _, gid := range install.SupplementalGIDs {
		value, found, err := dsclAttr("/Groups/"+stockNames[gid], "PrimaryGroupID")
		if err != nil || !found || value != strconv.Itoa(gid) {
			return errStage2aReservationAuthority
		}
	}
	if err := os.Mkdir(stage2aQualificationQHome, 0755); err != nil {
		return err
	}
	undo = append(undo, func() error { return os.Remove(stage2aQualificationQHome) })
	for _, input := range []struct {
		name  string
		bytes []byte
		mode  os.FileMode
	}{
		{"installed.json", config, 0444}, {"qualification-runner.mjs", source, 0444},
		{"process-observer", observer, 0555},
		{"observer.sb", []byte(stage2aQualificationQSandbox(install)), 0444},
	} {
		path := filepath.Join(stage2aQualificationQHome, input.name)
		if err := writeUpgradeFile(path, input.bytes, input.mode, true); err != nil {
			return err
		}
		undo = append(undo, func() error { return os.Remove(path) })
	}
	savedPath := stage2aQualificationQPlanPath
	if err := writeUpgradeFile(savedPath, saved, 0600, true); err != nil {
		return err
	}
	undo = append(undo, func() error { return os.Remove(savedPath) })
	if err := os.Lchown(savedPath, admin.UID, admin.GID); err != nil {
		return err
	}
	if _, err := loadStage2aQualificationQInstall(); err != nil {
		return err
	}
	if err := os.Mkdir(stage2aQualificationQSocket, 0700); err != nil {
		return err
	}
	undo = append(undo, func() error { return os.Remove(stage2aQualificationQSocket) })
	if err := os.Chown(stage2aQualificationQSocket, install.AdminUID, install.GID); err != nil {
		return err
	}
	if err := os.Chmod(stage2aQualificationQSocket, os.ModeSetgid|0710); err != nil {
		return err
	}
	if err := syncUpgradeDir(filepath.Dir(stage2aQualificationQSocket)); err != nil {
		return err
	}
	// Publish and bootstrap a fixed non-root job only after all reviewed
	// inputs are in place. The A-owned socket is the sole trigger.
	plist := renderStage2aQualificationQLaunchd(install)
	if err := writeUpgradeFile(stage2aQualificationQPlist, plist, 0644, true); err != nil {
		return err
	}
	undo = append(undo, func() error { return withdrawStage2aQualificationQLaunchd(install) })
	if err := runProgram("/usr/bin/plutil", "-lint", stage2aQualificationQPlist); err != nil {
		return err
	}
	if err := runProgram("/bin/launchctl", "bootstrap", "system", stage2aQualificationQPlist); err != nil {
		return err
	}
	if loaded, err := stage2aQualificationQLaunchdLoaded(); err != nil || !loaded {
		return errStage2aReservationAuthority
	}
	return checkStage2aQualificationQTrigger(install)
}
