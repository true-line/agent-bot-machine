//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
	"golang.org/x/sys/unix"
)

func runSoulProtectedRetireApply(s Saved, a Approval, owner string, h Host, deps Deps,
	paired func(Approval, func() error) error) cli.Result {
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "protected Soul retirement refused: %v", err)
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || deps.Root != nil ||
		a.Purpose != SoulProtectedLaunchRetirePurpose || a.PlanID != s.PlanID ||
		a.PlanDigest != s.PlanDigest || !digestPattern.MatchString(a.PairCommitment) ||
		!digestPattern.MatchString(a.MachineFingerprint) || s.SoulProtectedRetire == nil {
		return refused(errors.New("root and exact paired owner proof are required"))
	}
	var installed Plan
	if json.Unmarshal(s.SoulProtectedRetire.InstalledPlan, &installed) != nil || installed.SoulProtectedLaunch == nil {
		return refused(errStage2aReservationAuthority)
	}
	var p stage2aInstalledPolicy
	if json.Unmarshal(installed.SoulProtectedLaunch.Policy, &p) != nil ||
		CheckDarwinSoulProtectedRetire(s, owner, p.HQUID) != nil {
		return refused(errStage2aReservationAuthority)
	}
	key, err := hex.DecodeString(installed.SoulProtectedLaunch.MachinePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize ||
		fmt.Sprintf("%x", sha256.Sum256(key)) != a.MachineFingerprint {
		return refused(errors.New("reviewed Machine key differs from paired signer"))
	}
	authorize := harnessAuthority(a, upgradePairGuard(paired), deps.Time)
	if err := authorize(nil); err != nil {
		return refused(err)
	}
	rootReceiptPath := filepath.Join("/private"+DarwinReceiptsDir, s.SoulProtectedRetire.InstalledPlanID+".json")
	installedReceipt, err := stage2aReadRootFile(rootReceiptPath, 256<<10, 0644)
	var old Receipt
	if err != nil || json.Unmarshal(installedReceipt, &old) != nil || old.Result != "applied" ||
		old.PlanID != s.SoulProtectedRetire.InstalledPlanID ||
		old.PlanDigest != s.SoulProtectedRetire.InstalledPlanDigest || old.Owner != owner {
		return refused(errors.New("original root installation receipt is not applied"))
	}
	root := OSRoot{}
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner,
		HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: s.Plan.Members,
		Changes: s.Plan.Changes(), Result: "started"}
	if err := authorize(func() error {
		receipt.StartedAt = deps.Time().UTC().Format(approvalTime)
		claimed, err := root.Claim(s.PlanID, encodeReceipt(receipt))
		if err != nil {
			return err
		}
		if !claimed {
			return errors.New("protected Soul retirement approval already used")
		}
		return syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID)))
	}); err != nil {
		return refused(err)
	}
	retireErr := authorize(func() error {
		return stage2aDisableInstalledSoul(p, s.SoulProtectedRetire, installed, installedReceipt, key, s.PlanID)
	})
	if retireErr == nil {
		retireErr = authorize(func() error {
			receipt.Result = "applied"
			receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
			if err := root.Finish(s.PlanID, encodeReceipt(receipt)); err != nil {
				return err
			}
			return syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID)))
		})
	}
	if retireErr != nil {
		receipt.Result, receipt.FailedAt = "failed", "protected Soul retirement"
		receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
		retireErr = errors.Join(retireErr, root.Finish(s.PlanID, encodeReceipt(receipt)))
		return failure(diag.MembersApplyFailed, "protected Soul retirement stopped: %v", retireErr)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", s.PlanID).
		Set("plan_digest", s.PlanDigest).Set("applied", true).Set("receipt", ReceiptPath(s.PlanID))}}
}

func stage2aDisableInstalledSoul(template stage2aInstalledPolicy, retire *SoulProtectedLaunchRetire, installed Plan, receipt, key []byte, retirePlanID string) error {
	installationID := template.Binding.InstallationID
	policyPath, err := stage2aAuthorityPath(installationID)
	if err != nil {
		return err
	}
	claimPath := filepath.Join(stage2aClaimsParent, soulEndpointInstallationSlot(installationID))
	claimDir, err := openStage2aAdminDirectory(claimPath, uint32(template.MachineUID))
	if err != nil {
		return err
	}
	defer claimDir.Close()
	if _, err := stage2aInstalledDirectoryIdentity(claimPath, template.MachineUID, template.MachineGID, 0700); err != nil {
		return err
	}
	lock, err := stage2aRootRetireLock(claimDir, installationID, uint32(template.MachineUID), uint32(template.MachineGID))
	if err != nil {
		return err
	}
	defer lock.Close()
	if requireIdleHarnessRoles([]HarnessAdapter{{Account: template.Runner.Account, UID: template.Runner.UID},
		{Account: template.Bridge.Account, UID: template.Bridge.UID}}, unix.SysctlKinfoProcSlice) != nil {
		return errStage2aReservationAuthority
	}
	if err := stage2aRetirePolicy(policyPath, template, retire, installed, receipt, key); err != nil {
		return err
	}
	rulePath := stage2aInstallRulePath(installationID)
	rule, err := RenderSoulProtectedRule([]SoulRunner{template.Runner}, []SoulBridge{template.Bridge}, template.HQUID, nil, template.LauncherSHA256)
	if err != nil {
		return err
	}
	if err := stage2aRetireRule(rulePath, []byte(rule)); err != nil {
		return err
	}
	if requireIdleHarnessRoles([]HarnessAdapter{{Account: template.Runner.Account, UID: template.Runner.UID},
		{Account: template.Bridge.Account, UID: template.Bridge.UID}}, unix.SysctlKinfoProcSlice) != nil {
		return errStage2aReservationAuthority
	}
	// The A daemon may have crashed with a spent active name. Once the
	// authority and sudo rule are gone and both UIDs remain idle, retire that
	// exact name without discarding the audit claim.
	return stage2aRootRetireActive(claimDir, installationID, retirePlanID, uint32(template.MachineUID), uint32(template.MachineGID))
}

func stage2aRootRetireActive(dir *os.File, installationID, retirePlanID string, uid, gid uint32) error {
	if !ValidApproval(retirePlanID, fmt.Sprintf("%064d", 0)) {
		return errStage2aReservationAuthority
	}
	active := stage2aActiveClaimName(installationID)
	retired := ".stage2a-retired-" + soulEndpointInstallationSlot(installationID) + "-" + retirePlanID
	if err := requireUnspentStage2aReservation(dir, active); err == nil {
		return nil
	} else if !errors.Is(err, errStage2aReservationSpent) {
		return err
	}
	if err := stage2aCheckSpentClaim(dir, active, uid, gid); err != nil {
		return err
	}
	if err := unix.RenameatxNp(int(dir.Fd()), active, int(dir.Fd()), retired, unix.RENAME_EXCL); err != nil {
		return err
	}
	return dir.Sync()
}

func stage2aRootRetireLock(dir *os.File, installationID string, uid, gid uint32) (*os.File, error) {
	name := ".stage2a-" + soulEndpointInstallationSlot(installationID) + ".lock"
	flags := unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_RDWR | unix.O_NONBLOCK
	fd, err := unix.Openat(int(dir.Fd()), name, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(int(dir.Fd()), name, flags|unix.O_CREAT|unix.O_EXCL, 0600)
		if err == nil {
			if err = unix.Fchown(fd, int(uid), int(gid)); err == nil {
				err = unix.Fchmod(fd, 0600)
			}
			if err != nil {
				unix.Close(fd)
				return nil, err
			}
		} else if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(int(dir.Fd()), name, flags, 0)
		}
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600) != nil || unix.Flock(fd, unix.LOCK_EX) != nil {
		file.Close()
		return nil, errStage2aReservationAuthority
	}
	return file, nil
}

func stage2aRetirePolicy(path string, template stage2aInstalledPolicy, retire *SoulProtectedLaunchRetire, installed Plan, receipt, key []byte) error {
	dir, err := openStage2aAdminDirectory(stage2aAuthorityDirectory, uint32(template.MachineUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	name := filepath.Base(path)
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st, after unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0400 || st.Uid != uint32(template.MachineUID) ||
		st.Gid != uint32(template.MachineGID) || st.Nlink != 1 || st.Size <= 0 || st.Size > 1<<20 ||
		checkDarwinACLs([]string{path}) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	var p stage2aInstalledPolicy
	if err != nil || int64(len(raw)) != st.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) ||
		stage2aStrictJSON(raw) != nil || json.Unmarshal(raw, &p) != nil ||
		p.Binding.InstallationID != template.Binding.InstallationID ||
		p.Binding.PlanID != retire.InstalledPlanID ||
		p.Binding.InstalledPlanDigest != retire.InstalledPlanDigest ||
		!bytes.Equal(p.Receipt, receipt) || !bytes.Equal(p.Plan, bytes.TrimSpace(retire.InstalledPlan)) ||
		!stage2aInstalledPolicyMatchesPlan(p, installed, ed25519.PublicKey(key)) {
		return errStage2aReservationAuthority
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		return err
	}
	return dir.Sync()
}

func stage2aRetireRule(path string, expected []byte) error {
	dir, err := openStage2aAdminDirectory(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	raw, err := stage2aReadRootFile(path, int64(len(expected)), 0440)
	if err != nil || !bytes.Equal(raw, expected) {
		return errStage2aReservationAuthority
	}
	if err := unix.Unlinkat(int(dir.Fd()), filepath.Base(path), 0); err != nil {
		return err
	}
	return dir.Sync()
}
