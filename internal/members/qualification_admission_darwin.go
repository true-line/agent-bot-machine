package members

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	errQualificationAdmissionUnavailable = errors.New("qualification admission requires an authenticated physical runner")
	errQualificationApprovalSpent        = errors.New("qualification approval has already been spent")
)

const qualificationAttemptsDir = "qualification-attempts"

// AdmitDarwinQualificationRun is the Machine A issuer's one-use admission
// boundary. The issuer must supply its privately resolved state directory and
// approval, the live pair guard, and its installed-input verifier. The verifier
// must authenticate the designated physical host, fixed gate plan, provider,
// and installed Q account, Node, runner source, ps and socket policy against
// the reviewed run. A start or stimulus must occur only after admission
// succeeds. Admission is not a per-Soul start reservation or a signed report.
//
// Keep this off the HQ request surface until the production issuer can supply
// those inputs. Never substitute HQ-asserted input or an externally supplied
// state path. The issuer must still recheck executable bytes before spawning.
func AdmitDarwinQualificationRun(saved Saved, approval Approval, owner string, hqUID int, state string,
	guard upgradePairGuard, now func() time.Time, verifyInstalled func(QualificationRun) error) (QualificationAttempt, error) {
	return admitQualificationRun(saved, approval, owner, hqUID, guard, now, CheckDarwinHarnessQualification,
		verifyInstalled, func(_ string, attempt QualificationAttempt) error {
			return claimAdminQualificationAttempt(state, attempt)
		})
}

func admitQualificationRun(saved Saved, approval Approval, owner string, hqUID int, guard upgradePairGuard,
	now func() time.Time, checkPlan func(Saved, string, int) error, verifyInstalled func(QualificationRun) error,
	claim func(string, QualificationAttempt) error) (QualificationAttempt, error) {
	if verifyInstalled == nil || checkPlan == nil || claim == nil {
		return QualificationAttempt{}, errQualificationAdmissionUnavailable
	}
	return claimApprovedQualificationAttempt(saved, approval, owner, hqUID, guard, now,
		func(plan Saved, owner string, uid int) error {
			if err := checkPlan(plan, owner, uid); err != nil {
				return err
			}
			return verifyInstalled(*plan.QualificationRun)
		}, func(path string, attempt QualificationAttempt) error {
			err := claim(path, attempt)
			if errors.Is(err, fs.ErrExist) {
				return errQualificationApprovalSpent
			}
			return err
		})
}

func claimAdminQualificationAttempt(state string, attempt QualificationAttempt) error {
	uid := os.Geteuid()
	if uid == 0 || os.Getuid() != uid || !filepath.IsAbs(state) || filepath.Clean(state) != state {
		return errQualificationAdmissionUnavailable
	}
	if err := checkQualificationAdminDir(state, uid); err != nil {
		return err
	}
	ancestors := pathAncestry(filepath.Dir(state))
	for _, path := range ancestors {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || (stat.Uid != 0 && stat.Uid != uint32(uid)) {
			return errors.New("qualification state has an untrusted ancestor")
		}
	}
	if err := checkDarwinACLs(ancestors); err != nil {
		return err
	}
	// A plan already consumed by the original ledger remains spent. An
	// inaccessible legacy ledger blocks admission rather than guessing.
	spent, err := qualificationAttemptExists(qualificationAttemptPath(attempt.PlanID))
	if err != nil {
		return fmt.Errorf("check retained qualification claim: %w", err)
	}
	if spent {
		return fs.ErrExist
	}
	dir := filepath.Join(state, qualificationAttemptsDir)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := checkQualificationAdminDir(dir, uid); err != nil {
		return err
	}
	// Persist the ledger directory entry even when a concurrent first
	// admission created it. The claim writer syncs the ledger itself.
	if err := syncUpgradeDir(state); err != nil {
		return err
	}
	return claimQualificationAttemptFile(filepath.Join(dir, attempt.PlanID+".qualification.json"), attempt)
}

func checkQualificationAdminDir(path string, uid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode() != fs.ModeDir|0o700 || stat.Uid != uint32(uid) {
		return errors.New("qualification attempt directory is not private to Machine A")
	}
	return checkDarwinACLs([]string{path})
}
