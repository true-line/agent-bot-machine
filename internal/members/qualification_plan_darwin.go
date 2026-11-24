package members

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func verifyQualificationExecutable(path, digest string) error {
	return verifyHarnessExecutableLimit(path, digest, 2<<30)
}

func verifyQualificationPendingQSource(f qualificationFile) error {
	if !qualificationDigest.MatchString(f.SHA256) ||
		trustedPath(OSHost{}, f.Path, false) != nil ||
		checkDarwinACLs(pathAncestry(f.Path)) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := stage2aReadInstallSource(f.Path, 256<<10)
	if err != nil || stage2aQualificationSHA256(raw) != "sha256:"+f.SHA256 {
		return errStage2aReservationAuthority
	}
	return nil
}

// CheckDarwinHarnessQualification allows the paired HQ to request an owner
// challenge for an exact review plan. It neither launches the candidate nor
// treats the owner's approval as a reusable qualification.
func CheckDarwinHarnessQualification(saved Saved, owner string, uid int) error {
	run := saved.QualificationRun
	if run == nil || saved.Plan.Purpose != HarnessQualificationPurpose ||
		saved.HarnessLaunch != nil || saved.HQService != nil || saved.UpgradeFrom != nil ||
		!ValidApproval(saved.PlanID, saved.PlanDigest) || owner == "" || owner == run.Request.Target.Account {
		return errors.New("saved plan is not an independent qualification review")
	}
	h := OSHost{}
	hq, found, err := h.Account(DarwinHQAccount)
	others, extra := sharing(hq)
	if err != nil || !found || hq.UID != uid || uid < 300 || uid > 399 ||
		hq.GID != uid || hq.DarwinRole != darwinHQRoleName ||
		hq.Group != DarwinHQAccount || hq.Home != HQHome(PlatformDarwin, DarwinHQAccount) ||
		hq.Shell != DarwinNoLoginShell || len(others) != 0 || len(extra) != 0 {
		return errors.New("qualification owner challenge requires the paired dedicated HQ role")
	}
	private, err := h.PrivateDarwinRoleGroup(DarwinHQAccount, uid)
	if err != nil || !private {
		return errors.New("qualification owner challenge requires a private HQ role group")
	}
	home, found, err := h.Lstat(hq.Home)
	if err != nil || !found || !home.Dir || home.Owner != DarwinHQAccount || home.Group != DarwinHQAccount || home.Mode&0o7777 != 0o700 {
		return errors.New("qualification owner challenge requires the private HQ home")
	}
	if err := checkQualificationTarget(run.Request, h); err != nil {
		return err
	}
	canonical, err := saved.CanonicalForReview()
	sum := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(sum[:]) != saved.PlanDigest {
		return errors.New("saved qualification plan no longer matches its review digest")
	}
	return verifyQualificationReviewFiles(run.Request)
}
