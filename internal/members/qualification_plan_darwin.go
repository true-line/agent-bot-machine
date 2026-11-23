package members

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func verifyQualificationExecutable(path, digest string) error {
	return verifyHarnessExecutableLimit(path, digest, 2<<30)
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
	if err := checkQualificationRole(run.Request.Target.Account, run.Request.Target.UID, h); err != nil {
		return err
	}
	canonical, err := saved.CanonicalForReview()
	sum := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(sum[:]) != saved.PlanDigest {
		return errors.New("saved qualification plan no longer matches its review digest")
	}
	r := run.Request
	files := []qualificationFile{{r.Adapter.PackagePath, r.Adapter.PackageSHA},
		{r.Runner.BinaryPath, r.Runner.BinarySHA}, {r.TestProvider.ConfigPath, r.TestProvider.ConfigSHA}}
	for _, input := range r.Adapter.Launch.CodeInputs {
		files = append(files, qualificationFile{input.Path, input.SHA256})
	}
	if r.Adapter.Launch.CodeInputManifest.Path != "" {
		files = append(files, r.Adapter.Launch.CodeInputManifest)
	}
	if r.Adapter.Launch.Driver.Path != "" {
		files = append(files, r.Adapter.Launch.Driver)
	}
	for _, file := range append(files, qualificationCandidateFiles(r)...) {
		if err := verifyQualificationFile(file); err != nil {
			return err
		}
	}
	for _, file := range []qualificationFile{{r.Adapter.Launch.Executable, r.Adapter.Launch.ExecutableSHA},
		{r.Adapter.Harness.BinaryPath, r.Adapter.Harness.BinarySHA}} {
		if err := verifyQualificationExecutable(file.Path, file.SHA256); err != nil {
			return err
		}
	}
	return nil
}
