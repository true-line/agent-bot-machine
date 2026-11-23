package members

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQualificationAdmissionRequiresInstalledVerificationAndConsumesOnce(t *testing.T) {
	path, expected, now := qualificationClaimFixture(t)
	approval := Approval{
		Purpose: expected.Purpose, PlanID: expected.PlanID, PlanDigest: expected.PlanDigest,
		MachineFingerprint: expected.MachineFingerprint, PairCommitment: expected.PairCommitment,
		ApprovedAt: now.Add(-time.Minute).Format(approvalTime),
		ExpiresAt:  now.Add(ApprovalTTL - time.Minute).Format(approvalTime),
	}
	saved := Saved{PlanID: approval.PlanID, PlanDigest: approval.PlanDigest, QualificationRun: &QualificationRun{
		RequestSHA256: expected.RequestSHA256, MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates(),
	}}
	var inGuard bool
	guard := func(_ Approval, run func() error) error {
		inGuard = true
		defer func() { inGuard = false }()
		return run()
	}
	check := func(Saved, string, int) error { return nil }
	claim := func(_ string, attempt QualificationAttempt) error {
		if !inGuard {
			t.Fatal("claim ran outside the live pairing guard")
		}
		return claimQualificationAttemptFile(path, attempt)
	}
	admit := func(verify func(QualificationRun) error) (QualificationAttempt, error) {
		return admitQualificationRun(saved, approval, expected.Owner, 301, guard, func() time.Time { return now }, check, verify, claim)
	}
	if _, err := admit(nil); !errors.Is(err, errQualificationAdmissionUnavailable) {
		t.Fatalf("missing verifier permitted admission: %v", err)
	}
	if _, err := admit(func(QualificationRun) error { return fs.ErrPermission }); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("installed-input refusal lost: %v", err)
	}
	refusePair := func(Approval, func() error) error { return fs.ErrPermission }
	shouldNotVerify := func(QualificationRun) error { t.Fatal("unbound admission checked installed inputs"); return nil }
	if _, err := admitQualificationRun(saved, approval, expected.Owner, 301, refusePair, func() time.Time { return now }, check, shouldNotVerify, claim); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unbound approval permitted admission: %v", err)
	}
	verify := func(run QualificationRun) error {
		if !inGuard || run.RequestSHA256 != expected.RequestSHA256 {
			t.Fatal("verifier did not receive the exact guarded run")
		}
		return nil
	}
	if got, err := admit(verify); err != nil || got != expected {
		t.Fatalf("admission did not create the expected claim: %+v, %v", got, err)
	}
	if _, err := admit(verify); !errors.Is(err, errQualificationApprovalSpent) {
		t.Fatalf("replayed qualification approval: %v", err)
	}
}

func TestAdminQualificationLedgerRejectsReplayAndUnsafeState(t *testing.T) {
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Skip("qualification ledger requires the non-root Machine account")
	}
	_, attempt, _ := qualificationClaimFixture(t)
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := claimAdminQualificationAttempt(state, attempt); err == nil {
		t.Fatal("qualification ledger accepted non-private Machine state")
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(state, qualificationAttemptsDir)
	if err := os.Symlink(t.TempDir(), ledger); err != nil {
		t.Fatal(err)
	}
	if err := claimAdminQualificationAttempt(state, attempt); err == nil {
		t.Fatal("qualification ledger followed a symlink")
	}
	if err := os.Remove(ledger); err != nil {
		t.Fatal(err)
	}
	if err := claimAdminQualificationAttempt(state, attempt); err != nil {
		t.Fatal(err)
	}
	if err := claimAdminQualificationAttempt(state, attempt); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("persistent ledger admitted replay: %v", err)
	}
}
