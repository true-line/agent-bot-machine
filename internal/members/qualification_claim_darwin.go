package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// QualificationAttempt is the durable, single-use reservation for one owner
// approved run. A started attempt is spent, including after a process crash.
// It is never a qualification or permission to install a launch rule.
type QualificationAttempt struct {
	Purpose            string `json:"purpose"`
	PlanID             string `json:"plan_id"`
	PlanDigest         string `json:"plan_digest"`
	RequestSHA256      string `json:"request_sha256"`
	MachineFingerprint string `json:"machine_fingerprint"`
	PairCommitment     string `json:"pair_commitment"`
	Owner              string `json:"owner"`
	StartedAt          string `json:"started_at"`
	FinishedAt         string `json:"finished_at,omitempty"`
	Result             string `json:"result"`
	Reason             string `json:"reason,omitempty"`
}

func qualificationAttemptPath(planID string) string {
	return filepath.Join(receiptsDir(), planID+".qualification.json")
}

func newQualificationAttempt(a Approval, run *QualificationRun, owner string, now time.Time) (QualificationAttempt, error) {
	if a.Purpose != HarnessQualificationPurpose || !ValidApproval(a.PlanID, a.PlanDigest) ||
		!digestPattern.MatchString(a.MachineFingerprint) || !digestPattern.MatchString(a.PairCommitment) ||
		run == nil || !qualificationDigest.MatchString(run.RequestSHA256) ||
		run.MemberState != "disposable" || !run.OneUse || !sameQualificationGates(run.Gates) ||
		owner == "" {
		return QualificationAttempt{}, errors.New("invalid paired qualification approval or fixed plan")
	}
	start, e1 := time.Parse(approvalTime, a.ApprovedAt)
	end, e2 := time.Parse(approvalTime, a.ExpiresAt)
	if e1 != nil || e2 != nil || end.Sub(start) != ApprovalTTL || now.Before(start) || !now.Before(end) {
		return QualificationAttempt{}, errors.New("qualification approval is outside its validity window")
	}
	return QualificationAttempt{Purpose: HarnessQualificationPurpose, PlanID: a.PlanID, PlanDigest: a.PlanDigest,
		RequestSHA256: run.RequestSHA256, MachineFingerprint: a.MachineFingerprint,
		PairCommitment: a.PairCommitment, Owner: owner, StartedAt: now.UTC().Format(approvalTime), Result: "started"}, nil
}

// claimApprovedQualificationAttempt is the authorization boundary before a
// future fixed runner. It does not itself execute the candidate. The plan and
// artifacts are rechecked while the original paired HQ remains live, then the
// single-use record is durably claimed in that same guard. A future executor
// must separately verify the physical host and runner protocol before calling
// this boundary, and must recheck executable bytes immediately before spawn.
func claimApprovedQualificationAttempt(saved Saved, a Approval, owner string, hqUID int,
	guard upgradePairGuard, now func() time.Time,
	check func(Saved, string, int) error, claim func(string, QualificationAttempt) error) (QualificationAttempt, error) {
	if guard == nil || now == nil || check == nil || claim == nil ||
		saved.QualificationRun == nil || a.PlanID != saved.PlanID || a.PlanDigest != saved.PlanDigest {
		return QualificationAttempt{}, errors.New("qualification claim needs the exact paired saved plan")
	}
	var attempt QualificationAttempt
	err := guard(a, func() error {
		if err := check(saved, owner, hqUID); err != nil {
			return err
		}
		var err error
		attempt, err = newQualificationAttempt(a, saved.QualificationRun, owner, now())
		if err != nil {
			return err
		}
		return claim(qualificationAttemptPath(saved.PlanID), attempt)
	})
	if err != nil {
		return QualificationAttempt{}, err
	}
	return attempt, nil
}

func claimDarwinQualificationApproval(saved Saved, a Approval, owner string, hqUID int,
	guard upgradePairGuard, now func() time.Time) (QualificationAttempt, error) {
	return claimApprovedQualificationAttempt(saved, a, owner, hqUID, guard, now,
		CheckDarwinHarnessQualification, claimQualificationAttempt)
}

// claimQualificationAttempt publishes a complete record with an exclusive
// rename and syncs the receipt directory. The caller must hold the live-pair
// guard, have checked the saved plan and all artifacts, and run as root.
// Existing records are never replaced, including an interrupted "started".
func claimQualificationAttempt(path string, attempt QualificationAttempt) error {
	if err := trustedPath(OSHost{}, filepath.Dir(path), true); err != nil {
		return fmt.Errorf("qualification receipt directory is not protected: %w", err)
	}
	if err := checkDarwinACLs(pathAncestry(filepath.Dir(path))); err != nil {
		return fmt.Errorf("qualification receipt directory has an ACL: %w", err)
	}
	return claimQualificationAttemptFile(path, attempt)
}

func claimQualificationAttemptFile(path string, attempt QualificationAttempt) error {
	if attempt.Purpose != HarnessQualificationPurpose || !ValidApproval(attempt.PlanID, attempt.PlanDigest) ||
		!qualificationDigest.MatchString(attempt.RequestSHA256) ||
		!digestPattern.MatchString(attempt.MachineFingerprint) || !digestPattern.MatchString(attempt.PairCommitment) ||
		attempt.Owner == "" || attempt.Result != "started" || attempt.StartedAt == "" ||
		attempt.FinishedAt != "" || attempt.Reason != "" || filepath.Base(path) != attempt.PlanID+".qualification.json" {
		return errors.New("invalid qualification claim")
	}
	raw, err := json.Marshal(attempt)
	if err != nil {
		return err
	}
	return writeUpgradeFile(path, append(raw, '\n'), 0600, true)
}

// finishQualificationAttempt records a failed or incomplete attempt in a
// separate immutable file. A crash before this update leaves the spent,
// inspectable "started" claim, and concurrent finishers cannot overwrite one
// another. A local run never becomes a certified result.
func finishQualificationAttempt(path string, started QualificationAttempt, result, reason string, now time.Time) error {
	return finishQualificationAttemptFile(path, started, result, reason, now, readProtectedUpgradeFile)
}

func finishQualificationAttemptFile(path string, started QualificationAttempt, result, reason string, now time.Time, read func(string) ([]byte, error)) error {
	if result != "failed" && result != "incomplete" {
		return errors.New("qualification attempt cannot be certified locally")
	}
	if reason == "" || len(reason) > 256 || hasASCIIControl(reason) {
		return errors.New("qualification attempt needs a bounded reason")
	}
	raw, err := read(path)
	if err != nil {
		return err
	}
	var current QualificationAttempt
	if json.Unmarshal(raw, &current) != nil || current != started || current.Result != "started" {
		return errors.New("qualification attempt changed after claim")
	}
	end, err := time.Parse(approvalTime, started.StartedAt)
	if err != nil || now.Before(end) {
		return errors.New("qualification finish precedes claim")
	}
	current.Result, current.Reason, current.FinishedAt = result, reason, now.UTC().Format(approvalTime)
	updated, err := json.Marshal(current)
	if err != nil {
		return err
	}
	resultPath := filepath.Join(filepath.Dir(path), started.PlanID+".qualification-result.json")
	return writeUpgradeFile(resultPath, append(updated, '\n'), 0600, true)
}

func qualificationAttemptExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
