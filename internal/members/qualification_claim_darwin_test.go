package members

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func qualificationClaimFixture(t *testing.T) (string, QualificationAttempt, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 21, 19, 0, 0, 0, time.UTC)
	a := Approval{Purpose: HarnessQualificationPurpose, PlanID: "plan-20261121T190000Z-abcd",
		PlanDigest: strings.Repeat("a", 64), MachineFingerprint: strings.Repeat("b", 64),
		PairCommitment: strings.Repeat("c", 64), ApprovedAt: now.Add(-time.Minute).Format(approvalTime),
		ExpiresAt: now.Add(ApprovalTTL - time.Minute).Format(approvalTime)}
	run := &QualificationRun{RequestSHA256: strings.Repeat("d", 64), MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates()}
	attempt, err := newQualificationAttempt(a, run, "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(t.TempDir(), a.PlanID+".qualification.json"), attempt, now
}

func TestQualificationClaimUsesPhysicalDarwinReceiptAncestry(t *testing.T) {
	_, attempt, _ := qualificationClaimFixture(t)
	want := filepath.Join("/private"+DarwinReceiptsDir, attempt.PlanID+".qualification.json")
	if got := qualificationAttemptPath(attempt.PlanID); got != want {
		t.Fatalf("qualification claim uses %q, want physical path %q", got, want)
	}
	h := emptyHost()
	parent := filepath.Dir(want)
	for _, p := range pathAncestry(parent) {
		h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	}
	// Darwin's /var is a symlink. The wrapper must never traverse it.
	h.entries["/var"] = Entry{Owner: "root", Group: "wheel", Mode: 0755}
	var checkedACL, claimed bool
	checkACL := func(paths []string) error {
		checkedACL = true
		if !slices.Contains(paths, parent) || slices.Contains(paths, "/var") {
			return errors.New("qualification ACL check used logical /var")
		}
		return nil
	}
	claimFile := func(path string, got QualificationAttempt) error {
		claimed = true
		if path != want || got != attempt {
			return errors.New("qualification claim changed its reviewed subject")
		}
		return nil
	}
	if err := claimQualificationAttemptWith(h, checkACL, claimFile, want, attempt); err != nil || !checkedACL || !claimed {
		t.Fatalf("physical receipt ancestry refused: acl=%v claim=%v err=%v", checkedACL, claimed, err)
	}
	claimed = false
	legacy := filepath.Join(DarwinReceiptsDir, attempt.PlanID+".qualification.json")
	if err := claimQualificationAttemptWith(h, checkACL, claimFile, legacy, attempt); err == nil || claimed {
		t.Fatal("logical /var symlink reached a qualification claim")
	}
}

func TestQualificationClaimPhysicalHostAncestry(t *testing.T) {
	parent := filepath.Dir(qualificationAttemptPath("plan-20261121T190000Z-abcd"))
	if _, err := os.Lstat(parent); errors.Is(err, fs.ErrNotExist) {
		t.Skip("Machine receipt tree is not installed on this Mac")
	} else if err != nil {
		t.Fatal(err)
	}
	if err := trustedPath(OSHost{}, parent, true); err != nil {
		t.Fatalf("physical qualification receipt tree was refused: %v", err)
	}
	if err := checkDarwinACLs(pathAncestry(parent)); err != nil {
		t.Fatalf("physical qualification receipt tree has an ACL: %v", err)
	}
	if link, err := os.Lstat("/var"); err == nil && link.Mode()&os.ModeSymlink != 0 {
		if err := trustedPath(OSHost{}, DarwinReceiptsDir, true); err == nil {
			t.Fatal("logical /var symlink unexpectedly passed trusted ancestry")
		}
	}
}

func TestQualificationClaimIsAtomicAndSpentAcrossConcurrentRetries(t *testing.T) {
	path, attempt, _ := qualificationClaimFixture(t)
	const contenders = 24
	var wg sync.WaitGroup
	results := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- claimQualificationAttemptFile(path, attempt) }()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("unexpected concurrent claim result: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d claims succeeded; expected exactly one", won)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var found QualificationAttempt
	if json.Unmarshal(raw, &found) != nil || found != attempt || found.Result != "started" {
		t.Fatalf("claim is not a complete inspectable started record: %s", raw)
	}
	if mode := (func() os.FileMode { s, _ := os.Stat(path); return s.Mode().Perm() })(); mode != 0600 {
		t.Fatalf("claim mode %o, want 0600", mode)
	}
	if err := claimQualificationAttemptFile(path, attempt); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("interrupted started claim became reusable: %v", err)
	}
}

func TestQualificationClaimRejectsPreexistingSymlinkAndNeverCertifies(t *testing.T) {
	path, attempt, now := qualificationClaimFixture(t)
	other := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(other, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if err := claimQualificationAttemptFile(path, attempt); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("claim replaced an occupied path: %v", err)
	}
	if raw, _ := os.ReadFile(other); string(raw) != "keep" {
		t.Fatal("occupied symlink target changed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := claimQualificationAttemptFile(path, attempt); err != nil {
		t.Fatal(err)
	}
	if err := finishQualificationAttemptFile(path, attempt, "passed", "", now, os.ReadFile); err == nil {
		t.Fatal("local claim issued a qualification")
	}
	if err := finishQualificationAttemptFile(path, attempt, "failed", "runner was interrupted", now.Add(time.Second), os.ReadFile); err != nil {
		t.Fatal(err)
	}
	claim, _ := os.ReadFile(path)
	var persisted QualificationAttempt
	if json.Unmarshal(claim, &persisted) != nil || persisted != attempt {
		t.Fatal("immutable started claim was changed")
	}
	resultPath := filepath.Join(filepath.Dir(path), attempt.PlanID+".qualification-result.json")
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &persisted) != nil || persisted.Result != "failed" || persisted.Reason != "runner was interrupted" {
		t.Fatalf("final result is not inspectable: %s", raw)
	}
	if err := claimQualificationAttemptFile(path, attempt); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("failed claim became reusable: %v", err)
	}
	if err := finishQualificationAttemptFile(path, attempt, "incomplete", "retry", now.Add(2*time.Second), os.ReadFile); err == nil {
		t.Fatal("finalized attempt was overwritten")
	}
}

func TestQualificationClaimRequiresExactPairedApproval(t *testing.T) {
	path, attempt, now := qualificationClaimFixture(t)
	for _, change := range []func(*QualificationAttempt){
		func(a *QualificationAttempt) { a.Purpose = "harness-launch-install" },
		func(a *QualificationAttempt) { a.PairCommitment = "" },
		func(a *QualificationAttempt) { a.Result = "passed" },
		func(a *QualificationAttempt) { a.Reason = "already ran" },
	} {
		bad := attempt
		change(&bad)
		if err := claimQualificationAttemptFile(path, bad); err == nil {
			t.Fatal("invalid claim was published")
		}
	}
	if exists, _ := qualificationAttemptExists(path); exists {
		t.Fatal("refused claim created a receipt")
	}
	a := Approval{Purpose: HarnessQualificationPurpose, PlanID: attempt.PlanID, PlanDigest: attempt.PlanDigest,
		MachineFingerprint: attempt.MachineFingerprint, PairCommitment: attempt.PairCommitment,
		ApprovedAt: now.Add(-ApprovalTTL).Format(approvalTime), ExpiresAt: now.Format(approvalTime)}
	run := &QualificationRun{RequestSHA256: attempt.RequestSHA256, MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates()}
	if _, err := newQualificationAttempt(a, run, attempt.Owner, now); err == nil {
		t.Fatal("expired owner approval accepted")
	}
}

func TestQualificationClaimRequiresLivePairAndFreshArtifactReview(t *testing.T) {
	path, expected, now := qualificationClaimFixture(t)
	a := Approval{Purpose: HarnessQualificationPurpose, PlanID: expected.PlanID, PlanDigest: expected.PlanDigest,
		MachineFingerprint: expected.MachineFingerprint, PairCommitment: expected.PairCommitment,
		ApprovedAt: now.Add(-time.Minute).Format(approvalTime), ExpiresAt: now.Add(ApprovalTTL - time.Minute).Format(approvalTime)}
	saved := Saved{PlanID: a.PlanID, PlanDigest: a.PlanDigest, QualificationRun: &QualificationRun{
		RequestSHA256: expected.RequestSHA256, MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates(),
	}}
	var checks, claims int
	check := func(s Saved, owner string, uid int) error {
		checks++
		if s.PlanID != a.PlanID || owner != "owner" || uid != 301 {
			return errors.New("changed review subject")
		}
		return nil
	}
	claim := func(want string, record QualificationAttempt) error {
		claims++
		if want != qualificationAttemptPath(a.PlanID) || record != expected {
			return errors.New("changed claim")
		}
		return claimQualificationAttemptFile(path, record)
	}
	refusePair := func(Approval, func() error) error { return errors.New("pair revoked") }
	if _, err := claimApprovedQualificationAttempt(saved, a, "owner", 301, refusePair, func() time.Time { return now }, check, claim); err == nil || checks != 0 || claims != 0 {
		t.Fatalf("revoked pairing reached review or claim: checks=%d claims=%d err=%v", checks, claims, err)
	}
	guard := func(_ Approval, work func() error) error { return work() }
	refuseArtifacts := func(Saved, string, int) error { checks++; return errors.New("artifact changed") }
	if _, err := claimApprovedQualificationAttempt(saved, a, "owner", 301, guard, func() time.Time { return now }, refuseArtifacts, claim); err == nil || claims != 0 {
		t.Fatalf("changed artifact reached claim: claims=%d err=%v", claims, err)
	}
	changed := a
	changed.PlanDigest = strings.Repeat("f", 64)
	if _, err := claimApprovedQualificationAttempt(saved, changed, "owner", 301, guard, func() time.Time { return now }, check, claim); err == nil || claims != 0 {
		t.Fatal("approval for another plan reached claim")
	}
	got, err := claimApprovedQualificationAttempt(saved, a, "owner", 301, guard, func() time.Time { return now }, check, claim)
	if err != nil || got != expected || claims != 1 {
		t.Fatalf("exact approved claim refused: %+v claims=%d err=%v", got, claims, err)
	}
	if _, err := claimApprovedQualificationAttempt(saved, a, "owner", 301, guard, func() time.Time { return now }, check, claim); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("same approval launched twice: %v", err)
	}
}

func TestQualificationFailureResultHasOneWinner(t *testing.T) {
	path, attempt, now := qualificationClaimFixture(t)
	if err := claimQualificationAttemptFile(path, attempt); err != nil {
		t.Fatal(err)
	}
	const contenders = 12
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- finishQualificationAttemptFile(path, attempt, "incomplete", "interrupted before signed report", now.Add(time.Second), os.ReadFile)
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("unexpected concurrent finish result: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d result writers succeeded; expected one", won)
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), attempt.PlanID+".qualification-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result QualificationAttempt
	if json.Unmarshal(raw, &result) != nil || result.Result != "incomplete" || result.Reason != "interrupted before signed report" {
		t.Fatalf("incomplete result is not inspectable: %s", raw)
	}
}
