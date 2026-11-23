package members

import (
	"errors"
	"testing"
)

type testStage2aHQCutover struct {
	*testUpgradeHost
	preparationErr error
	withdrawErr    error
	prepared       bool
	withdrawn      bool
}

func (h *testStage2aHQCutover) prepareProtectedHQ(launchRecord) error {
	if h.stops != 0 || h.activePlist != "old" {
		return errors.New("protected preparation took place after stopping the base service")
	}
	h.prepared = h.preparationErr == nil
	return h.preparationErr
}

func (h *testStage2aHQCutover) rollbackProtectedHQ() error {
	if h.withdrawErr != nil {
		return h.withdrawErr
	}
	if !h.prepared || (h.activePlist != "" && h.activePlist != "old") || h.stops != 2 {
		return errors.New("candidate descriptor was withdrawn before the candidate stopped")
	}
	h.withdrawn = true
	return nil
}

func TestStage2aHQCutoverKeepsBaseRunningUntilPreparation(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"},
		Next: launchRecord{Plist: "new", Stage2a: &hqStage2aLaunch{}}}
	base := &testUpgradeHost{activePlist: "old", installedPlist: "old", stagedPlist: "new"}
	h := &testStage2aHQCutover{testUpgradeHost: base, preparationErr: errors.New("missing sealed R binding")}
	if err := performUpgrade(h, rec); !errors.Is(err, h.preparationErr) || h.activePlist != "old" || h.stops != 0 || h.starts != 0 {
		t.Fatalf("preflight changed the service: %v, %+v", err, h.testUpgradeHost)
	}
	if err := performUpgrade(base, rec); err == nil || h.activePlist != "old" || h.stops != 0 || h.starts != 0 {
		t.Fatalf("base operations accepted a protected transition: %v, %+v", err, base)
	}
}

func TestStage2aHQCutoverRollsBackDescriptorAfterCandidateStops(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"},
		Next: launchRecord{Plist: "new", Stage2a: &hqStage2aLaunch{}}}
	base := &testUpgradeHost{activePlist: "old", installedPlist: "old", stagedPlist: "new", wrongStatus: "new"}
	h := &testStage2aHQCutover{testUpgradeHost: base}
	if err := performUpgrade(h, rec); err == nil || !h.prepared || !h.withdrawn || h.activePlist != "old" || h.outcome != "failed" || h.stops != 2 || h.starts != 2 {
		t.Fatalf("failed protected cutover did not restore the base service: %v, %+v", err, h)
	}
}

func TestStage2aHQReentryPreservesWitnessUntilCleanupSucceeds(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"},
		Next: launchRecord{Plist: "new", Stage2a: &hqStage2aLaunch{}}}
	base := &testUpgradeHost{installedPlist: "new", stagedPlist: "old", stops: 2}
	h := &testStage2aHQCutover{testUpgradeHost: base, prepared: true, withdrawErr: errors.New("descriptor witness changed")}
	if err := reconcileUpgrade(h, rec, "started", "stopping-next"); !errors.Is(err, h.withdrawErr) ||
		h.activePlist != "" || h.outcome != "" || h.withdrawn || h.starts != 0 {
		t.Fatalf("interrupted rollback lost its cleanup evidence: %v, %+v", err, h)
	}
	h.withdrawErr = nil
	if err := reconcileUpgrade(h, rec, "started", "stopping-next"); err == nil ||
		h.activePlist != "old" || h.outcome != "failed" || !h.withdrawn || h.starts != 1 {
		t.Fatalf("reentry did not complete verified cleanup: %v, %+v", err, h)
	}
}

func TestStage2aHQActivePredecessorKeepsJournalAfterWithdrawRefusal(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"},
		Next: launchRecord{Plist: "new", Stage2a: &hqStage2aLaunch{}}}
	base := &testUpgradeHost{activePlist: "old", installedPlist: "old", stagedPlist: "new"}
	h := &testStage2aHQCutover{testUpgradeHost: base, withdrawErr: errors.New("A withdrawal refused")}
	if err := restorePrevious(h, rec); !errors.Is(err, h.withdrawErr) || h.outcome != "" || h.starts != 0 || h.stops != 0 {
		t.Fatalf("active predecessor caused premature journal disposal: %v, %+v", err, h)
	}
}
