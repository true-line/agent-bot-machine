package members

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStage2aHQAppliedReceiptReentryUsesDurableWitnesses(t *testing.T) {
	service, _ := stage2aHQTestService(t)
	next := launchRecord{Service: service, Stage2a: &hqStage2aLaunch{}}
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("R-runtime", "fixture-runtime")
	if err != nil {
		t.Fatal(err)
	}
	runtime := stage2aDomainInventoryRefV3{Domain: "R-runtime", InstallationID: "fixture-runtime", MachineUID: uint32(service.Stage2a.MachineUID),
		ReaderUID: 331, ReaderGID: 331, Snapshot: stage2aDomainNodeRefV3{Path: filepath.Join(namespace, snapshot)},
		Sidecar: stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{Path: filepath.Join(namespace, sidecar)}}}
	witness := &hqStage2aJournalDescriptor{Descriptor: &stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{Path: hqStage2aDescriptor}}, H: &stage2aDomainInventoryRefV3{}, Runtime: &runtime}
	approved := Approval{PlanID: "plan-20261122T141517Z-abcd", Purpose: UpgradePurpose}
	pair := func(a Approval, work func() error) error {
		if a != approved {
			t.Fatal("wrong approval")
		}
		if work != nil {
			return work()
		}
		return nil
	}
	initial := upgradeJournal{Approval: approved, pair: pair, Upgrade: launchUpgrade{Next: next}, ProtectedDescriptor: witness,
		protectedPublication: &hqStage2aPublication{recheck: func() error { t.Fatal("unexpected live verification after reentry"); return nil }}}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := initial.commitReceipt(path, Receipt{Result: "started"}, true); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err := json.Unmarshal(persisted, &receipt); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	resumed := upgradeJournal{pair: pair}
	if err := json.Unmarshal(raw, &resumed); err != nil {
		t.Fatal(err)
	}
	checked := false
	if err := resumed.checkProtectedHQCandidate(next, func(r launchRecord, a Approval, saved *hqStage2aJournalDescriptor) error {
		checked = true
		if a != approved || !reflect.DeepEqual(r, next) || !reflect.DeepEqual(saved, witness) {
			t.Fatal("changed durable witness")
		}
		return nil
	}); err != nil || !checked {
		t.Fatalf("recheck did not use durable state: %v", err)
	}
	if err := resumed.commitReceipt(path, receipt, true); err != nil {
		t.Fatal(err)
	}
	resumed.ProtectedDescriptor.Runtime.ReaderGID++
	if err := resumed.commitReceipt(path, receipt, true); err == nil {
		t.Fatal("accepted a different recovered R witness")
	}
}
