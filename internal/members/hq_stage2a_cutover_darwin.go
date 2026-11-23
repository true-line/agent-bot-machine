package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

type hqStage2aJournalDescriptor struct {
	Directory  stage2aInstalledDirectory    `json:"directory"`
	Descriptor *stage2aDomainSidecarRefV3   `json:"descriptor,omitempty"`
	Runtime    *stage2aDomainInventoryRefV3 `json:"runtime,omitempty"`
}

type protectedHQUpgradeOperations interface {
	prepareProtectedHQ(launchRecord) error
	rollbackProtectedHQ() error
}

// The paired H/R verifier must establish the reviewed limits, release
// source and exact manifest mapping, installed R binding, and guard
// before root touches host state. Only that verifier can supply evidence.
// A verified release closure alone never authorizes activation.
type hqStage2aUpgradeEvidence struct {
	review func(launchRecord, Approval) error
	// The fixed offline A publisher reopens H/R, compares the independently
	// enrolled A key, signs, and durably publishes at the reviewed fixed path.
	publish func(launchRecord, Approval, stage2aDomainInventoryRefV3) (*hqStage2aPublication, error)
}

type hqStage2aPublication struct {
	witness stage2aDomainSidecarRefV3
	runtime stage2aDomainInventoryRefV3
	// Before launchd submission, recheck the sealed H/R, A signature,
	// selected bytes, and the exact published descriptor inode.
	recheck func() error
}

func (j *upgradeJournal) prepareProtectedHQ(rec launchRecord) error {
	evidence := j.protectedEvidence
	if evidence == nil || evidence.review == nil || evidence.publish == nil || rec.Stage2a == nil || rec.Service.Stage2a == nil {
		return errors.New(hqStage2aCutoverRefusal)
	}
	if err := evidence.review(rec, j.Approval); err != nil {
		return err
	}
	raw, err := stage2aReadRootFile(rec.Service.Stage2a.InventorySource, 2<<20, 0444, 0644)
	if err != nil {
		return err
	}
	sealed, err := prepareHQStage2aSeal(rec, j.Approval.PlanDigest, raw)
	if err != nil {
		return err
	}
	metadata, err := provisionHQStage2aDescriptorDirectory(rec)
	if err != nil {
		return err
	}
	j.ProtectedDescriptor = &hqStage2aJournalDescriptor{Directory: metadata}
	journal := filepath.Join(receiptsDir(), upgradeJournalName)
	if err := j.write(journal, false); err != nil {
		return err
	}
	var published *hqStage2aPublication
	if err := j.pair(j.Approval, func() error {
		var err error
		published, err = evidence.publish(rec, j.Approval, sealed)
		return err
	}); err != nil {
		return err
	}
	if published == nil || published.recheck == nil || !validHQStage2aDescriptorWitness(*rec.Service.Stage2a, published.witness) || !hqStage2aRuntimeMatches(rec, published.runtime) {
		return errors.New(hqStage2aCutoverRefusal)
	}
	verifyRuntime := published.recheck
	published.recheck = func() error {
		witness, _, _, err := recoverHQStage2aDescriptorWitness(rec, j.Approval)
		if err != nil || witness != published.witness {
			return errStage2aReservationAuthority
		}
		return verifyRuntime()
	}
	if err := published.recheck(); err != nil {
		return err
	}
	j.protectedPublication = published
	j.ProtectedDescriptor.Descriptor = &published.witness
	j.ProtectedDescriptor.Runtime = &published.runtime
	return j.write(journal, false)
}

func (j *upgradeJournal) rollbackProtectedHQ() error {
	rec := j.Upgrade.Next
	if rec.Stage2a == nil || rec.Service.Stage2a == nil {
		return errors.New(hqStage2aCutoverRefusal)
	}
	state := j.ProtectedDescriptor
	if _, err := os.Lstat(hqStage2aMetadataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if state == nil || state.Directory.Path != hqStage2aMetadataDir {
		return errors.New("preserving unrecorded protected HQ descriptor directory")
	}
	s := *rec.Service.Stage2a
	if err := checkHQStage2aDescriptorDirectory(s, state.Directory); err != nil {
		return err
	}
	if _, err := os.Lstat(hqStage2aDescriptor); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		if state.Descriptor == nil {
			witness, _, _, err := recoverHQStage2aDescriptorWitness(rec, j.Approval)
			if err != nil {
				return errors.New("preserving an unrecognized protected HQ descriptor")
			}
			state.Descriptor = &witness
			if err := j.write(filepath.Join(receiptsDir(), upgradeJournalName), false); err != nil {
				return err
			}
		}
		if !validHQStage2aDescriptorWitness(s, *state.Descriptor) {
			return errors.New("preserving a changed protected HQ descriptor witness")
		}
		if err := withdrawHQStage2aDescriptorOffline(rec, *state.Descriptor); err != nil {
			return err
		}
	}
	return removeHQStage2aDescriptorDirectory(s, state.Directory)
}

func rollbackProtectedHQ(j upgradeOperations, rec launchUpgrade) error {
	if rec.Next.Service.Stage2a == nil && rec.Next.Stage2a == nil {
		return nil
	}
	protected, ok := j.(protectedHQUpgradeOperations)
	if !ok {
		return errors.New(hqStage2aCutoverRefusal)
	}
	return protected.rollbackProtectedHQ()
}

func hqStage2aRuntimeMatches(rec launchRecord, ref stage2aDomainInventoryRefV3) bool {
	s := rec.Service.Stage2a
	return s != nil && ref.InstallationID == s.RuntimeInstallationID && ref.Domain == "R-runtime" && ref.MachineUID == uint32(s.MachineUID) &&
		ref.ReaderUID > 0 && ref.ReaderGID > 0 && ref.ReaderUID != uint32(s.ReaderUID) && ref.ReaderGID != uint32(s.ReaderGID) &&
		matchesHQStage2aRuntimeNames(ref)
}

func (j *upgradeJournal) checkProtectedHQCandidate(rec launchRecord,
	checkDurable func(launchRecord, Approval, *hqStage2aJournalDescriptor) error) error {
	if j.protectedPublication != nil {
		return j.protectedPublication.recheck()
	}
	state := j.ProtectedDescriptor
	if state == nil || state.Descriptor == nil || state.Runtime == nil || !hqStage2aRuntimeMatches(rec, *state.Runtime) {
		return errors.New(hqStage2aCutoverRefusal)
	}
	return checkDurable(rec, j.Approval, state)
}

func matchesHQStage2aReceiptWitness(receipt, journal json.RawMessage) bool {
	if len(receipt) == 0 || len(journal) == 0 {
		return len(receipt) == 0 && len(journal) == 0
	}
	var fromReceipt, fromJournal *hqStage2aJournalDescriptor
	return stage2aDecodeExact(receipt, &fromReceipt) == nil && stage2aDecodeExact(journal, &fromJournal) == nil &&
		fromReceipt != nil && fromJournal != nil && reflect.DeepEqual(fromReceipt, fromJournal)
}
