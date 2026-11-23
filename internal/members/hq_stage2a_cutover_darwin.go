package members

import (
	"errors"
	"os"
	"path/filepath"
)

type hqStage2aJournalDescriptor struct {
	Directory  stage2aInstalledDirectory  `json:"directory"`
	Descriptor *stage2aDomainSidecarRefV3 `json:"descriptor,omitempty"`
}

type protectedHQUpgradeOperations interface {
	prepareProtectedHQ(launchRecord) error
	rollbackProtectedHQ() error
}

// The paired H/R verifier must establish the reviewed limits, release
// attestations and exact manifest mapping, installed R binding, and guard
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
	// Before launchd submission, recheck the sealed H/R, A signature,
	// selected bytes, and the exact published descriptor inode.
	recheck func() error
	// Withdraw only the exact descriptor, after the protected process has
	// been stopped and before restoring the original launchd job.
	withdraw func() error
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
	published, err := evidence.publish(rec, j.Approval, sealed)
	if err != nil {
		return err
	}
	if published == nil || published.recheck == nil || published.withdraw == nil || !validHQStage2aDescriptorWitness(*rec.Service.Stage2a, published.witness) {
		return errors.New(hqStage2aCutoverRefusal)
	}
	withdraw := published.withdraw
	published.withdraw = func() error {
		if err := withdraw(); err != nil {
			return err
		}
		return removeHQStage2aDescriptorDirectory(*rec.Service.Stage2a, metadata)
	}
	j.protectedPublication = published
	if err := published.recheck(); err != nil {
		return err
	}
	j.ProtectedDescriptor.Descriptor = &published.witness
	return j.write(journal, false)
}

func (j *upgradeJournal) rollbackProtectedHQ() error {
	if j.protectedPublication != nil && j.protectedPublication.withdraw != nil {
		return j.protectedPublication.withdraw()
	}
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
		if state.Descriptor == nil || !validHQStage2aDescriptorWitness(s, *state.Descriptor) {
			return errors.New("preserving an unrecorded protected HQ descriptor")
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
