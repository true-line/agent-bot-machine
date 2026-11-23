package members

import "errors"

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
	published, err := evidence.publish(rec, j.Approval, sealed)
	if err != nil {
		return err
	}
	if published == nil || published.recheck == nil || published.withdraw == nil {
		return errors.New(hqStage2aCutoverRefusal)
	}
	withdraw := published.withdraw
	published.withdraw = func() error {
		if err := withdraw(); err != nil {
			return err
		}
		return removeHQStage2aDescriptorDirectory(*rec.Service.Stage2a, metadata)
	}
	if err := published.recheck(); err != nil {
		return errors.Join(err, published.withdraw())
	}
	j.protectedPublication = published
	return nil
}

func (j *upgradeJournal) rollbackProtectedHQ() error {
	if j.protectedPublication == nil || j.protectedPublication.withdraw == nil {
		return errors.New(hqStage2aCutoverRefusal)
	}
	return j.protectedPublication.withdraw()
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
