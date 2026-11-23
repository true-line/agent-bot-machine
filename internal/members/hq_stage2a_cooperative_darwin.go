package members

import (
	"crypto/ed25519"
	"reflect"
	"time"
)

// This proof is constructed by the cooperative owner-plan loader after
// checking its canonical approval, applied receipt and actual paired owner.
// No HQ request is allowed to supply these fields or the pairing guard.
type stage2aCooperativeHProofV3 struct {
	verified                     bool
	hostID                       string
	hqInstallationID             string
	hOwnerPlanDigest             string
	cooperativePlanID            string
	cooperativePlanDigest        string
	pairCommitment               string
	machineUID, hqUID, readerGID int
	components                   []stage2aHReleaseComponentV3
	approvedUntil                time.Time
	withLivePair                 func(commitment string, run func() error) error
}

type stage2aCooperativeHDescriptorV3 struct {
	verifiedH        stage2aVerifiedDomainRefV3
	envelope         []byte
	descriptorDigest string
	witness          stage2aDomainSidecarRefV3
}

func (p stage2aCooperativeHProofV3) valid(now time.Time) bool {
	return p.verified && p.withLivePair != nil && stage2aBindingID.MatchString(p.hostID) &&
		soulInstallationID.MatchString(p.hqInstallationID) && stage2aPrefixedDigest.MatchString(p.hOwnerPlanDigest) &&
		ValidApproval(p.cooperativePlanID, p.cooperativePlanDigest) &&
		p.hOwnerPlanDigest != "sha256:"+p.cooperativePlanDigest && digestPattern.MatchString(p.pairCommitment) &&
		p.machineUID >= 400 && p.hqUID >= 300 && p.hqUID <= 399 && p.readerGID == p.hqUID &&
		len(p.components) > 0 && now.Before(p.approvedUntil)
}

func (p stage2aCooperativeHProofV3) matches(d stage2aHServiceDescriptorPayloadV3) bool {
	h := d.HInventory
	return p.hostID == d.HostID && p.hqInstallationID == d.HQInstallationID && p.hOwnerPlanDigest == d.OwnerPlanDigest &&
		p.hOwnerPlanDigest == h.OwnerPlanDigest && h.InstallationID == p.hqInstallationID && h.Domain == "H-code" &&
		uint32(p.machineUID) == h.MachineUID && uint32(p.hqUID) == h.ReaderUID && uint32(p.readerGID) == h.ReaderGID &&
		reflect.DeepEqual(p.components, d.Components)
}

// H-only publication is an owner-approved installation. It cannot depend on
// a later per-Soul cooperative plan, which does not exist at HQ cutover time.
func (service *Stage2aService) signAndPublishCooperativeHQStage2a(rec launchRecord, approved Approval,
	h stage2aDomainInventoryRefV3, authority hqStage2aSigningAuthority) (stage2aCooperativeHDescriptorV3, error) {
	s := rec.Service.Stage2a
	if s == nil || !s.CooperativeOnly || s.RuntimeInstallationID != "" || authority.verifyRuntime != nil ||
		authority.pair == nil || h.OwnerPlanDigest != "sha256:"+approved.PlanDigest {
		return stage2aCooperativeHDescriptorV3{}, errStage2aReservationAuthority
	}
	var published stage2aCooperativeHDescriptorV3
	err := authority.pair(approved, func() error {
		var err error
		published, err = service.publishReviewedHQStage2a(rec, approved, h, authority, func(d stage2aHServiceDescriptorPayloadV3) error {
			if d.HostID != s.HostID || d.HQInstallationID != s.InstallationID ||
				d.OwnerPlanDigest != h.OwnerPlanDigest || d.HInventory != h {
				return errStage2aReservationAuthority
			}
			return nil
		})
		return err
	})
	if err != nil || !published.verifiedH.verified {
		return stage2aCooperativeHDescriptorV3{}, errStage2aReservationAuthority
	}
	return published, nil
}

// Load an H descriptor using the cooperative install's independent identity
// and release pins. This evidence authorizes no reservation or launch.
func loadStage2aCooperativeHV3(proof stage2aCooperativeHProofV3,
	key ed25519.PublicKey) (stage2aCooperativeHDescriptorV3, error) {
	if !proof.valid(time.Now()) {
		return stage2aCooperativeHDescriptorV3{}, errStage2aReservationAuthority
	}
	var result stage2aCooperativeHDescriptorV3
	err := proof.withLivePair(proof.pairCommitment, func() error {
		h, d, err := loadStage2aInstalledHV3(proof.hostID, proof.machineUID, proof.hqUID, proof.readerGID, key)
		if err != nil || !proof.matches(d) || !proof.valid(time.Now()) || stage2aRecheckVerifiedDomainV3(h.verifiedH) != nil {
			return errStage2aReservationAuthority
		}
		result = h
		return nil
	})
	if err != nil || !result.verifiedH.verified {
		return stage2aCooperativeHDescriptorV3{}, errStage2aReservationAuthority
	}
	return result, nil
}
