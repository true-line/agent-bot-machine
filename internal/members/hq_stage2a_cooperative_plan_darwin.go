//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"
)

// loadInstalledCooperativeHV3 joins a daemon-selected canonical H upgrade
// plan to its durable applied root receipt and the currently installed H.
// The receipt's original approval proves the reviewed installation; its
// ten-minute install TTL is not a new approval requirement for each start.
// A's fresh cooperative reservation, not this H lookup, authorizes a launch.
// The daemon must refuse zero or multiple matching H plans before calling.
func loadInstalledCooperativeHV3(saved Saved, owner string,
	cooperativePlanID, cooperativePlanDigest string, until time.Time,
	key ed25519.PublicKey, withLivePair func(string, func() error) error) (stage2aCooperativeHDescriptorV3, error) {
	var empty stage2aCooperativeHDescriptorV3
	if withLivePair == nil || !ValidApproval(cooperativePlanID, cooperativePlanDigest) ||
		!time.Now().Before(until) || len(key) != ed25519.PublicKeySize {
		return empty, errStage2aReservationAuthority
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(key))
	receipt, err := currentUpgradeReceipt(Approval{Purpose: UpgradePurpose,
		PlanID: saved.PlanID, PlanDigest: saved.PlanDigest,
		MachineFingerprint: fingerprint}, owner)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	rec, approved, journal, err := retainedCooperativeHReceipt(saved, receipt, owner, fingerprint)
	if err != nil || checkHQStage2aDescriptorDirectory(*rec.Service.Stage2a, journal.Directory) != nil {
		return empty, errStage2aReservationAuthority
	}
	s := rec.Service.Stage2a
	components := make([]stage2aHReleaseComponentV3, 0, len(s.Components))
	for _, c := range s.Components {
		component := stage2aHReleaseComponentV3{ComponentID: c.ComponentID,
			SourceRepository: c.SourceRepository, SourceCommit: c.SourceCommit,
			ReleaseArtifactSHA256: c.ArtifactSHA256, ReleaseManifestSHA256: c.ManifestSHA256}
		if c.SourceTag != "" {
			tag := c.SourceTag
			component.SourceTag = &tag
		}
		components = append(components, component)
	}
	proof := stage2aCooperativeHProofV3{verified: true,
		hostID: s.HostID, hqInstallationID: s.InstallationID,
		hOwnerPlanDigest:  "sha256:" + approved.PlanDigest,
		cooperativePlanID: cooperativePlanID, cooperativePlanDigest: cooperativePlanDigest,
		pairCommitment: approved.PairCommitment,
		machineUID:     s.MachineUID, hqUID: s.ReaderUID, readerGID: s.ReaderGID,
		components: components, approvedUntil: until, withLivePair: withLivePair}
	if !proof.valid(time.Now()) {
		return empty, errStage2aReservationAuthority
	}
	installed, err := loadStage2aCooperativeHV3(proof, key)
	if err != nil || journal.Descriptor == nil || installed.witness != *journal.Descriptor {
		return empty, errStage2aReservationAuthority
	}
	return installed, nil
}

// The root-owned applied receipt retains the exact install approval and H
// witness after the short-lived approval file has expired or been pruned.
// This check is data-only so its negative cases can be tested without a host
// installation. The caller reads the receipt from the fixed protected path.
func retainedCooperativeHReceipt(saved Saved, receipt Receipt, owner, fingerprint string) (
	launchRecord, Approval, hqStage2aJournalDescriptor, error) {
	var empty launchRecord
	var approval Approval
	var journal hqStage2aJournalDescriptor
	if receipt.Result != "applied" || receipt.Upgrade == nil ||
		receipt.PlanID != saved.PlanID || receipt.PlanDigest != saved.PlanDigest ||
		receipt.Owner != owner || receipt.HQAccount != DarwinHQAccount ||
		receipt.Dir != DarwinDir || len(receipt.Members) != 0 {
		return empty, approval, journal, errStage2aReservationAuthority
	}
	approval = receipt.Upgrade.Approval
	if approval.Purpose != UpgradePurpose || approval.PlanID != saved.PlanID ||
		approval.PlanDigest != saved.PlanDigest || approval.MachineFingerprint != fingerprint ||
		!digestPattern.MatchString(approval.PairCommitment) {
		return empty, approval, journal, errStage2aReservationAuthority
	}
	approvedAt, e1 := time.Parse(approvalTime, approval.ApprovedAt)
	expiresAt, e2 := time.Parse(approvalTime, approval.ExpiresAt)
	startedAt, e3 := time.Parse(approvalTime, receipt.StartedAt)
	finishedAt, e4 := time.Parse(approvalTime, receipt.FinishedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
		expiresAt.Sub(approvedAt) != ApprovalTTL || startedAt.Before(approvedAt) ||
		!startedAt.Before(expiresAt) || finishedAt.Before(startedAt) {
		return empty, approval, journal, errStage2aReservationAuthority
	}
	rec, err := (hqStage2aWorkerRequest{Saved: saved, Approval: approval, Owner: owner}).record()
	if err != nil || rec.Service.Stage2a == nil || !rec.Service.Stage2a.CooperativeOnly ||
		rec.Service.Stage2a.RuntimeInstallationID != "" ||
		stage2aDecodeExact(receipt.Upgrade.ProtectedDescriptor, &journal) != nil ||
		journal.Descriptor == nil || journal.Runtime != nil ||
		!validHQStage2aDescriptorWitness(*rec.Service.Stage2a, *journal.Descriptor) {
		return empty, approval, journal, errStage2aReservationAuthority
	}
	return rec, approval, journal, nil
}
