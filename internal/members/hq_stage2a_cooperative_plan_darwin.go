//go:build darwin

package members

import (
	"crypto/ed25519"
	"time"
)

// loadApprovedCooperativeHV3 is the A-local join from one daemon-selected,
// canonical H upgrade plan to the independently installed cooperative plan.
// The caller must obtain cooperativePlanID, cooperativePlanDigest and until
// from A's installed cooperative record, not from an HQ request. The daemon
// must refuse zero or multiple matching H plan digests before calling this.
func loadApprovedCooperativeHV3(saved Saved, approved Approval, owner, daemonDir string,
	cooperativePlanID, cooperativePlanDigest string, until time.Time,
	key ed25519.PublicKey, withLivePair func(string, func() error) error) (stage2aCooperativeHDescriptorV3, error) {
	var empty stage2aCooperativeHDescriptorV3
	if withLivePair == nil || !ValidApproval(cooperativePlanID, cooperativePlanDigest) ||
		!time.Now().Before(until) || len(key) != ed25519.PublicKeySize {
		return empty, errStage2aReservationAuthority
	}
	rec, err := (hqStage2aWorkerRequest{Saved: saved, Approval: approved, Owner: owner}).record()
	if err != nil || rec.Service.Stage2a == nil || !rec.Service.Stage2a.CooperativeOnly ||
		rec.Service.Stage2a.RuntimeInstallationID != "" {
		return empty, errStage2aReservationAuthority
	}
	s := rec.Service.Stage2a
	pair := func(a Approval, run func() error) error {
		if a != approved {
			return errStage2aReservationAuthority
		}
		return withLivePair(a.PairCommitment, run)
	}
	if checkHQStage2aPairedApproval(saved, rec, approved, key, daemonDir, owner, pair, true) != nil {
		return empty, errStage2aReservationAuthority
	}
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
	return loadStage2aCooperativeHV3(proof, key)
}
