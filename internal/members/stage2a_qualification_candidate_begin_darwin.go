package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// beginStage2aApprovedCandidateV3 is called by the A daemon exactly once per
// reviewed run. The caller supplies records loaded from the resolved local
// owner plan and A-private approval store, and the live pairing guard. It
// must have authenticated the host designation and installed Q profile; a
// nil verifier or stale R reference prevents consuming the owner approval.
//
// Keep the returned authority in the current A process. The persisted
// started record is spent evidence and does not restore a run after restart.
func beginStage2aApprovedCandidateV3(saved Saved, approval Approval, owner, state string,
	hqUID int, base stage2aReservationEvidenceV3, guard upgradePairGuard,
	checkDesignatedHost, checkInstalledQ func(QualificationRequest) error) (stage2aQualificationCandidateAuthorityV3, []byte, error) {
	var empty stage2aQualificationCandidateAuthorityV3
	key := base.base.enrolledAdminKey
	digest := sha256.Sum256(key)
	if saved.QualificationRun == nil || saved.QualificationRun.Request.SchemaVersion != 2 ||
		saved.QualificationRun.Request.Candidate == nil || checkDesignatedHost == nil || checkInstalledQ == nil ||
		len(key) != ed25519.PublicKeySize || approval.MachineFingerprint != hex.EncodeToString(digest[:]) ||
		!base.h.verified || !base.r.verified {
		return empty, nil, errQualificationAdmissionUnavailable
	}
	var authority stage2aQualificationCandidateAuthorityV3
	var sealedR stage2aVerifiedDomainRefV3
	_, err := AdmitDarwinQualificationRun(saved, approval, owner, hqUID, state, guard, time.Now,
		func(run QualificationRun) error {
			var err error
			authority, sealedR, err = stage2aPrepareCandidateAuthorityV3(saved, approval, owner, state,
				hqUID, base, checkDesignatedHost, checkInstalledQ)
			return err
		})
	if err != nil {
		return empty, nil, err
	}
	if err := stage2aRecheckVerifiedDomainV3(sealedR); err != nil {
		return empty, nil, err
	}
	spent, err := readStage2aCandidateSpentAttemptV3(state, saved.PlanID, saved.PlanDigest, uint32(base.base.machineUID))
	if err != nil {
		return empty, nil, err
	}
	return authority, spent, nil
}

// Both the one-use admission and the offline worker rebuild these inputs
// from the installed Q plan and A's sealed H/R authority. This preparation
// never creates or restores an approval or live grant.
func stage2aPrepareCandidateAuthorityV3(saved Saved, approval Approval, owner, state string,
	hqUID int, base stage2aReservationEvidenceV3,
	checkDesignatedHost, checkInstalledQ func(QualificationRequest) error) (stage2aQualificationCandidateAuthorityV3, stage2aVerifiedDomainRefV3, error) {
	var empty stage2aQualificationCandidateAuthorityV3
	var noR stage2aVerifiedDomainRefV3
	if saved.QualificationRun == nil || checkDesignatedHost == nil || checkInstalledQ == nil ||
		len(base.base.enrolledAdminKey) != ed25519.PublicKeySize ||
		!base.h.verified || !base.r.verified ||
		CheckDarwinHarnessQualification(saved, owner, hqUID) != nil {
		return empty, noR, errQualificationAdmissionUnavailable
	}
	r := saved.QualificationRun.Request
	q := r.Candidate
	if validateQualificationRequest(r) != nil || q == nil ||
		r.Host.ID != base.base.hostID || "sha256:"+r.TestProvider.ConfigSHA != base.broker.ProviderConfigSHA256 ||
		q.InstallationID != base.base.binding.InstallationID ||
		q.InstalledPlanDigest != base.base.binding.InstalledPlanDigest ||
		"sha256:"+q.RuntimeInventorySHA != base.r.ref.InventoryDigest ||
		checkDesignatedHost(r) != nil || checkInstalledQ(r) != nil {
		return empty, noR, errQualificationAdmissionUnavailable
	}
	runtime, err := stage2aLoadInstalledRuntimeV3(base.base.enrolledAdminKey, hqUID, base.base.binding.HQEpoch, q.InstallationID)
	if err != nil || runtime.VerifiedR.ref != base.r.ref ||
		runtime.Policy.Binding.InstalledPlanDigest != q.InstalledPlanDigest {
		return empty, noR, errQualificationAdmissionUnavailable
	}
	component, err := stage2aOwnerCandidateComponentV3(runtime.Plan, r)
	if err != nil {
		return empty, noR, err
	}
	archive, err := verifyStage2aCandidateAdapterArchiveV3(component, runtime.Inventory)
	if err != nil {
		return empty, noR, err
	}
	authority := stage2aQualificationCandidateAuthorityV3{
		base: base, approval: approval, saved: saved, owner: owner,
		testPlanSHA: "sha256:" + q.TestPlan.SHA256, archive: archive,
		candidateComponent: q.ComponentID, approvedInstallationID: q.InstallationID,
		approvedInstalledPlanDigest: q.InstalledPlanDigest, stateDirectory: state,
	}
	if _, err := stage2aCandidateAdapterV3(authority); err != nil ||
		stage2aRecheckVerifiedDomainV3(runtime.VerifiedR) != nil {
		return empty, noR, errQualificationAdmissionUnavailable
	}
	return authority, runtime.VerifiedR, nil
}

func stage2aOwnerCandidateComponentV3(installed stage2aRuntimeV3Install, request QualificationRequest) (stage2aReleaseComponent, error) {
	var empty stage2aReleaseComponent
	review := request.Candidate
	if review == nil {
		return empty, errQualificationAdmissionUnavailable
	}
	for _, item := range installed.Components {
		if item.ComponentID != review.ComponentID {
			continue
		}
		if item.ArtifactFormat != "zip" || item.ArtifactSource != request.Adapter.PackagePath ||
			item.ReleaseArtifactSHA256 != "sha256:"+request.Adapter.PackageSHA ||
			item.ManifestSource != review.Manifest.Path || item.ReleaseManifestSHA256 != "sha256:"+review.Manifest.SHA256 {
			return empty, errQualificationAdmissionUnavailable
		}
		return stage2aReleaseComponent{
			ComponentID: item.ComponentID, SourceRepository: item.SourceRepository,
			SourceCommit: item.SourceCommit, SourceTag: item.SourceTag,
			ArtifactSource: item.ArtifactSource, ArtifactSHA256: item.ReleaseArtifactSHA256,
			ManifestSource: item.ManifestSource, ManifestSHA256: item.ReleaseManifestSHA256,
		}, nil
	}
	return empty, errQualificationAdmissionUnavailable
}
