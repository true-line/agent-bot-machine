package members

import (
	"crypto/ed25519"
	"time"
)

type stage2aReservationRunModeV3 string

const (
	stage2aQualifiedRunV3 stage2aReservationRunModeV3 = "qualified"
	stage2aCandidateRunV3 stage2aReservationRunModeV3 = "qualification-candidate"
	stage2aLocalTestRunV1 stage2aReservationRunModeV3 = "observed-body-local-test"
)

type stage2aReservationGuardV3 struct {
	assignment stage2aReservationAssignmentV3
	binding    Stage2aMeasurementBinding
	hDigest    string
	r          stage2aDomainInventoryRefV3
	member     SoulMemberLaunchAssignment
	payload    stage2aReservationPayload
}

// The expected mode comes from installed authority or a Machine-signed role
// grant. The envelope and its expected payload cannot choose the verifier.
func verifyStage2aReservationModeV3(mode stage2aReservationRunModeV3, raw []byte, digest string,
	expected []byte, key ed25519.PublicKey, now time.Time) (stage2aReservationGuardV3, error) {
	switch mode {
	case stage2aQualifiedRunV3:
		var p stage2aReservationPayloadV3
		if stage2aDecodeExact(expected, &p) == nil && verifyStage2aReservationV3(raw, digest, p, key, now) == nil {
			return stage2aReservationGuardV3{p.Assignment, p.MeasurementBinding.Stage2aMeasurementBinding,
				p.MeasurementBinding.HDescriptorDigest, p.MeasurementBinding.RInventory, p.MemberEndpoint,
				stage2aReservationPayload{Contract: p.Contract, Kind: p.Kind, SchemaVersion: p.SchemaVersion, HostID: p.HostID, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, InstalledPlanReceiptSHA256: p.InstalledPlanReceiptSHA256, AdmissionChallengeSHA256: p.AdmissionChallengeSHA256, MemberEndpoint: p.MemberEndpoint}}, nil
		}
	case stage2aCandidateRunV3:
		var p stage2aQualificationCandidateReservationV3
		if stage2aDecodeExact(expected, &p) == nil && verifyStage2aQualificationCandidateV3(raw, digest, p, key, now) == nil &&
			p.MeasurementBinding.Kind == "stage2a-qualification-candidate-binding" {
			binding := p.MeasurementBinding.Stage2aMeasurementBinding
			binding.Kind = "stage2a-measurement-binding"
			return stage2aReservationGuardV3{p.Assignment, binding, p.MeasurementBinding.HDescriptorDigest,
				p.MeasurementBinding.RInventory, p.MemberEndpoint,
				stage2aReservationPayload{Contract: p.Contract, Kind: p.Kind, SchemaVersion: p.SchemaVersion, HostID: p.HostID, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, InstalledPlanReceiptSHA256: p.InstalledPlanReceiptSHA256, AdmissionChallengeSHA256: p.AdmissionChallengeSHA256, MemberEndpoint: p.MemberEndpoint}}, nil
		}
	case stage2aLocalTestRunV1:
		var p stage2aLocalTestReservationV1
		if stage2aDecodeExact(expected, &p) == nil && verifyStage2aLocalTestReservationV1(raw, digest, p, key, now) == nil {
			return stage2aReservationGuardV3{p.Assignment, p.MeasurementBinding.Stage2aMeasurementBinding,
				p.MeasurementBinding.HDescriptorDigest, p.MeasurementBinding.RInventory, p.MemberEndpoint,
				stage2aReservationPayload{Contract: p.Contract, Kind: p.Kind, SchemaVersion: p.SchemaVersion, HostID: p.HostID, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, InstalledPlanReceiptSHA256: p.InstalledPlanReceiptSHA256, AdmissionChallengeSHA256: p.AdmissionChallengeSHA256, MemberEndpoint: p.MemberEndpoint}}, nil
		}
	}
	return stage2aReservationGuardV3{}, errStage2aReservationAuthority
}
