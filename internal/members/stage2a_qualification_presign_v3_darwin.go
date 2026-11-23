package members

import (
	"crypto/ed25519"
	"time"
)

// Keep the exact v3 record that A issued for the active start. The run mode
// is fixed in authenticated local authority, not discovered from raw bytes.
type stage2aQualificationReservationV3 struct {
	mode      stage2aReservationRunModeV3
	qualified *stage2aReservationPayloadV3
	candidate *stage2aQualificationCandidateReservationV3
}

func stage2aQualificationReservationJoinV3(expected stage2aQualificationReservationV3,
	session stage2aQualificationSessionResultV1, raw []byte, key ed25519.PublicKey) (string, error) {
	begin := session.begin
	digest := stage2aQualificationSHA256(raw)
	if digest != begin.ReservationSHA256 || session.startedAt.IsZero() ||
		session.eofObservedAt.Before(session.startedAt) {
		return "", errStage2aReservationAuthority
	}
	var assignment stage2aReservationAssignmentV3
	var binding Stage2aMeasurementBinding
	var challenge string
	switch expected.mode {
	case stage2aQualifiedRunV3:
		want := expected.qualified
		if want == nil || expected.candidate != nil ||
			verifyStage2aReservationV3(raw, digest, *want, key, session.startedAt) != nil {
			return "", errStage2aReservationAuthority
		}
		assignment, binding, challenge = want.Assignment, want.MeasurementBinding.Stage2aMeasurementBinding, want.AdmissionChallengeSHA256
	case stage2aCandidateRunV3:
		want := expected.candidate
		if want == nil || expected.qualified != nil ||
			verifyStage2aQualificationCandidateV3(raw, digest, *want, key, session.startedAt) != nil ||
			want.Attempt.TestPlanSHA256 != begin.TestPlanSHA256 || want.Attempt.SuiteRevision != begin.SuiteRevision {
			return "", errStage2aReservationAuthority
		}
		assignment, binding, challenge = want.Assignment, want.MeasurementBinding.Stage2aMeasurementBinding, want.AdmissionChallengeSHA256
	default:
		return "", errStage2aReservationAuthority
	}
	if assignment.InstallationID != begin.InstallationID || assignment.StartID != begin.StartID ||
		assignment.SoulID != begin.SoulID || binding.InstallationID != begin.InstallationID ||
		binding.StartID != begin.StartID || binding.SoulID != begin.SoulID ||
		binding.LaunchID != assignment.LaunchID || binding.HostID != begin.HostID ||
		binding.ProfileInForce != begin.Profile || !stage2aQualificationDigest(challenge) {
		return "", errStage2aReservationAuthority
	}
	return challenge, nil
}

// The envelope's lease is checked at A's independently captured session
// start time. The lease limits admission, not the later archival operation.
func persistStage2aQualificationPreSignV3(store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1, reservation []byte,
	expected stage2aQualificationReservationV3, now time.Time, machineKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (stage2aQualificationPreSignArtifactsV1, error) {
	if session.peer.uid == int(store.uid) || session.eofObservedAt.After(now) {
		return stage2aQualificationPreSignArtifactsV1{}, errStage2aReservationAuthority
	}
	challenge, err := stage2aQualificationReservationJoinV3(expected, session, reservation, machineKey)
	if err != nil {
		return stage2aQualificationPreSignArtifactsV1{}, err
	}
	return publishStage2aQualificationPreSign(store, session, reservation, challenge, now, machineKey, sign)
}
