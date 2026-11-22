package qualification

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// VerifyReleasedReportsV3 checks the exact two-report set named by a verified
// release Statement and both Machine-signed completed-run chains. All inputs
// are supplied as local bytes; no resolver or network access is hidden here.
// The caller must separately measure the installed adapter, runner, frozen
// Soul and host inputs before granting protected launch.
func VerifyReleasedReportsV3(release VerifiedRelease, policy VerifiedPolicy,
	qualificationJSON, protectedEnvelope, cooperativeEnvelope,
	protectedExecution, cooperativeExecution,
	protectedCommitment, cooperativeCommitment []byte,
	machineKey ed25519.PublicKey, now time.Time) error {
	if !release.verified || release.v3Reports == nil || !policy.verified || policy.version != 3 ||
		now.IsZero() || !policy.at.Equal(now) || !release.v3ExpiresAt.After(now) ||
		release.ownerKeyID != policy.value.OwnerKeyID ||
		release.policyRevision != policy.value.PolicyRevision ||
		digest(qualificationJSON) != release.qualificationSHA256 ||
		len(machineKey) != ed25519.PublicKeySize {
		return ErrUnqualified
	}
	qualification, refs, _, recorded, err := qualificationObjectV3(qualificationJSON, now)
	if err != nil || refs != *release.v3Reports ||
		digest(protectedEnvelope) != refs.ProtectedReport.Signature.SHA256 ||
		digest(cooperativeEnvelope) != refs.CooperativeReport.Signature.SHA256 ||
		digest(protectedCommitment) != refs.ProtectedReport.CompletedRun.SHA256 ||
		digest(cooperativeCommitment) != refs.CooperativeReport.CompletedRun.SHA256 ||
		digest(protectedExecution) == digest(cooperativeExecution) {
		return ErrUnqualified
	}
	var soulArtifact string
	if json.Unmarshal(qualification["soul_artifact_sha256"], &soulArtifact) != nil ||
		soulArtifact != release.v3SoulArtifact {
		return ErrUnqualified
	}
	if verifyV3ReportPairClaims(policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, now) != nil {
		return ErrUnqualified
	}
	for _, run := range []struct {
		report, execution, commitment []byte
		expected                      string
	}{
		{protectedEnvelope, protectedExecution, protectedCommitment, refs.ProtectedReport.CompletedRun.SHA256},
		{cooperativeEnvelope, cooperativeExecution, cooperativeCommitment, refs.CooperativeReport.CompletedRun.SHA256},
	} {
		if VerifyCompletedRunV3(run.report, run.execution, run.commitment, machineKey, run.expected, policy, now) != nil {
			return ErrUnqualified
		}
		payload, err := verifyMachineRecordV3(run.commitment, ReportCommitmentPurposeV3, machineKey)
		if err != nil {
			return ErrUnqualified
		}
		var commitment reportCommitmentV3
		if json.Unmarshal(payload, &commitment) != nil {
			return ErrUnqualified
		}
		committed, err := parseTime(commitment.CommittedAt)
		if err != nil || committed.After(recorded) {
			return ErrUnqualified
		}
	}
	return nil
}
