package qualification

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// HostReportsPreflightV3 is producer evidence for a future release workflow.
// It is not a verified release, installed-byte measurement, or launch grant.
type HostReportsPreflightV3 struct {
	ProtectedReportSHA256                string
	ProtectedEnvelopeSHA256              string
	ProtectedExecutionCompletionSHA256   string
	ProtectedCompletedRunSHA256          string
	CooperativeReportSHA256              string
	CooperativeEnvelopeSHA256            string
	CooperativeExecutionCompletionSHA256 string
	CooperativeCompletedRunSHA256        string
	SoulArtifactSHA256                   string
	SoulsBuildBundleSHA256               string
	SoulsPackageSHA256                   string
	SoulsSourceTree                      string
}

// VerifyHostReportsForReleaseV3 checks the exact candidate qualification,
// two host envelopes, both distinct Machine completion chains, and a
// separately authenticated Souls build before a release is signed. The
// caller must still authenticate the physical observer and measured bytes.
func VerifyHostReportsForReleaseV3(policy VerifiedPolicy, qualificationJSON,
	protectedEnvelope, cooperativeEnvelope, protectedExecution, cooperativeExecution,
	protectedCommitment, cooperativeCommitment []byte, build VerifiedSoulsBuild,
	machineKey ed25519.PublicKey, now time.Time) (HostReportsPreflightV3, error) {
	var zero HostReportsPreflightV3
	if !policy.verified || policy.version != 3 || !policy.at.Equal(now) || !build.verified ||
		len(machineKey) != ed25519.PublicKeySize || digest(protectedExecution) == digest(cooperativeExecution) {
		return zero, ErrUnqualified
	}
	fields, refs, claim, recorded, err := qualificationObjectV3(qualificationJSON, now)
	if err != nil || build.build != claim ||
		verifyV3ReportPairClaims(policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, now) != nil {
		return zero, ErrUnqualified
	}
	var soulArtifact string
	if json.Unmarshal(fields["soul_artifact_sha256"], &soulArtifact) != nil {
		return zero, ErrUnqualified
	}
	for _, run := range []struct {
		host, execution, commitment []byte
		ref                         qualificationReportRefV3
	}{
		{protectedEnvelope, protectedExecution, protectedCommitment, refs.ProtectedReport},
		{cooperativeEnvelope, cooperativeExecution, cooperativeCommitment, refs.CooperativeReport},
	} {
		if digest(run.commitment) != run.ref.CompletedRun.SHA256 ||
			VerifyCompletedRunV3(run.host, run.execution, run.commitment, machineKey,
				run.ref.CompletedRun.SHA256, policy, now) != nil {
			return zero, ErrUnqualified
		}
		payload, err := verifyMachineRecordV3(run.commitment, ReportCommitmentPurposeV3, machineKey)
		if err != nil {
			return zero, ErrUnqualified
		}
		var commitment reportCommitmentV3
		if json.Unmarshal(payload, &commitment) != nil {
			return zero, ErrUnqualified
		}
		committed, err := parseTime(commitment.CommittedAt)
		if err != nil || committed.After(recorded) {
			return zero, ErrUnqualified
		}
	}
	return HostReportsPreflightV3{
		ProtectedReportSHA256:                refs.ProtectedReport.Payload.SHA256,
		ProtectedEnvelopeSHA256:              refs.ProtectedReport.Signature.SHA256,
		ProtectedExecutionCompletionSHA256:   digest(protectedExecution),
		ProtectedCompletedRunSHA256:          refs.ProtectedReport.CompletedRun.SHA256,
		CooperativeReportSHA256:              refs.CooperativeReport.Payload.SHA256,
		CooperativeEnvelopeSHA256:            refs.CooperativeReport.Signature.SHA256,
		CooperativeExecutionCompletionSHA256: digest(cooperativeExecution),
		CooperativeCompletedRunSHA256:        refs.CooperativeReport.CompletedRun.SHA256,
		SoulArtifactSHA256:                   soulArtifact,
		SoulsBuildBundleSHA256:               claim.Receipt.SHA256,
		SoulsPackageSHA256:                   claim.PackageSHA,
		SoulsSourceTree:                      claim.SourceTree,
	}, nil
}
