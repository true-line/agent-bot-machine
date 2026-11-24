package qualification

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// VerifyV4SignedReleaseCandidateClaims joins an independently verified v4
// release bundle to the same exact qualification and completed run bytes used
// by the candidate checker. A nil result is still diagnostic: raw Q/ACP/OS,
// installed-byte custody and physical gate verdicts remain separate gates.
func VerifyV4SignedReleaseCandidateClaims(release VerifiedRelease, policy VerifiedPolicy,
	qualificationJSON, statementRaw, protectedEnvelope, cooperativeEnvelope,
	protectedExecution, cooperativeExecution, protectedCommitment, cooperativeCommitment []byte,
	build VerifiedSoulsBuild, machineKey ed25519.PublicKey, now time.Time) error {
	if !release.verified || !validSHA(release.bundleSHA256) || release.v4Reports == nil ||
		release.v4SoulsBuild == nil || release.qualificationSHA256 != digest(qualificationJSON) ||
		!validSHA(release.v4StatementSHA256) || release.v4StatementSHA256 != digest(statementRaw) ||
		release.ownerKeyID != policy.value.OwnerKeyID || release.policyRevision != policy.value.PolicyRevision ||
		!release.v4ExpiresAt.After(now) || !build.verified || *release.v4SoulsBuild != build.build {
		return ErrUnqualified
	}
	qualification, refs, _, _, err := qualificationObjectV4(qualificationJSON, now)
	if err != nil || refs != *release.v4Reports {
		return ErrUnqualified
	}
	var artifact string
	if json.Unmarshal(qualification["soul_artifact_sha256"], &artifact) != nil || artifact != release.v4SoulArtifact {
		return ErrUnqualified
	}
	return VerifyV4ReleaseCandidateClaims(policy, qualificationJSON, statementRaw,
		protectedEnvelope, cooperativeEnvelope, protectedExecution, cooperativeExecution,
		protectedCommitment, cooperativeCommitment, build, machineKey, now)
}

// VerifyV4ReleaseCandidateClaims checks the unsigned release candidate's
// exact v4 qualification/Statement bytes, two owner-designated host signatures,
// two A pre-sign/post-sign chains and separately verified Souls build. A nil
// error is diagnostic only: this function has no release signing-time proof,
// raw Q/ACP/OS traversal, installed-byte proof, or physical gate verdict.
// It never mints VerifiedRelease or opens protected launch.
func VerifyV4ReleaseCandidateClaims(policy VerifiedPolicy, qualificationJSON, statementRaw,
	protectedEnvelope, cooperativeEnvelope, protectedExecution, cooperativeExecution,
	protectedCommitment, cooperativeCommitment []byte, build VerifiedSoulsBuild,
	machineKey ed25519.PublicKey, now time.Time) error {
	if !policy.verified || policy.version != 3 || !policy.at.Equal(now) || now.IsZero() ||
		policy.value.FrozenSoulMapping == nil || !build.verified || len(machineKey) != ed25519.PublicKeySize ||
		digest(protectedExecution) == digest(cooperativeExecution) {
		return ErrUnqualified
	}
	qualification, refs, claimedBuild, recorded, err := qualificationObjectV4(qualificationJSON, now)
	if err != nil || claimedBuild != build.build {
		return ErrUnqualified
	}
	var artifact string
	if json.Unmarshal(qualification["soul_artifact_sha256"], &artifact) != nil {
		return ErrUnqualified
	}
	statementRefs, statementBuild, expires, err := fixedStatementV4(statementRaw, policy.value,
		digest(qualificationJSON), artifact, recorded, now)
	if err != nil || refs != statementRefs || claimedBuild != statementBuild || !expires.After(now) {
		return ErrUnqualified
	}
	protected, err := VerifyHostReportV4(protectedEnvelope, policy, now)
	if err != nil {
		return ErrUnqualified
	}
	cooperative, err := VerifyHostReportV4(cooperativeEnvelope, policy, now)
	if err != nil || digest(protected) != refs.ProtectedReport.Payload.SHA256 ||
		digest(protectedEnvelope) != refs.ProtectedReport.Signature.SHA256 ||
		digest(protectedCommitment) != refs.ProtectedReport.CompletedRun.SHA256 ||
		digest(cooperative) != refs.CooperativeReport.Payload.SHA256 ||
		digest(cooperativeEnvelope) != refs.CooperativeReport.Signature.SHA256 ||
		digest(cooperativeCommitment) != refs.CooperativeReport.CompletedRun.SHA256 {
		return ErrUnqualified
	}
	if verifyV4ReportPairClaims(policy, qualification, protected, cooperative, artifact, recorded, now) != nil {
		return ErrUnqualified
	}
	for _, run := range []struct {
		host, execution, commitment []byte
		ref                         qualificationReportRefV3
	}{
		{protectedEnvelope, protectedExecution, protectedCommitment, refs.ProtectedReport},
		{cooperativeEnvelope, cooperativeExecution, cooperativeCommitment, refs.CooperativeReport},
	} {
		if VerifyCompletedRunV4(run.host, run.execution, run.commitment, machineKey,
			run.ref.CompletedRun.SHA256, policy, now) != nil {
			return ErrUnqualified
		}
		payload, err := verifyMachineRecordV4(run.commitment, ReportCommitmentPurposeV4, machineKey)
		if err != nil {
			return ErrUnqualified
		}
		var commitment reportCommitmentV4
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

func verifyV4ReportPairClaims(policy VerifiedPolicy, qualification map[string]json.RawMessage,
	protected, cooperative []byte, artifact string, qualificationAt, now time.Time) error {
	p, err := canonicalObjectV4(protected, MaxReportBytes)
	if err != nil {
		return ErrUnqualified
	}
	c, err := canonicalObjectV4(cooperative, MaxReportBytes)
	if err != nil || !sameJSON(p["profile_in_force"], []byte(`"managed-protected"`)) ||
		!sameJSON(c["profile_in_force"], []byte(`"managed-cooperative"`)) ||
		sameJSON(p["run_id"], c["run_id"]) {
		return ErrUnqualified
	}
	for _, name := range []string{"adapter", "launch", "harness", "runner", "host", "renders", "cost_bound", "evaluation_cells"} {
		if !sameJSON(qualification[name], p[name]) || !sameJSON(qualification[name], c[name]) {
			return ErrUnqualified
		}
	}
	if !sameJSON(qualification["soul_start"], p["soul_start"]) ||
		!sameJSON(qualification["profile_in_force"], p["profile_in_force"]) ||
		!sameJSON(qualification["conformance_suite_revision"], p["suite_revision"]) ||
		!sameJSON(p["suite_revision"], c["suite_revision"]) ||
		!sameJSON(qualification["conformance_run_id"], p["run_id"]) ||
		!sameJSON(qualification["conformance_outcome"], p["outcome"]) ||
		!sameJSON(qualification["conformance_checks"], p["checks"]) {
		return ErrUnqualified
	}
	// The two physical profiles need separate HQ launch and A observation
	// objects, even when they reuse the same frozen Soul installation. A URI
	// alias or the same bytes under another URI cannot stand for another run.
	var pStart, cStart struct {
		HQLaunchReceipt    reportReference `json:"hq_launch_receipt"`
		MachineObservation reportReference `json:"machine_observation"`
	}
	if json.Unmarshal(p["soul_start"], &pStart) != nil || json.Unmarshal(c["soul_start"], &cStart) != nil ||
		!reportRef(pStart.HQLaunchReceipt) || !reportRef(cStart.HQLaunchReceipt) ||
		!reportRef(pStart.MachineObservation) || !reportRef(cStart.MachineObservation) ||
		pStart.HQLaunchReceipt.URI == cStart.HQLaunchReceipt.URI ||
		pStart.HQLaunchReceipt.SHA256 == cStart.HQLaunchReceipt.SHA256 ||
		pStart.MachineObservation.URI == cStart.MachineObservation.URI ||
		pStart.MachineObservation.SHA256 == cStart.MachineObservation.SHA256 {
		return ErrUnqualified
	}
	for _, raw := range [][]byte{protected, cooperative} {
		var report struct {
			RecordedAt string `json:"recorded_at"`
		}
		if json.Unmarshal(raw, &report) != nil {
			return ErrUnqualified
		}
		at, err := parseTime(report.RecordedAt)
		if err != nil || at.After(now) || at.After(qualificationAt) {
			return ErrUnqualified
		}
	}
	pMeasured, err := parseHRMeasurementBindingV3(p["measurement_binding"])
	if err != nil {
		return ErrUnqualified
	}
	cMeasured, err := parseCooperativeMeasurementBindingV3(c["measurement_binding"])
	pBinding, cBinding := pMeasured.Base, cMeasured.Base
	if err != nil || pBinding.SoulArtifactSHA256 != artifact {
		return ErrUnqualified
	}
	mapping := policy.value.FrozenSoulMapping
	if mapping.SoulID != pBinding.SoulID || mapping.ArtifactSHA256 != artifact ||
		mapping.ClaimedDefinitionDigest != pBinding.ClaimedDefinitionDigest ||
		mapping.DefinitionMeasurement != pBinding.DefinitionMeasurement ||
		pMeasured.AdapterRelease != cMeasured.AdapterRelease ||
		pBinding.InstallationID != cBinding.InstallationID || pBinding.SoulID != cBinding.SoulID ||
		pBinding.HostID != cBinding.HostID || pBinding.PackageSHA256 != cBinding.PackageSHA256 ||
		pBinding.SoulArtifactSHA256 != cBinding.SoulArtifactSHA256 ||
		pBinding.ClaimedDefinitionDigest != cBinding.ClaimedDefinitionDigest ||
		pBinding.DefinitionMeasurement != cBinding.DefinitionMeasurement ||
		pBinding.Snapshots.Definition != cBinding.Snapshots.Definition ||
		pBinding.StartID == cBinding.StartID || pBinding.LaunchID == cBinding.LaunchID ||
		pBinding.LaunchInputMeasurement == cBinding.LaunchInputMeasurement ||
		pBinding.Snapshots.LaunchInputs == cBinding.Snapshots.LaunchInputs {
		return ErrUnqualified
	}
	pRun, err := reportRefsV4(p["run_evidence"], "managed-protected")
	if err != nil {
		return ErrUnqualified
	}
	cRun, err := reportRefsV4(c["run_evidence"], "managed-cooperative")
	if err != nil || pRun.Reservation == cRun.Reservation ||
		pRun.ExecutionCompletion == cRun.ExecutionCompletion ||
		pRun.ChallengeSHA256 == cRun.ChallengeSHA256 ||
		pRun.QSession.FramedWire == cRun.QSession.FramedWire ||
		pRun.QSession.FrameIndexEnvelope == cRun.QSession.FrameIndexEnvelope ||
		pRun.QSession.CleanEOFEnvelope == cRun.QSession.CleanEOFEnvelope {
		return ErrUnqualified
	}
	return nil
}
