package qualification

import (
	"encoding/json"
	"time"
)

// verifyV3ReportPairClaims checks candidate qualification bytes against two
// authenticated host report byte sequences. It deliberately does not
// authenticate Machine-owned one-use records, the release signature, or
// installed bytes.
func verifyV3ReportPairClaims(policy VerifiedPolicy, qualificationJSON, protectedEnvelope, cooperativeEnvelope []byte, now time.Time) error {
	if !policy.verified || policy.version != 3 || policy.value.FrozenSoulMapping == nil || now.IsZero() || !policy.at.Equal(now) {
		return ErrUnqualified
	}
	qualification, refs, _, qualificationAt, err := qualificationObjectV3(qualificationJSON, now)
	if err != nil {
		return ErrUnqualified
	}
	protectedRaw, pErr := VerifyHostReportV3(protectedEnvelope, policy, now)
	cooperativeRaw, cErr := VerifyHostReportV3(cooperativeEnvelope, policy, now)
	if pErr != nil || cErr != nil ||
		digest(protectedRaw) != refs.ProtectedReport.Payload.SHA256 ||
		digest(protectedEnvelope) != refs.ProtectedReport.Signature.SHA256 ||
		digest(cooperativeRaw) != refs.CooperativeReport.Payload.SHA256 ||
		digest(cooperativeEnvelope) != refs.CooperativeReport.Signature.SHA256 {
		return ErrUnqualified
	}
	p, err := strictObject(protectedRaw, MaxReportBytes)
	if err != nil {
		return ErrUnqualified
	}
	c, err := strictObject(cooperativeRaw, MaxReportBytes)
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
	var pReport, cReport reportDocument
	if json.Unmarshal(protectedRaw, &pReport) != nil || json.Unmarshal(cooperativeRaw, &cReport) != nil {
		return ErrUnqualified
	}
	for _, date := range []string{pReport.RecordedAt, cReport.RecordedAt} {
		at, err := parseTime(date)
		if err != nil || at.After(now) || at.After(qualificationAt) {
			return ErrUnqualified
		}
	}
	pBinding, err := parseMeasurementBindingV2(p["measurement_binding"])
	if err != nil {
		return ErrUnqualified
	}
	cBinding, err := parseMeasurementBindingV2(c["measurement_binding"])
	if err != nil {
		return ErrUnqualified
	}
	var releasedSoulArtifact string
	if json.Unmarshal(qualification["soul_artifact_sha256"], &releasedSoulArtifact) != nil ||
		pBinding.SoulArtifactSHA256 != releasedSoulArtifact {
		return ErrUnqualified
	}
	mapping := policy.value.FrozenSoulMapping
	if mapping.SoulID != pBinding.SoulID || mapping.ArtifactSHA256 != releasedSoulArtifact ||
		mapping.ClaimedDefinitionDigest != pBinding.ClaimedDefinitionDigest ||
		mapping.DefinitionMeasurement != pBinding.DefinitionMeasurement {
		return ErrUnqualified
	}
	if pBinding.InstallationID != cBinding.InstallationID || pBinding.SoulID != cBinding.SoulID ||
		pBinding.HostID != cBinding.HostID ||
		pBinding.PackageSHA256 != cBinding.PackageSHA256 ||
		pBinding.SoulArtifactSHA256 != cBinding.SoulArtifactSHA256 ||
		pBinding.ClaimedDefinitionDigest != cBinding.ClaimedDefinitionDigest ||
		pBinding.DefinitionMeasurement != cBinding.DefinitionMeasurement ||
		pBinding.Snapshots.Definition != cBinding.Snapshots.Definition ||
		pBinding.StartID == cBinding.StartID || pBinding.LaunchID == cBinding.LaunchID ||
		pBinding.LaunchInputMeasurement == cBinding.LaunchInputMeasurement ||
		pBinding.Snapshots.LaunchInputs == cBinding.Snapshots.LaunchInputs {
		return ErrUnqualified
	}
	var pRun, cRun struct {
		Reservation         reportReference `json:"reservation"`
		Finalization        reportReference `json:"finalization"`
		ChallengeSHA256     string          `json:"challenge_sha256"`
		ExecutionCompletion reportReference `json:"execution_completion"`
	}
	if json.Unmarshal(p["run_evidence"], &pRun) != nil || json.Unmarshal(c["run_evidence"], &cRun) != nil ||
		pRun.Reservation.URI == cRun.Reservation.URI || pRun.Reservation.SHA256 == cRun.Reservation.SHA256 ||
		pRun.Finalization.URI == cRun.Finalization.URI || pRun.Finalization.SHA256 == cRun.Finalization.SHA256 ||
		pRun.ExecutionCompletion.URI == cRun.ExecutionCompletion.URI || pRun.ExecutionCompletion.SHA256 == cRun.ExecutionCompletion.SHA256 ||
		pRun.ChallengeSHA256 == cRun.ChallengeSHA256 {
		return ErrUnqualified
	}
	return nil
}
