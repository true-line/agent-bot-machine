package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const predicateTypeV4 = "https://true-line.ai/soul-contracts/adapter/v4/macos-measured-qualification"

// These parsers recognize the exact v4 release bytes without minting a
// VerifiedRelease. Signing-time proof, installed bytes and physical results
// remain independent prerequisites for any positive acceptance gate.
type qualificationReportPairV4 = qualificationReportPairV3

func validV4Ref(ref qualificationReportRefV3) bool {
	return ref.ReportSchemaVersion == 4 && ref.SignaturePurpose == HostPurposeV4 &&
		reportRef(ref.Payload) && reportRef(ref.Signature) && reportRef(ref.CompletedRun) &&
		ref.Payload.SHA256 != ref.Signature.SHA256 &&
		ref.Payload.SHA256 != ref.CompletedRun.SHA256 &&
		ref.Signature.SHA256 != ref.CompletedRun.SHA256
}

func validV4Pair(refs qualificationReportPairV4) bool {
	return validV4Ref(refs.ProtectedReport) && validV4Ref(refs.CooperativeReport) &&
		refs.ProtectedReport.Payload.SHA256 != refs.CooperativeReport.Payload.SHA256 &&
		refs.ProtectedReport.Payload.URI != refs.CooperativeReport.Payload.URI &&
		refs.ProtectedReport.Signature.SHA256 != refs.CooperativeReport.Signature.SHA256 &&
		refs.ProtectedReport.Signature.URI != refs.CooperativeReport.Signature.URI &&
		refs.ProtectedReport.CompletedRun.SHA256 != refs.CooperativeReport.CompletedRun.SHA256 &&
		refs.ProtectedReport.CompletedRun.URI != refs.CooperativeReport.CompletedRun.URI
}

func qualificationObjectV4(raw []byte, now time.Time) (map[string]json.RawMessage, qualificationReportPairV4, soulsBuildRef, time.Time, error) {
	refused := func() (map[string]json.RawMessage, qualificationReportPairV4, soulsBuildRef, time.Time, error) {
		return nil, qualificationReportPairV4{}, soulsBuildRef{}, time.Time{}, ErrUnqualified
	}
	fields, err := canonicalObjectV4(raw, MaxReportBytes)
	if err != nil || now.IsZero() || !hasFields(fields, "schema_version", "adapter", "launch", "harness", "runner", "soul_start", "host", "profile_in_force", "renders", "cost_bound", "conformance", "recorded_at", "evaluation_cells", "souls_build", "soul_artifact_sha256") ||
		!bytes.Equal(fields["schema_version"], []byte("4")) || !bytes.Equal(fields["profile_in_force"], []byte(`"managed-protected"`)) {
		return refused()
	}
	var soulArtifact string
	if json.Unmarshal(fields["soul_artifact_sha256"], &soulArtifact) != nil || !validHex(soulArtifact, 64) {
		return refused()
	}
	if _, err = bridgeFields(fields["souls_build"], "source_repository", "source_commit", "source_tree", "builder_sha256", "toolchain_sha256", "workflow", "run_id", "run_attempt", "package_sha256", "receipt"); err != nil {
		return refused()
	}
	var build soulsBuildRef
	if json.Unmarshal(fields["souls_build"], &build) != nil || !validSoulsBuild(build) {
		return refused()
	}
	conformance, err := bridgeFields(fields["conformance"], "suite_revision", "run_id", "outcome", "checks", "protected_report", "cooperative_report", "runner_observations")
	if err != nil || !bytes.Equal(conformance["outcome"], []byte(`"pass"`)) {
		return refused()
	}
	for _, name := range []string{"protected_report", "cooperative_report"} {
		if _, err = bridgeFields(conformance[name], "report_schema_version", "signature_purpose", "payload", "signature", "completed_run"); err != nil {
			return refused()
		}
	}
	var refs qualificationReportPairV4
	if json.Unmarshal(conformance["protected_report"], &refs.ProtectedReport) != nil ||
		json.Unmarshal(conformance["cooperative_report"], &refs.CooperativeReport) != nil ||
		!validV4Pair(refs) {
		return refused()
	}
	observations, err := bridgeFields(conformance["runner_observations"], "pinned_acp_and_cli", "private_state", "authenticated_session", "assigned_endpoints", "direct_ipv4_ipv6_egress", "clean_shutdown")
	if err != nil {
		return refused()
	}
	for _, value := range observations {
		var ref reportReference
		if json.Unmarshal(value, &ref) != nil || !reportRef(ref) {
			return refused()
		}
	}
	var recordedAt string
	if json.Unmarshal(fields["recorded_at"], &recordedAt) != nil {
		return refused()
	}
	recorded, err := parseTime(recordedAt)
	if err != nil || recorded.After(now) {
		return refused()
	}
	for _, name := range []string{"suite_revision", "run_id", "outcome", "checks"} {
		fields["conformance_"+name] = conformance[name]
	}
	return fields, refs, build, recorded, nil
}

type qualificationStatementV4 struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		HostReports        qualificationReportPairV4 `json:"host_reports"`
		SoulsBuild         soulsBuildRef             `json:"souls_build"`
		SoulArtifactSHA256 string                    `json:"soul_artifact_sha256"`
		ExpiresAt          string                    `json:"expires_at"`
		Release            struct {
			SourceRepository string `json:"source_repository"`
			SourceCommit     string `json:"source_commit"`
			Workflow         string `json:"workflow"`
		} `json:"release"`
	} `json:"predicate"`
}

func fixedStatementV4(raw []byte, policy Policy, qualificationSHA, expectedSoulArtifact string,
	qualificationRecorded, now time.Time) (qualificationReportPairV4, soulsBuildRef, time.Time, error) {
	refused := func() (qualificationReportPairV4, soulsBuildRef, time.Time, error) {
		return qualificationReportPairV4{}, soulsBuildRef{}, time.Time{}, ErrUnqualified
	}
	if !validSHA(qualificationSHA) || !validHex(expectedSoulArtifact, 64) || now.IsZero() ||
		qualificationRecorded.IsZero() || qualificationRecorded.After(now) {
		return refused()
	}
	if _, err := canonicalObjectV4(raw, MaxReportBytes); err != nil {
		return refused()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement qualificationStatementV4
	if d.Decode(&statement) != nil {
		return refused()
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return refused()
	}
	if statement.Type != statementType || statement.PredicateType != predicateTypeV4 ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != "qualification.json" ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != qualificationSHA[7:] ||
		statement.Predicate.Release.SourceRepository != policy.ReleaseWorkflow.Repository ||
		statement.Predicate.Release.SourceCommit != policy.ReleaseWorkflow.SourceCommit ||
		statement.Predicate.Release.Workflow != policy.ReleaseWorkflow.WorkflowPath ||
		!validV4Pair(statement.Predicate.HostReports) ||
		statement.Predicate.SoulArtifactSHA256 != expectedSoulArtifact ||
		!validSoulsBuild(statement.Predicate.SoulsBuild) {
		return refused()
	}
	expires, err := parseTime(statement.Predicate.ExpiresAt)
	if err != nil || !expires.After(now) || !expires.After(qualificationRecorded) {
		return refused()
	}
	return statement.Predicate.HostReports, statement.Predicate.SoulsBuild, expires, nil
}
