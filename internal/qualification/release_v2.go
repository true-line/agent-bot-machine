package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const predicateTypeV2 = "https://true-line.ai/soul-contracts/adapter/v2/macos-protected-qualification"

type qualificationReportRef struct {
	ReportSchemaVersion int             `json:"report_schema_version"`
	SignaturePurpose    string          `json:"signature_purpose"`
	Payload             reportReference `json:"payload"`
	Signature           reportReference `json:"signature"`
}

type qualificationReportPair struct {
	ProtectedReport   qualificationReportRef `json:"protected_report"`
	CooperativeReport qualificationReportRef `json:"cooperative_report"`
}

type soulsBuildRef struct {
	SourceRepository string          `json:"source_repository"`
	SourceCommit     string          `json:"source_commit"`
	SourceTree       string          `json:"source_tree"`
	BuilderSHA       string          `json:"builder_sha256"`
	ToolchainSHA     string          `json:"toolchain_sha256"`
	Workflow         string          `json:"workflow"`
	RunID            string          `json:"run_id"`
	RunAttempt       uint64          `json:"run_attempt"`
	PackageSHA       string          `json:"package_sha256"`
	Receipt          reportReference `json:"receipt"`
}

// VerifiedSoulsBuild is minted only by the separate offline Sigstore receipt
// verifier under the owner-pinned Souls build root and approved source tree.
type VerifiedSoulsBuild struct {
	verified bool
	build    soulsBuildRef
}

func validSoulsBuild(b soulsBuildRef) bool {
	runID, err := strconv.ParseUint(b.RunID, 10, 64)
	workflow := strings.TrimPrefix(b.Workflow, ".github/workflows/")
	validWorkflow := strings.HasPrefix(b.Workflow, ".github/workflows/") && workflow != "" &&
		(strings.HasSuffix(workflow, ".yml") || strings.HasSuffix(workflow, ".yaml")) &&
		!strings.Contains(workflow, "..")
	for _, c := range workflow {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			validWorkflow = false
		}
	}
	return b.SourceRepository == "true-line/agent-bot-souls" &&
		validHex(b.SourceCommit, 40) && validHex(b.SourceTree, 40) &&
		validSHA(b.BuilderSHA) && validSHA(b.ToolchainSHA) && validSHA(b.PackageSHA) &&
		validWorkflow &&
		err == nil && runID > 0 && b.RunID[0] != '0' && b.RunAttempt > 0 && reportRef(b.Receipt)
}

type qualificationStatementV2 struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		HostReports qualificationReportPair `json:"host_reports"`
		SoulsBuild  soulsBuildRef           `json:"souls_build"`
		ExpiresAt   string                  `json:"expires_at"`
		Release     struct {
			SourceRepository string `json:"source_repository"`
			SourceCommit     string `json:"source_commit"`
			Workflow         string `json:"workflow"`
		} `json:"release"`
	} `json:"predicate"`
}

func validV2Ref(ref qualificationReportRef, version int, purpose string) bool {
	return ref.ReportSchemaVersion == version && ref.SignaturePurpose == purpose &&
		reportRef(ref.Payload) && reportRef(ref.Signature) && ref.Payload.SHA256 != ref.Signature.SHA256
}

func fixedStatementV2(raw []byte, policy Policy, qualificationSHA string, now time.Time) (qualificationReportPair, soulsBuildRef, error) {
	if _, err := strictObject(raw, MaxReportBytes); err != nil {
		return qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement qualificationStatementV2
	if d.Decode(&statement) != nil {
		return qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	if statement.Type != statementType || statement.PredicateType != predicateTypeV2 ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != "qualification.json" ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != qualificationSHA[7:] ||
		statement.Predicate.Release.SourceRepository != policy.ReleaseWorkflow.Repository ||
		statement.Predicate.Release.SourceCommit != policy.ReleaseWorkflow.SourceCommit ||
		statement.Predicate.Release.Workflow != policy.ReleaseWorkflow.WorkflowPath ||
		!validV2Ref(statement.Predicate.HostReports.ProtectedReport, 2, HostPurposeV2) ||
		!validV2Ref(statement.Predicate.HostReports.CooperativeReport, 1, HostPurpose) ||
		!validSoulsBuild(statement.Predicate.SoulsBuild) {
		return qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	expires, err := parseTime(statement.Predicate.ExpiresAt)
	if err != nil || !expires.After(now) {
		return qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	return statement.Predicate.HostReports, statement.Predicate.SoulsBuild, nil
}

func qualificationObjectV2(raw []byte) (map[string]json.RawMessage, qualificationReportPair, soulsBuildRef, error) {
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, "schema_version", "adapter", "launch", "harness", "runner", "soul_start", "host", "profile_in_force", "renders", "cost_bound", "conformance", "recorded_at", "evaluation_cells", "souls_build") ||
		!bytes.Equal(fields["schema_version"], []byte("2")) || !bytes.Equal(fields["profile_in_force"], []byte(`"managed-protected"`)) {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	if _, err = bridgeFields(fields["souls_build"], "source_repository", "source_commit", "source_tree", "builder_sha256", "toolchain_sha256", "workflow", "run_id", "run_attempt", "package_sha256", "receipt"); err != nil {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	var build soulsBuildRef
	if json.Unmarshal(fields["souls_build"], &build) != nil || !validSoulsBuild(build) {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	conformance, err := bridgeFields(fields["conformance"], "suite_revision", "run_id", "outcome", "checks", "protected_report", "cooperative_report", "runner_observations")
	if err != nil || !bytes.Equal(conformance["outcome"], []byte(`"pass"`)) {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	if _, err = bridgeFields(conformance["protected_report"], "report_schema_version", "signature_purpose", "payload", "signature"); err != nil {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	if _, err = bridgeFields(conformance["cooperative_report"], "report_schema_version", "signature_purpose", "payload", "signature"); err != nil {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	var refs qualificationReportPair
	if json.Unmarshal(conformance["protected_report"], &refs.ProtectedReport) != nil ||
		json.Unmarshal(conformance["cooperative_report"], &refs.CooperativeReport) != nil ||
		!validV2Ref(refs.ProtectedReport, 2, HostPurposeV2) ||
		!validV2Ref(refs.CooperativeReport, 1, HostPurpose) {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	observations, err := bridgeFields(conformance["runner_observations"], "pinned_acp_and_cli", "private_state", "authenticated_session", "assigned_endpoints", "direct_ipv4_ipv6_egress", "clean_shutdown")
	if err != nil {
		return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
	}
	for _, ref := range observations {
		var r reportReference
		if json.Unmarshal(ref, &r) != nil || !reportRef(r) {
			return nil, qualificationReportPair{}, soulsBuildRef{}, ErrUnqualified
		}
	}
	for _, name := range []string{"suite_revision", "run_id", "outcome", "checks"} {
		fields["conformance_"+name] = conformance[name]
	}
	return fields, refs, build, nil
}

// VerifyHostReportsForReleaseV2 is a producer preflight. It verifies both
// designated-host signatures and exact v2 qualification references, but no
// release attestation or installed-byte measurements exist at this stage.
func VerifyHostReportsForReleaseV2(policy VerifiedPolicy, qualificationJSON, protectedEnvelope, cooperativeEnvelope []byte, build VerifiedSoulsBuild, now time.Time) (qualificationReportPair, error) {
	_, refs, buildClaim, err := qualificationObjectV2(qualificationJSON)
	if err != nil {
		return qualificationReportPair{}, ErrUnqualified
	}
	release := VerifiedRelease{verified: true, qualificationSHA256: digest(qualificationJSON), ownerKeyID: policy.value.OwnerKeyID, policyRevision: policy.value.PolicyRevision, v2Reports: &refs, v2SoulsBuild: &buildClaim}
	if VerifyReleasedReportsV2(release, policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, build, now) != nil {
		return qualificationReportPair{}, ErrUnqualified
	}
	return refs, nil
}

// VerifyReleasedReportsV2 binds both exact signed envelopes and payloads to
// the bridge-aware qualification and Statement. It does not resolve the
// independently captured physical observations or measure installed files.
func VerifyReleasedReportsV2(release VerifiedRelease, policy VerifiedPolicy, qualificationJSON, protectedEnvelope, cooperativeEnvelope []byte, build VerifiedSoulsBuild, now time.Time) error {
	if !release.verified || release.v2Reports == nil || release.v2SoulsBuild == nil || !build.verified || !policy.verified || policy.version != 2 || now.IsZero() || !policy.at.Equal(now) ||
		release.ownerKeyID != policy.value.OwnerKeyID || release.policyRevision != policy.value.PolicyRevision ||
		digest(qualificationJSON) != release.qualificationSHA256 {
		return ErrUnqualified
	}
	qualification, qualificationRefs, qualificationBuild, err := qualificationObjectV2(qualificationJSON)
	if err != nil || !reflect.DeepEqual(qualificationRefs, *release.v2Reports) ||
		qualificationBuild != *release.v2SoulsBuild || qualificationBuild != build.build {
		return ErrUnqualified
	}
	protectedRaw, e1 := VerifyHostReportV2(protectedEnvelope, policy, now)
	cooperativeRaw, e2 := VerifyHostReport(cooperativeEnvelope, policy, now)
	if e1 != nil || e2 != nil ||
		digest(protectedRaw) != qualificationRefs.ProtectedReport.Payload.SHA256 ||
		digest(protectedEnvelope) != qualificationRefs.ProtectedReport.Signature.SHA256 ||
		digest(cooperativeRaw) != qualificationRefs.CooperativeReport.Payload.SHA256 ||
		digest(cooperativeEnvelope) != qualificationRefs.CooperativeReport.Signature.SHA256 {
		return ErrUnqualified
	}
	var protected, cooperative reportDocument
	if json.Unmarshal(protectedRaw, &protected) != nil || json.Unmarshal(cooperativeRaw, &cooperative) != nil ||
		protected.SchemaVersion != 2 || cooperative.SchemaVersion != 1 ||
		protected.ProfileInForce != "managed-protected" || cooperative.ProfileInForce != "managed-cooperative" ||
		protected.RunID == cooperative.RunID ||
		protected.Adapter != cooperative.Adapter || !reflect.DeepEqual(protected.Launch, cooperative.Launch) ||
		protected.Harness != cooperative.Harness || protected.Runner != cooperative.Runner ||
		protected.Host.ID != cooperative.Host.ID || protected.Host.OS != cooperative.Host.OS ||
		protected.Host.OSVersion != cooperative.Host.OSVersion || protected.Host.Architecture != cooperative.Host.Architecture ||
		protected.Host.Profile != cooperative.Host.Profile || protected.SuiteRevision != cooperative.SuiteRevision ||
		!reflect.DeepEqual(protected.Renders, cooperative.Renders) || protected.CostBound != cooperative.CostBound ||
		!reflect.DeepEqual(protected.EvaluationCells, cooperative.EvaluationCells) ||
		len(protected.Gates) != 3 || len(cooperative.Gates) != 1 ||
		protected.Gates["T01"].Outcome != "pass" || protected.Gates["T02"].Outcome != "pass" ||
		protected.Gates["T03"].Outcome != "pass" || cooperative.Gates["T21"].Outcome != "pass" ||
		!qualificationMatchesReport(qualification, protected) {
		return ErrUnqualified
	}
	return nil
}
