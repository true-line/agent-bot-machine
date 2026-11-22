package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	maxReleaseBundle = 4 << 20
	maxTrustedRoot   = 1 << 20
	statementType    = "https://in-toto.io/Statement/v1"
	predicateType    = "https://true-line.ai/soul-contracts/adapter/v1/macos-protected-qualification"
	bundleMediaType  = "application/vnd.dev.sigstore.bundle.v0.3+json"
	DSSEPayloadType  = "application/vnd.in-toto+json"
)

// VerifiedRelease is only produced after offline verification against the
// already verified owner policy. It grants no launch permission by itself.
type VerifiedRelease struct {
	verified            bool
	bundleSHA256        string
	qualificationSHA256 string
	hostReports         []reportReference
	ownerKeyID          string
	policyRevision      uint64
}

func (r VerifiedRelease) HostReportDigests() []string {
	if !r.verified {
		return nil
	}
	out := make([]string, len(r.hostReports))
	for i, ref := range r.hostReports {
		out[i] = ref.SHA256
	}
	return out
}

type qualificationStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		HostReports []reportReference `json:"host_reports"`
		ExpiresAt   string            `json:"expires_at"`
		Release     struct {
			SourceRepository string `json:"source_repository"`
			SourceCommit     string `json:"source_commit"`
			Workflow         string `json:"workflow"`
		} `json:"release"`
	} `json:"predicate"`
}

func fixedStatement(raw []byte, policy Policy, qualificationSHA string, now time.Time) ([]reportReference, error) {
	if _, err := strictObject(raw, MaxReportBytes); err != nil {
		return nil, ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement qualificationStatement
	if d.Decode(&statement) != nil {
		return nil, ErrUnqualified
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrUnqualified
	}
	if statement.Type != statementType || statement.PredicateType != predicateType ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != "qualification.json" ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != qualificationSHA[7:] ||
		len(statement.Predicate.HostReports) < 2 || len(statement.Predicate.HostReports) > 16 ||
		statement.Predicate.Release.SourceRepository != policy.ReleaseWorkflow.Repository ||
		statement.Predicate.Release.SourceCommit != policy.ReleaseWorkflow.SourceCommit ||
		statement.Predicate.Release.Workflow != policy.ReleaseWorkflow.WorkflowPath {
		return nil, ErrUnqualified
	}
	expires, err := parseTime(statement.Predicate.ExpiresAt)
	if err != nil || !expires.After(now) {
		return nil, ErrUnqualified
	}
	seen := map[string]bool{}
	for _, ref := range statement.Predicate.HostReports {
		if !reportRef(ref) || seen[ref.SHA256] {
			return nil, ErrUnqualified
		}
		seen[ref.SHA256] = true
	}
	return statement.Predicate.HostReports, nil
}

// VerifyReleaseAttestation verifies a local Sigstore v0.3 DSSE bundle. The
// expected bundle digest must come from the installed adapter's qualification
// reference, while trustedRootJSON must come from the reviewed Machine release.
// Neither can be accepted from the bundle being verified. No network fetch is
// made: the root, bundle, statement, certificate and log proofs are local.
func VerifyReleaseAttestation(policy VerifiedPolicy, trustedRootJSON, bundleJSON, qualificationJSON []byte, expectedBundleSHA256 string, now time.Time) (VerifiedRelease, error) {
	if !policy.verified || now.IsZero() || !policy.at.Equal(now) ||
		len(trustedRootJSON) == 0 || len(trustedRootJSON) > maxTrustedRoot ||
		len(bundleJSON) == 0 || len(bundleJSON) > maxReleaseBundle ||
		len(qualificationJSON) == 0 || len(qualificationJSON) > MaxReportBytes ||
		!validSHA(expectedBundleSHA256) || digest(trustedRootJSON) != policy.value.ReleaseWorkflow.TrustRootSHA256 ||
		digest(bundleJSON) != expectedBundleSHA256 {
		return VerifiedRelease{}, ErrUnqualified
	}
	for _, revoked := range policy.value.RevocationSnapshot.RevokedAttestationSHA256 {
		if revoked == expectedBundleSHA256 {
			return VerifiedRelease{}, ErrUnqualified
		}
	}
	trust, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return VerifiedRelease{}, ErrUnqualified
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil || b.GetMediaType() != bundleMediaType || b.GetDsseEnvelope() == nil ||
		b.GetDsseEnvelope().GetPayloadType() != DSSEPayloadType || len(b.GetDsseEnvelope().GetSignatures()) != 1 {
		return VerifiedRelease{}, ErrUnqualified
	}
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) != 1 || entries[0].GetInclusionProof() == nil ||
		entries[0].GetInclusionProof().GetCheckpoint() == nil {
		return VerifiedRelease{}, ErrUnqualified
	}
	identity, err := verify.NewShortCertificateIdentity(policy.value.ReleaseWorkflow.OIDCIssuer, "", policy.value.ReleaseWorkflow.CertificateIdentity, "")
	if err != nil {
		return VerifiedRelease{}, ErrUnqualified
	}
	v, err := verify.NewVerifier(trust, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return VerifiedRelease{}, ErrUnqualified
	}
	qualificationDigest := sha256.Sum256(qualificationJSON)
	result, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", qualificationDigest[:]), verify.WithCertificateIdentity(identity)))
	if err != nil || result == nil || result.Statement == nil || result.Signature == nil || result.Signature.Certificate == nil || len(result.VerifiedTimestamps) == 0 {
		return VerifiedRelease{}, ErrUnqualified
	}
	cert := result.Signature.Certificate
	if cert.SourceRepositoryURI != "https://github.com/"+policy.value.ReleaseWorkflow.Repository ||
		cert.SourceRepositoryDigest != policy.value.ReleaseWorkflow.SourceCommit {
		return VerifiedRelease{}, ErrUnqualified
	}
	for _, timestamp := range result.VerifiedTimestamps {
		if timestamp.Timestamp.After(now) {
			return VerifiedRelease{}, ErrUnqualified
		}
	}
	qualificationSHA := digest(qualificationJSON)
	reports, err := fixedStatement(b.GetDsseEnvelope().GetPayload(), policy.value, qualificationSHA, now)
	if err != nil {
		return VerifiedRelease{}, err
	}
	return VerifiedRelease{verified: true, bundleSHA256: expectedBundleSHA256, qualificationSHA256: qualificationSHA, hostReports: reports, ownerKeyID: policy.value.OwnerKeyID, policyRevision: policy.value.PolicyRevision}, nil
}

// VerifyReleasedReports authenticates every report referenced by the release
// statement, binds the protected report to qualification.json, and requires
// the four physical gate results across the two enforcement profiles. The
// separate installed-byte measurement and Machine-owned completed-run record
// are still mandatory before a protected launch can be authorized.
func VerifyReleasedReports(release VerifiedRelease, policy VerifiedPolicy, qualificationJSON []byte, envelopes [][]byte, now time.Time) error {
	if !validSHA(release.bundleSHA256) {
		return ErrUnqualified
	}
	return verifyReportSet(release, policy, qualificationJSON, envelopes, now)
}

// VerifyHostReportsForRelease is a producer preflight, not a release or launch
// authorization. It authenticates exactly one protected and one cooperative
// host envelope before the release workflow signs their digests in a bundle.
// Machine must independently verify that final bundle and local measurements.
func VerifyHostReportsForRelease(policy VerifiedPolicy, qualificationJSON, protectedEnvelope, cooperativeEnvelope []byte, now time.Time) (protectedSHA256, cooperativeSHA256 string, err error) {
	if !policy.verified || !policy.at.Equal(now) {
		return "", "", ErrUnqualified
	}
	protectedRaw, e1 := VerifyHostReport(protectedEnvelope, policy, now)
	cooperativeRaw, e2 := VerifyHostReport(cooperativeEnvelope, policy, now)
	if e1 != nil || e2 != nil {
		return "", "", ErrUnqualified
	}
	var protected, cooperative reportDocument
	if json.Unmarshal(protectedRaw, &protected) != nil || json.Unmarshal(cooperativeRaw, &cooperative) != nil ||
		protected.ProfileInForce != "managed-protected" || cooperative.ProfileInForce != "managed-cooperative" {
		return "", "", ErrUnqualified
	}
	protectedSHA256, cooperativeSHA256 = digest(protectedRaw), digest(cooperativeRaw)
	release := VerifiedRelease{
		verified: true, qualificationSHA256: digest(qualificationJSON),
		ownerKeyID: policy.value.OwnerKeyID, policyRevision: policy.value.PolicyRevision,
		hostReports: []reportReference{{URI: "preflight:protected", SHA256: protectedSHA256}, {URI: "preflight:cooperative", SHA256: cooperativeSHA256}},
	}
	if verifyReportSet(release, policy, qualificationJSON, [][]byte{protectedEnvelope, cooperativeEnvelope}, now) != nil {
		return "", "", ErrUnqualified
	}
	return protectedSHA256, cooperativeSHA256, nil
}

func verifyReportSet(release VerifiedRelease, policy VerifiedPolicy, qualificationJSON []byte, envelopes [][]byte, now time.Time) error {
	if !release.verified || !policy.verified || now.IsZero() || !policy.at.Equal(now) ||
		release.ownerKeyID != policy.value.OwnerKeyID || release.policyRevision != policy.value.PolicyRevision ||
		digest(qualificationJSON) != release.qualificationSHA256 || len(envelopes) != len(release.hostReports) {
		return ErrUnqualified
	}
	qualification, err := qualificationObject(qualificationJSON)
	if err != nil {
		return ErrUnqualified
	}
	var primaryDigest string
	if json.Unmarshal(qualification["conformance_report_sha256"], &primaryDigest) != nil {
		return ErrUnqualified
	}
	refByDigest := make(map[string]bool, len(release.hostReports))
	for _, ref := range release.hostReports {
		refByDigest[ref.SHA256] = true
	}
	seenReports := map[string]bool{}
	seenRuns := map[string]bool{}
	seenGates := map[string]bool{}
	var primary *reportDocument
	var common *reportDocument
	protected, cooperative := 0, 0
	for _, envelope := range envelopes {
		raw, err := VerifyHostReport(envelope, policy, now)
		if err != nil || !refByDigest[digest(raw)] || seenReports[digest(raw)] {
			return ErrUnqualified
		}
		seenReports[digest(raw)] = true
		var report reportDocument
		if json.Unmarshal(raw, &report) != nil || seenRuns[report.RunID] {
			return ErrUnqualified
		}
		seenRuns[report.RunID] = true
		if common == nil {
			common = &report
		} else if report.Adapter != common.Adapter || !reflect.DeepEqual(report.Launch, common.Launch) ||
			report.Harness != common.Harness || report.Runner != common.Runner ||
			report.Host.ID != common.Host.ID || report.Host.OS != common.Host.OS ||
			report.Host.OSVersion != common.Host.OSVersion || report.Host.Architecture != common.Host.Architecture || report.Host.Profile != common.Host.Profile ||
			report.SuiteRevision != common.SuiteRevision || !reflect.DeepEqual(report.Renders, common.Renders) ||
			report.CostBound != common.CostBound || !reflect.DeepEqual(report.EvaluationCells, common.EvaluationCells) {
			return ErrUnqualified
		}
		if report.ProfileInForce == "managed-protected" {
			protected++
			if digest(raw) == primaryDigest {
				candidate := report
				primary = &candidate
			}
		} else {
			cooperative++
		}
		for gate := range report.Gates {
			if seenGates[gate] {
				return ErrUnqualified
			}
			seenGates[gate] = true
		}
	}
	if len(seenReports) != len(refByDigest) || protected == 0 || cooperative == 0 || primary == nil ||
		len(seenGates) != 4 || !seenGates["T01"] || !seenGates["T02"] || !seenGates["T03"] || !seenGates["T21"] {
		return ErrUnqualified
	}
	if !qualificationMatchesReport(qualification, *primary) {
		return ErrUnqualified
	}
	return nil
}

func qualificationObject(raw []byte) (map[string]json.RawMessage, error) {
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, "schema_version", "adapter", "launch", "harness", "runner", "soul_start", "host", "profile_in_force", "renders", "cost_bound", "conformance", "recorded_at", "evaluation_cells") {
		return nil, ErrUnqualified
	}
	var conformance map[string]json.RawMessage
	if json.Unmarshal(fields["conformance"], &conformance) != nil || !hasFields(conformance, "suite_revision", "run_id", "outcome", "report", "checks") {
		return nil, ErrUnqualified
	}
	var ref reportReference
	if json.Unmarshal(conformance["report"], &ref) != nil || !reportRef(ref) {
		return nil, ErrUnqualified
	}
	fields["conformance_report_sha256"] = json.RawMessage(`"` + ref.SHA256 + `"`)
	for _, name := range []string{"suite_revision", "run_id", "outcome", "checks"} {
		fields["conformance_"+name] = conformance[name]
	}
	return fields, nil
}

func qualificationMatchesReport(qualification map[string]json.RawMessage, report reportDocument) bool {
	encoded, err := json.Marshal(report)
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	for _, name := range []string{"schema_version", "adapter", "launch", "harness", "runner", "soul_start", "host", "profile_in_force", "renders", "cost_bound", "recorded_at", "evaluation_cells"} {
		if !sameJSON(qualification[name], fields[name]) {
			return false
		}
	}
	for _, name := range []string{"suite_revision", "run_id", "outcome", "checks"} {
		if !sameJSON(qualification["conformance_"+name], fields[name]) {
			return false
		}
	}
	return true
}

func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
