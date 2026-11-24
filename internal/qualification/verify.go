// Package qualification verifies the offline owner-policy and designated-host
// signature boundary. Production launch stays closed until the release bundle,
// installed inputs and physical run are also verified.
package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	HostPurpose      = "agent-bot/qualification-host-report/v1"
	HostPurposeV2    = "agent-bot/qualification-host-report/v2"
	HostPurposeV3    = "agent-bot/qualification-host-report/v3"
	HostPurposeV4    = "agent-bot/qualification-host-report/v4"
	PolicyPurpose    = "agent-bot/qualification-policy/v1"
	PolicyPurposeV2  = "agent-bot/qualification-policy/v2"
	PolicyPurposeV3  = "agent-bot/qualification-policy/v3"
	MaxRevocationAge = 3600 * time.Second
	MaxReportBytes   = 1 << 20
)

var ErrUnqualified = errors.New("authenticated adapter qualification unavailable")

type Envelope struct {
	SchemaVersion      int    `json:"schema_version"`
	Purpose            string `json:"purpose"`
	OwnerKeyID         string `json:"owner_key_id,omitempty"`
	PolicySHA256       string `json:"policy_sha256,omitempty"`
	PolicyBase64URL    string `json:"policy_base64url,omitempty"`
	HostID             string `json:"host_id,omitempty"`
	SignerID           string `json:"signer_id,omitempty"`
	ReportSHA256       string `json:"report_sha256,omitempty"`
	ReportBase64URL    string `json:"report_base64url,omitempty"`
	SignatureBase64URL string `json:"signature_base64url"`
}

type Policy struct {
	Contract        string `json:"contract"`
	Kind            string `json:"kind"`
	PolicyRevision  uint64 `json:"policy_revision"`
	OwnerKeyID      string `json:"owner_key_id"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
	ReleaseWorkflow struct {
		ID                  string `json:"id"`
		Repository          string `json:"repository"`
		WorkflowPath        string `json:"workflow_path"`
		SourceCommit        string `json:"source_commit"`
		OIDCIssuer          string `json:"oidc_issuer"`
		CertificateIdentity string `json:"certificate_identity"`
		TrustRootSHA256     string `json:"trust_root_sha256"`
	} `json:"release_workflow"`
	SoulsBuildWorkflow *struct {
		ID                   string `json:"id"`
		Repository           string `json:"repository"`
		WorkflowPath         string `json:"workflow_path"`
		SourceCommit         string `json:"source_commit"`
		SourceTree           string `json:"source_tree"`
		OIDCIssuer           string `json:"oidc_issuer"`
		CertificateIdentity  string `json:"certificate_identity"`
		TrustRootSHA256      string `json:"trust_root_sha256"`
		BuilderSHA256        string `json:"builder_sha256"`
		ToolchainSHA256      string `json:"toolchain_sha256"`
		ReceiptPredicateType string `json:"receipt_predicate_type"`
		BundleMediaType      string `json:"bundle_media_type"`
		DSSEPayloadType      string `json:"dsse_payload_type"`
	} `json:"souls_build_workflow,omitempty"`
	FrozenSoulBuildWorkflow            *FrozenSoulBuildWorkflow `json:"frozen_soul_build_workflow,omitempty"`
	FrozenSoulMapping                  *FrozenSoulMapping       `json:"frozen_soul_mapping,omitempty"`
	FrozenSoulReleaseProvenanceEnabled *bool                    `json:"frozen_soul_release_provenance_enabled,omitempty"`
	EvidenceSigners                    []struct {
		ID                     string `json:"id"`
		HostID                 string `json:"host_id"`
		Algorithm              string `json:"algorithm"`
		PublicKeySPKIDERBase64 string `json:"public_key_spki_der_base64"`
	} `json:"evidence_signers"`
	RevocationSnapshot struct {
		UpdatedAt                         string   `json:"updated_at"`
		RevokedAttestationSHA256          []string `json:"revoked_attestation_sha256"`
		RevokedEvidenceSignerIDs          []string `json:"revoked_evidence_signer_ids"`
		RevokedReleaseWorkflowIDs         []string `json:"revoked_release_workflow_ids"`
		RevokedSoulsBuildWorkflowIDs      []string `json:"revoked_souls_build_workflow_ids,omitempty"`
		RevokedSoulsBuildReceiptSHA256    []string `json:"revoked_souls_build_receipt_sha256,omitempty"`
		RevokedFrozenSoulBuildWorkflowIDs []string `json:"revoked_frozen_soul_build_workflow_ids,omitempty"`
		RevokedFrozenSoulReceiptSHA256    []string `json:"revoked_frozen_soul_receipt_sha256,omitempty"`
		RevokedFrozenSoulArtifactSHA256   []string `json:"revoked_frozen_soul_artifact_sha256,omitempty"`
	} `json:"revocation_snapshot"`
	MaxRevocationAgeSeconds int `json:"max_revocation_age_seconds"`
}

type FrozenSoulBuildWorkflow struct {
	ID                   string `json:"id"`
	Repository           string `json:"repository"`
	WorkflowPath         string `json:"workflow_path"`
	SourceCommit         string `json:"source_commit"`
	SourceTree           string `json:"source_tree"`
	OIDCIssuer           string `json:"oidc_issuer"`
	CertificateIdentity  string `json:"certificate_identity"`
	TrustRootSHA256      string `json:"trust_root_sha256"`
	BuilderSHA256        string `json:"builder_sha256"`
	ToolchainSHA256      string `json:"toolchain_sha256"`
	ReceiptPredicateType string `json:"receipt_predicate_type"`
	BundleMediaType      string `json:"bundle_media_type"`
	DSSEPayloadType      string `json:"dsse_payload_type"`
	ArtifactFormat       string `json:"artifact_format"`
	SubjectNameTemplate  string `json:"subject_name_template"`
	RekorEntryKind       string `json:"rekor_entry_kind"`
	RekorEntryVersion    string `json:"rekor_entry_version"`
	TransparencyLogID    string `json:"transparency_log_id"`
	Template             struct {
		Repository   string `json:"repository"`
		SourceCommit string `json:"source_commit"`
		SourceTree   string `json:"source_tree"`
		Path         string `json:"path"`
		TemplateTree string `json:"template_tree"`
	} `json:"template"`
}

type FrozenSoulMapping struct {
	SoulID                  string `json:"soul_id"`
	ArtifactSHA256          string `json:"artifact_sha256"`
	ReceiptSHA256           string `json:"receipt_sha256,omitempty"`
	ClaimedDefinitionDigest string `json:"claimed_definition_digest"`
	DefinitionMeasurement   string `json:"definition_measurement"`
}

// VerifiedPolicy can only be obtained by verifying an owner signature against
// a root supplied by the reviewed Machine release.
type VerifiedPolicy struct {
	value         Policy
	verified      bool
	at            time.Time
	version       int
	payloadSHA256 string
}

// RevisionDigest is the accepted rollback checkpoint to persist atomically
// before a protected launch. Both policy versions share this revision space.
func (p VerifiedPolicy) RevisionDigest() (uint64, string, error) {
	if !p.verified || p.value.PolicyRevision == 0 || !validSHA(p.payloadSHA256) {
		return 0, "", ErrUnqualified
	}
	return p.value.PolicyRevision, p.payloadSHA256, nil
}

func (p VerifiedPolicy) SoulsSourceTree() string {
	if !p.verified || p.version < 2 || p.value.SoulsBuildWorkflow == nil {
		return ""
	}
	return p.value.SoulsBuildWorkflow.SourceTree
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func strictObject(raw []byte, max int) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > max || !json.Valid(raw) {
		return nil, ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readValue(d)
	if err != nil {
		return nil, ErrUnqualified
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrUnqualified
	}
	obj, ok := v.(map[string]json.RawMessage)
	if !ok {
		return nil, ErrUnqualified
	}
	return obj, nil
}

func readValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]json.RawMessage{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrUnqualified
			}
			if _, exists := seen[name]; exists {
				return nil, ErrUnqualified
			}
			value, err := readValue(d)
			if err != nil {
				return nil, err
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			seen[name] = encoded
		}
		if close, err := d.Token(); err != nil || close != json.Delim('}') {
			return nil, ErrUnqualified
		}
		return seen, nil
	case json.Delim('['):
		values := []any{}
		for d.More() {
			value, err := readValue(d)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if close, err := d.Token(); err != nil || close != json.Delim(']') {
			return nil, ErrUnqualified
		}
		return values, nil
	default:
		if n, ok := t.(json.Number); ok && (strings.ContainsAny(string(n), ".eE") || string(n) == "-0") {
			return nil, ErrUnqualified
		}
		return t, nil
	}
}

// canonicalBytes accepts the implemented ASCII-only JCS subset. The fixed
// report and policy keys are ASCII; rejecting other bytes is fail closed.
func canonicalBytes(raw []byte, max int) (map[string]json.RawMessage, error) {
	if !isASCII(raw) {
		return nil, ErrUnqualified
	}
	fields, err := strictObject(raw, max)
	if err != nil {
		return nil, err
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, ErrUnqualified
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(value) != nil || !bytes.Equal(bytes.TrimSuffix(b.Bytes(), []byte("\n")), raw) {
		return nil, ErrUnqualified
	}
	return fields, nil
}

func isASCII(raw []byte) bool {
	for _, b := range raw {
		if b >= 0x80 {
			return false
		}
	}
	return true
}

func decode(s string, max int) ([]byte, error) {
	if strings.Contains(s, "=") {
		return nil, ErrUnqualified
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrUnqualified
	}
	return b, nil
}

func parseEnvelope(raw []byte, expected string) (Envelope, error) {
	fields, err := strictObject(raw, MaxReportBytes*2)
	if err != nil {
		return Envelope{}, err
	}
	keys := []string{"schema_version", "purpose", "signature_base64url"}
	if expected == PolicyPurpose || expected == PolicyPurposeV2 || expected == PolicyPurposeV3 {
		keys = append(keys, "owner_key_id", "policy_sha256", "policy_base64url")
	} else {
		keys = append(keys, "host_id", "signer_id", "report_sha256", "report_base64url")
	}
	if len(fields) != len(keys) {
		return Envelope{}, ErrUnqualified
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return Envelope{}, ErrUnqualified
		}
	}
	var e Envelope
	version := 1
	if expected == HostPurposeV2 || expected == PolicyPurposeV2 {
		version = 2
	} else if expected == HostPurposeV3 || expected == PolicyPurposeV3 {
		version = 3
	} else if expected == HostPurposeV4 {
		version = 4
	}
	if json.Unmarshal(raw, &e) != nil || e.SchemaVersion != version || e.Purpose != expected {
		return Envelope{}, ErrUnqualified
	}
	return e, nil
}

func preimage(purpose string, raw []byte) []byte {
	b := []byte(purpose)
	b = append(b, 0)
	return append(b, raw...)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Location() == nil {
		return time.Time{}, ErrUnqualified
	}
	return t, nil
}

// VerifyOwnerPolicy checks exact signed bytes against a release-pinned root.
// highest and acceptedDigest come from the protected persisted policy state.
// Equal revisions may be reused only with exactly the previously accepted bytes.
func VerifyOwnerPolicy(envelope []byte, ownerKeyID string, root ed25519.PublicKey, highest uint64, acceptedDigest string, now time.Time) (VerifiedPolicy, error) {
	return verifyOwnerPolicyVersion(envelope, ownerKeyID, root, highest, acceptedDigest, now, 1)
}

// VerifyOwnerPolicyV2 authenticates the distinct bridge-aware owner policy,
// including its separate Souls build root and approved source tree.
func VerifyOwnerPolicyV2(envelope []byte, ownerKeyID string, root ed25519.PublicKey, highest uint64, acceptedDigest string, now time.Time) (VerifiedPolicy, error) {
	return verifyOwnerPolicyVersion(envelope, ownerKeyID, root, highest, acceptedDigest, now, 2)
}

// VerifyOwnerPolicyV3 authenticates the separate frozen .soul workflow and
// owner-approved exact artifact/definition mapping. It does not authenticate
// a build receipt or grant launch authority by itself.
func VerifyOwnerPolicyV3(envelope []byte, ownerKeyID string, root ed25519.PublicKey, highest uint64, acceptedDigest string, now time.Time) (VerifiedPolicy, error) {
	return verifyOwnerPolicyVersion(envelope, ownerKeyID, root, highest, acceptedDigest, now, 3)
}

func verifyOwnerPolicyVersion(envelope []byte, ownerKeyID string, root ed25519.PublicKey, highest uint64, acceptedDigest string, now time.Time, version int) (VerifiedPolicy, error) {
	var zero Policy
	if len(root) != ed25519.PublicKeySize || now.IsZero() ||
		(highest == 0 && acceptedDigest != "") || (highest > 0 && !validSHA(acceptedDigest)) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	purpose := PolicyPurpose
	if version == 2 {
		purpose = PolicyPurposeV2
	} else if version == 3 {
		purpose = PolicyPurposeV3
	}
	e, err := parseEnvelope(envelope, purpose)
	if err != nil || e.OwnerKeyID != ownerKeyID {
		return VerifiedPolicy{}, ErrUnqualified
	}
	raw, err := decode(e.PolicyBase64URL, MaxReportBytes)
	if err != nil || digest(raw) != e.PolicySHA256 {
		return VerifiedPolicy{}, ErrUnqualified
	}
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	policyFields := []string{"contract", "kind", "policy_revision", "owner_key_id", "issued_at", "expires_at", "release_workflow", "evidence_signers", "revocation_snapshot", "max_revocation_age_seconds"}
	if version >= 2 {
		policyFields = append(policyFields, "souls_build_workflow")
	}
	var frozenProvenanceEnabled bool
	if version == 3 {
		flag := fields["frozen_soul_release_provenance_enabled"]
		if !bytes.Equal(flag, []byte("true")) && !bytes.Equal(flag, []byte("false")) {
			return VerifiedPolicy{}, ErrUnqualified
		}
		frozenProvenanceEnabled = bytes.Equal(flag, []byte("true"))
		policyFields = append(policyFields, "frozen_soul_release_provenance_enabled", "frozen_soul_mapping")
		if frozenProvenanceEnabled {
			policyFields = append(policyFields, "frozen_soul_build_workflow")
		}
	}
	if !hasFields(fields, policyFields...) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	var snapshotFields map[string]json.RawMessage
	snapshotNames := []string{"updated_at", "revoked_attestation_sha256", "revoked_evidence_signer_ids", "revoked_release_workflow_ids"}
	if version >= 2 {
		snapshotNames = append(snapshotNames, "revoked_souls_build_workflow_ids", "revoked_souls_build_receipt_sha256")
	}
	if version == 3 {
		snapshotNames = append(snapshotNames, "revoked_frozen_soul_artifact_sha256")
		if frozenProvenanceEnabled {
			snapshotNames = append(snapshotNames, "revoked_frozen_soul_build_workflow_ids", "revoked_frozen_soul_receipt_sha256")
		}
		mapping, err := strictObject(fields["frozen_soul_mapping"], MaxReportBytes)
		if err != nil {
			return VerifiedPolicy{}, ErrUnqualified
		}
		mappingNames := []string{"soul_id", "artifact_sha256", "claimed_definition_digest", "definition_measurement"}
		if frozenProvenanceEnabled {
			mappingNames = append(mappingNames, "receipt_sha256")
		}
		if !hasFields(mapping, mappingNames...) {
			return VerifiedPolicy{}, ErrUnqualified
		}
	}
	if json.Unmarshal(fields["revocation_snapshot"], &snapshotFields) != nil || !hasFields(snapshotFields, snapshotNames...) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	sig, err := decode(e.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(root, preimage(purpose, raw), sig) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&zero) != nil || zero.Contract != "control/v"+strconv.Itoa(version) || zero.Kind != "qualification-trust-policy" || zero.OwnerKeyID != ownerKeyID || zero.PolicyRevision < highest || zero.PolicyRevision == 0 || zero.MaxRevocationAgeSeconds != 3600 {
		return VerifiedPolicy{}, ErrUnqualified
	}
	if highest > 0 && zero.PolicyRevision == highest && digest(raw) != acceptedDigest {
		return VerifiedPolicy{}, ErrUnqualified
	}
	issued, e1 := parseTime(zero.IssuedAt)
	expires, e2 := parseTime(zero.ExpiresAt)
	snapshot, e3 := parseTime(zero.RevocationSnapshot.UpdatedAt)
	if e1 != nil || e2 != nil || e3 != nil || issued.After(now) || !expires.After(now) || snapshot.After(now) || now.Sub(snapshot) > MaxRevocationAge || snapshot.Before(issued) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	workflow := zero.ReleaseWorkflow
	if workflow.Repository != "true-line/soul-adapters" || workflow.ID == "" || !strings.HasPrefix(workflow.WorkflowPath, ".github/workflows/") || !strings.HasSuffix(workflow.WorkflowPath, ".yml") && !strings.HasSuffix(workflow.WorkflowPath, ".yaml") || !validHex(workflow.SourceCommit, 40) || !httpsURL(workflow.OIDCIssuer) || !httpsURL(workflow.CertificateIdentity) || !validSHA(workflow.TrustRootSHA256) || len(zero.EvidenceSigners) == 0 {
		return VerifiedPolicy{}, ErrUnqualified
	}
	seen := map[string]bool{}
	for _, signer := range zero.EvidenceSigners {
		if signer.ID == "" || signer.HostID == "" || signer.Algorithm != "ES256" || seen[signer.ID] {
			return VerifiedPolicy{}, ErrUnqualified
		}
		seen[signer.ID] = true
		der, err := base64.StdEncoding.Strict().DecodeString(signer.PublicKeySPKIDERBase64)
		if err != nil || base64.StdEncoding.EncodeToString(der) != signer.PublicKeySPKIDERBase64 {
			return VerifiedPolicy{}, ErrUnqualified
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		key, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || key.Curve.Params().Name != "P-256" {
			return VerifiedPolicy{}, ErrUnqualified
		}
	}
	for _, revoked := range zero.RevocationSnapshot.RevokedReleaseWorkflowIDs {
		if revoked == workflow.ID {
			return VerifiedPolicy{}, ErrUnqualified
		}
	}
	if version >= 2 {
		build := zero.SoulsBuildWorkflow
		if build == nil || build.ID == "" || build.Repository != "true-line/agent-bot-souls" ||
			!validWorkflowPath(build.WorkflowPath) || !validHex(build.SourceCommit, 40) || !validHex(build.SourceTree, 40) ||
			!httpsURL(build.OIDCIssuer) || !httpsURL(build.CertificateIdentity) ||
			!validSHA(build.TrustRootSHA256) || !validSHA(build.BuilderSHA256) || !validSHA(build.ToolchainSHA256) ||
			build.ReceiptPredicateType != "https://true-line.ai/soul-contracts/adapter/v2/souls-build" ||
			build.BundleMediaType != bundleMediaType || build.DSSEPayloadType != DSSEPayloadType {
			return VerifiedPolicy{}, ErrUnqualified
		}
		for _, revoked := range zero.RevocationSnapshot.RevokedSoulsBuildWorkflowIDs {
			if revoked == build.ID {
				return VerifiedPolicy{}, ErrUnqualified
			}
		}
		if !validRevocationLists(zero) {
			return VerifiedPolicy{}, ErrUnqualified
		}
	}
	if version == 3 && (zero.FrozenSoulReleaseProvenanceEnabled == nil || *zero.FrozenSoulReleaseProvenanceEnabled != frozenProvenanceEnabled || !validFrozenSoulPolicy(zero)) {
		return VerifiedPolicy{}, ErrUnqualified
	}
	return VerifiedPolicy{value: zero, verified: true, at: now, version: version, payloadSHA256: digest(raw)}, nil
}

func validHex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validWorkflowPath(value string) bool {
	if !strings.HasPrefix(value, ".github/workflows/") {
		return false
	}
	name := strings.TrimPrefix(value, ".github/workflows/")
	if name == "" || strings.Contains(name, "..") || !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
		return false
	}
	for _, c := range name {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validRevocationLists(policy Policy) bool {
	digests := [][]string{policy.RevocationSnapshot.RevokedAttestationSHA256, policy.RevocationSnapshot.RevokedSoulsBuildReceiptSHA256, policy.RevocationSnapshot.RevokedFrozenSoulReceiptSHA256}
	ids := [][]string{policy.RevocationSnapshot.RevokedEvidenceSignerIDs, policy.RevocationSnapshot.RevokedReleaseWorkflowIDs, policy.RevocationSnapshot.RevokedSoulsBuildWorkflowIDs, policy.RevocationSnapshot.RevokedFrozenSoulBuildWorkflowIDs}
	for _, list := range digests {
		seen := map[string]bool{}
		for _, item := range list {
			if !validSHA(item) || seen[item] {
				return false
			}
			seen[item] = true
		}
	}
	for _, list := range ids {
		seen := map[string]bool{}
		for _, item := range list {
			if !reportID.MatchString(item) || seen[item] {
				return false
			}
			seen[item] = true
		}
	}
	return true
}

func hasFields(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(value, []byte("null")) {
			return false
		}
	}
	return true
}
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// VerifyHostReport checks exact canonical report bytes and its designated
// Secure Enclave signature under the already verified owner policy.
func VerifyHostReport(envelope []byte, verified VerifiedPolicy, now time.Time) ([]byte, error) {
	return verifyHostReport(envelope, verified, now, HostPurpose, 1, reportShape)
}

// VerifyHostReportV2 authenticates the distinct bridge-aware protected report.
// It validates the signed claims; a live Machine observation and release
// attestation are still required before a protected launch.
func VerifyHostReportV2(envelope []byte, verified VerifiedPolicy, now time.Time) ([]byte, error) {
	if verified.version != 2 {
		return nil, ErrUnqualified
	}
	return verifyHostReport(envelope, verified, now, HostPurposeV2, 2, reportShapeV2)
}

// VerifyHostReportV3 authenticates a measured protected or cooperative host
// report. It does not resolve one-use records, installed inputs, or the
// release attestation and therefore cannot authorize launch by itself.
func VerifyHostReportV3(envelope []byte, verified VerifiedPolicy, now time.Time) ([]byte, error) {
	if verified.version != 3 {
		return nil, ErrUnqualified
	}
	return verifyHostReport(envelope, verified, now, HostPurposeV3, 3, reportShapeV3)
}

// VerifyHostReportV4 authenticates the exact successor report and its
// owner-designated host signer. Physical evidence and release refs still need
// independent offline verification before qualification.
func VerifyHostReportV4(envelope []byte, verified VerifiedPolicy, now time.Time) ([]byte, error) {
	if verified.version != 3 {
		return nil, ErrUnqualified
	}
	return verifyHostReport(envelope, verified, now, HostPurposeV4, 4, reportShapeV4)
}

func verifyHostReport(envelope []byte, verified VerifiedPolicy, now time.Time, purpose string, version int, shape func([]byte) error) ([]byte, error) {
	if !verified.verified || !verified.at.Equal(now) || now.IsZero() {
		return nil, ErrUnqualified
	}
	policy := verified.value
	e, err := parseEnvelope(envelope, purpose)
	if err != nil {
		return nil, err
	}
	raw, err := decode(e.ReportBase64URL, MaxReportBytes)
	if err != nil || digest(raw) != e.ReportSHA256 {
		return nil, ErrUnqualified
	}
	var fields map[string]json.RawMessage
	if version == 4 {
		fields, err = canonicalObjectV4(raw, MaxReportBytes)
	} else {
		fields, err = canonicalBytes(raw, MaxReportBytes)
	}
	if err != nil {
		return nil, err
	}
	if err := shape(raw); err != nil {
		return nil, err
	}
	required := []string{"adapter", "checks", "cost_bound", "evaluation_cells", "gates", "harness", "host", "launch", "outcome", "profile_in_force", "recorded_at", "renders", "run_id", "runner", "schema_version", "soul_start", "suite_revision"}
	if version == 2 {
		required = append(required, "bridge")
	} else if version == 3 || version == 4 {
		required = append(required, "measurement_binding", "run_evidence")
		if _, protected := fields["bridge"]; protected {
			required = append(required, "bridge")
		}
	}
	if len(fields) != len(required) {
		return nil, ErrUnqualified
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, ErrUnqualified
		}
	}
	var report struct {
		SchemaVersion int    `json:"schema_version"`
		Outcome       string `json:"outcome"`
		Profile       string `json:"profile_in_force"`
		RunID         string `json:"run_id"`
		RecordedAt    string `json:"recorded_at"`
		SuiteRevision string `json:"suite_revision"`
		Runner        struct {
			BinaryPath   string `json:"binary_path"`
			BinarySHA256 string `json:"binary_sha256"`
		} `json:"runner"`
		SoulStart struct {
			Initiator       string `json:"initiator"`
			HQLaunchReceipt struct {
				URI    string `json:"uri"`
				SHA256 string `json:"sha256"`
			} `json:"hq_launch_receipt"`
			MachineObservation struct {
				URI    string `json:"uri"`
				SHA256 string `json:"sha256"`
			} `json:"machine_observation"`
		} `json:"soul_start"`
		Checks map[string]struct {
			Outcome string `json:"outcome"`
		} `json:"checks"`
		Gates map[string]struct {
			Outcome string `json:"outcome"`
		} `json:"gates"`
	}
	if json.Unmarshal(raw, &report) != nil || report.SchemaVersion != version || report.Outcome != "pass" || report.RunID == "" || len(report.SuiteRevision) != 40 || report.Runner.BinaryPath == "" || !validSHA(report.Runner.BinarySHA256) || report.SoulStart.Initiator != "hq" || report.SoulStart.HQLaunchReceipt.URI == "" || !validSHA(report.SoulStart.HQLaunchReceipt.SHA256) || report.SoulStart.MachineObservation.URI == "" || !validSHA(report.SoulStart.MachineObservation.SHA256) {
		return nil, ErrUnqualified
	}
	recorded, err := parseTime(report.RecordedAt)
	if err != nil || recorded.After(now) {
		return nil, ErrUnqualified
	}
	if report.Profile != "managed-protected" && report.Profile != "managed-cooperative" {
		return nil, ErrUnqualified
	}
	if len(report.Gates) == 0 || len(report.Gates) > 3 {
		return nil, ErrUnqualified
	}
	for name, gate := range report.Gates {
		if gate.Outcome != "pass" || (name != "T01" && name != "T02" && name != "T03" && name != "T21") || (report.Profile == "managed-protected" && name == "T21") || (report.Profile == "managed-cooperative" && name != "T21") {
			return nil, ErrUnqualified
		}
	}
	if report.Profile == "managed-protected" && (len(report.Gates) != 3 || report.Gates["T01"].Outcome != "pass" || report.Gates["T02"].Outcome != "pass" || report.Gates["T03"].Outcome != "pass") {
		return nil, ErrUnqualified
	}
	if report.Profile == "managed-cooperative" && len(report.Gates) != 1 {
		return nil, ErrUnqualified
	}
	if report.Profile == "managed-protected" {
		for _, name := range []string{"egress", "credentials", "state_redirect", "safe_interrupt_resume", "session_reuse", "cost_bound", "render_coverage"} {
			if report.Checks[name].Outcome != "pass" {
				return nil, ErrUnqualified
			}
		}
	}
	var host struct {
		ID string `json:"id"`
		OS string `json:"os"`
	}
	if json.Unmarshal(fields["host"], &host) != nil || host.ID != e.HostID || host.OS != "darwin" {
		return nil, ErrUnqualified
	}
	key, err := designatedHostSigner(policy, e.HostID, e.SignerID)
	if err != nil {
		return nil, ErrUnqualified
	}
	sig, err := decode(e.SignatureBase64URL, 64)
	if err != nil || len(sig) != 64 {
		return nil, ErrUnqualified
	}
	message := sha256.Sum256(preimage(purpose, raw))
	if !ecdsa.Verify(key, message[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, ErrUnqualified
	}
	return raw, nil
}

// CheckDesignatedHostSignerV3 is the signing-side owner-policy gate. The
// caller must verify the owner policy for the same instant and still prove a
// completed physical run before asking keyd to sign.
func CheckDesignatedHostSignerV3(verified VerifiedPolicy, hostID, signerID string, at time.Time) error {
	if !verified.verified || verified.version != 3 || at.IsZero() || !verified.at.Equal(at) {
		return ErrUnqualified
	}
	_, err := designatedHostSigner(verified.value, hostID, signerID)
	return err
}

// The v4 report continues to use the verified owner-signed v3 policy. A
// purpose upgrade never changes the designated host or signer trust anchor.
func CheckDesignatedHostSignerV4(verified VerifiedPolicy, hostID, signerID string, at time.Time) error {
	return CheckDesignatedHostSignerV3(verified, hostID, signerID, at)
}

func designatedHostSigner(policy Policy, hostID, signerID string) (*ecdsa.PublicKey, error) {
	for _, revoked := range policy.RevocationSnapshot.RevokedEvidenceSignerIDs {
		if revoked == signerID {
			return nil, ErrUnqualified
		}
	}
	var key *ecdsa.PublicKey
	for _, signer := range policy.EvidenceSigners {
		if signer.ID != signerID || signer.HostID != hostID || signer.Algorithm != "ES256" {
			continue
		}
		der, err := base64.StdEncoding.Strict().DecodeString(signer.PublicKeySPKIDERBase64)
		if err != nil || base64.StdEncoding.EncodeToString(der) != signer.PublicKeySPKIDERBase64 {
			return nil, ErrUnqualified
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, ErrUnqualified
		}
		p, ok := parsed.(*ecdsa.PublicKey)
		if !ok || p.Curve.Params().Name != "P-256" || key != nil {
			return nil, ErrUnqualified
		}
		key = p
	}
	if key == nil {
		return nil, ErrUnqualified
	}
	return key, nil
}

func validSHA(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return err == nil && strings.ToLower(s) == s
}
