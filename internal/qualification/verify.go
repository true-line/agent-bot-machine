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
	"strings"
	"time"
)

const (
	HostPurpose      = "agent-bot/qualification-host-report/v1"
	PolicyPurpose    = "agent-bot/qualification-policy/v1"
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
	EvidenceSigners []struct {
		ID                     string `json:"id"`
		HostID                 string `json:"host_id"`
		Algorithm              string `json:"algorithm"`
		PublicKeySPKIDERBase64 string `json:"public_key_spki_der_base64"`
	} `json:"evidence_signers"`
	RevocationSnapshot struct {
		UpdatedAt                 string   `json:"updated_at"`
		RevokedAttestationSHA256  []string `json:"revoked_attestation_sha256"`
		RevokedEvidenceSignerIDs  []string `json:"revoked_evidence_signer_ids"`
		RevokedReleaseWorkflowIDs []string `json:"revoked_release_workflow_ids"`
	} `json:"revocation_snapshot"`
	MaxRevocationAgeSeconds int `json:"max_revocation_age_seconds"`
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
		var values []any
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
	if expected == PolicyPurpose {
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
	if json.Unmarshal(raw, &e) != nil || e.SchemaVersion != 1 || e.Purpose != expected {
		return Envelope{}, ErrUnqualified
	}
	return e, nil
}

func preimage(purpose string, raw []byte) []byte {
	b := make([]byte, 0, len(purpose)+1+len(raw))
	b = append(b, purpose...)
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
func VerifyOwnerPolicy(envelope []byte, ownerKeyID string, root ed25519.PublicKey, highest uint64, acceptedDigest string, now time.Time) (Policy, error) {
	var zero Policy
	if len(root) != ed25519.PublicKeySize || now.IsZero() {
		return zero, ErrUnqualified
	}
	e, err := parseEnvelope(envelope, PolicyPurpose)
	if err != nil || e.OwnerKeyID != ownerKeyID {
		return zero, ErrUnqualified
	}
	raw, err := decode(e.PolicyBase64URL, MaxReportBytes)
	if err != nil || digest(raw) != e.PolicySHA256 {
		return zero, ErrUnqualified
	}
	if _, err = canonicalBytes(raw, MaxReportBytes); err != nil {
		return zero, err
	}
	sig, err := decode(e.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(root, preimage(PolicyPurpose, raw), sig) {
		return zero, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&zero) != nil || zero.Contract != "control/v1" || zero.Kind != "qualification-trust-policy" || zero.OwnerKeyID != ownerKeyID || zero.PolicyRevision < highest || zero.PolicyRevision == 0 || zero.MaxRevocationAgeSeconds != 3600 {
		return Policy{}, ErrUnqualified
	}
	if highest > 0 && zero.PolicyRevision == highest && digest(raw) != acceptedDigest {
		return Policy{}, ErrUnqualified
	}
	issued, e1 := parseTime(zero.IssuedAt)
	expires, e2 := parseTime(zero.ExpiresAt)
	snapshot, e3 := parseTime(zero.RevocationSnapshot.UpdatedAt)
	if e1 != nil || e2 != nil || e3 != nil || issued.After(now) || !expires.After(now) || snapshot.After(now) || now.Sub(snapshot) > MaxRevocationAge || snapshot.Before(issued) {
		return Policy{}, ErrUnqualified
	}
	workflow := zero.ReleaseWorkflow
	if workflow.Repository != "true-line/soul-adapters" || workflow.ID == "" || !strings.HasPrefix(workflow.WorkflowPath, ".github/workflows/") || !strings.HasSuffix(workflow.WorkflowPath, ".yml") && !strings.HasSuffix(workflow.WorkflowPath, ".yaml") || !validHex(workflow.SourceCommit, 40) || !httpsURL(workflow.OIDCIssuer) || !httpsURL(workflow.CertificateIdentity) || !validSHA(workflow.TrustRootSHA256) || len(zero.EvidenceSigners) == 0 {
		return Policy{}, ErrUnqualified
	}
	seen := map[string]bool{}
	for _, signer := range zero.EvidenceSigners {
		if signer.ID == "" || signer.HostID == "" || signer.Algorithm != "ES256" || seen[signer.ID] {
			return Policy{}, ErrUnqualified
		}
		seen[signer.ID] = true
		der, err := base64.StdEncoding.Strict().DecodeString(signer.PublicKeySPKIDERBase64)
		if err != nil || base64.StdEncoding.EncodeToString(der) != signer.PublicKeySPKIDERBase64 {
			return Policy{}, ErrUnqualified
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		key, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || key.Curve.Params().Name != "P-256" {
			return Policy{}, ErrUnqualified
		}
	}
	return zero, nil
}

func validHex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

// VerifyHostReport checks exact canonical report bytes and its designated
// Secure Enclave signature under the already verified owner policy.
func VerifyHostReport(envelope []byte, policy Policy) ([]byte, error) {
	e, err := parseEnvelope(envelope, HostPurpose)
	if err != nil {
		return nil, err
	}
	raw, err := decode(e.ReportBase64URL, MaxReportBytes)
	if err != nil || digest(raw) != e.ReportSHA256 {
		return nil, ErrUnqualified
	}
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil {
		return nil, err
	}
	required := []string{"adapter", "checks", "cost_bound", "evaluation_cells", "gates", "harness", "host", "launch", "outcome", "profile_in_force", "recorded_at", "renders", "run_id", "runner", "schema_version", "soul_start", "suite_revision"}
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
	if json.Unmarshal(raw, &report) != nil || report.SchemaVersion != 1 || report.Outcome != "pass" || report.RunID == "" || len(report.SuiteRevision) != 40 || report.Runner.BinaryPath == "" || !validSHA(report.Runner.BinarySHA256) || report.SoulStart.Initiator != "hq" || report.SoulStart.HQLaunchReceipt.URI == "" || !validSHA(report.SoulStart.HQLaunchReceipt.SHA256) || report.SoulStart.MachineObservation.URI == "" || !validSHA(report.SoulStart.MachineObservation.SHA256) {
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
	for _, revoked := range policy.RevocationSnapshot.RevokedEvidenceSignerIDs {
		if revoked == e.SignerID {
			return nil, ErrUnqualified
		}
	}
	var key *ecdsa.PublicKey
	for _, signer := range policy.EvidenceSigners {
		if signer.ID != e.SignerID || signer.HostID != e.HostID || signer.Algorithm != "ES256" {
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
	sig, err := decode(e.SignatureBase64URL, 64)
	if err != nil || len(sig) != 64 {
		return nil, ErrUnqualified
	}
	message := sha256.Sum256(preimage(HostPurpose, raw))
	if !ecdsa.Verify(key, message[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, ErrUnqualified
	}
	return raw, nil
}

func validSHA(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return err == nil && strings.ToLower(s) == s
}
