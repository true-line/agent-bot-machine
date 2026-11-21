package qualification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixturePolicy(t *testing.T, now time.Time) (Policy, []byte, ed25519.PublicKey) {
	t.Helper()
	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Contract: "control/v1", Kind: "qualification-trust-policy", PolicyRevision: 2, OwnerKeyID: "fixture-root", IssuedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MaxRevocationAgeSeconds: 3600}
	p.RevocationSnapshot.UpdatedAt = now.Add(-time.Hour).Format(time.RFC3339)
	p.RevocationSnapshot.RevokedAttestationSHA256 = []string{}
	p.RevocationSnapshot.RevokedEvidenceSignerIDs = []string{}
	p.RevocationSnapshot.RevokedReleaseWorkflowIDs = []string{}
	p.ReleaseWorkflow.ID = "fixture-workflow"
	p.ReleaseWorkflow.Repository = "true-line/soul-adapters"
	p.ReleaseWorkflow.WorkflowPath = ".github/workflows/qualify.yml"
	p.ReleaseWorkflow.SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p.ReleaseWorkflow.OIDCIssuer = "https://token.actions.githubusercontent.com"
	p.ReleaseWorkflow.CertificateIdentity = "https://github.com/true-line/soul-adapters/.github/workflows/qualify.yml@refs/heads/main"
	p.ReleaseWorkflow.TrustRootSHA256 = "sha256:" + strings.Repeat("c", 64)
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p.EvidenceSigners = append(p.EvidenceSigners, struct {
		ID                     string `json:"id"`
		HostID                 string `json:"host_id"`
		Algorithm              string `json:"algorithm"`
		PublicKeySPKIDERBase64 string `json:"public_key_spki_der_base64"`
	}{ID: "fixture-signer", HostID: "fixture-host", Algorithm: "ES256", PublicKeySPKIDERBase64: base64.StdEncoding.EncodeToString(spki)})
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var asMap map[string]any
	if json.Unmarshal(raw, &asMap) != nil {
		t.Fatal("decode policy")
	}
	raw, err = json.Marshal(asMap)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(private, preimage(PolicyPurpose, raw))
	envelope, err := json.Marshal(Envelope{SchemaVersion: 1, Purpose: PolicyPurpose, OwnerKeyID: p.OwnerKeyID, PolicySHA256: digest(raw), PolicyBase64URL: base64.RawURLEncoding.EncodeToString(raw), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return p, envelope, root
}

func TestOwnerPolicySignatureAndFreshness(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	_, envelope, root := fixturePolicy(t, now)
	var parsed Envelope
	if json.Unmarshal(envelope, &parsed) != nil {
		t.Fatal("decode")
	}
	if _, err := VerifyOwnerPolicy(envelope, "fixture-root", root, 2, parsed.PolicySHA256, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		at       time.Time
		revision uint64
		key      ed25519.PublicKey
	}{
		{"stale", now.Add(time.Second), 2, root},
		{"rollback", now, 3, root},
		{"unknown root", now, 2, ed25519.PublicKey(make([]byte, 32))},
	} {
		if _, err := VerifyOwnerPolicy(envelope, "fixture-root", tc.key, tc.revision, parsed.PolicySHA256, tc.at); err == nil {
			t.Fatal(tc.name)
		}
	}
	var altered Envelope
	if json.Unmarshal(envelope, &altered) != nil {
		t.Fatal("decode")
	}
	altered.PolicySHA256 = "sha256:" + strings.Repeat("0", 64)
	bad, _ := json.Marshal(altered)
	if _, err := VerifyOwnerPolicy(bad, "fixture-root", root, 2, parsed.PolicySHA256, now); err == nil {
		t.Fatal("tampered digest")
	}
}

func TestHostSignatureDesignatedAndBound(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	p, _, _ := fixturePolicy(t, now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	// This package-only fixture represents an already verified owner policy.
	verified := VerifiedPolicy{value: p, verified: true, at: now}
	sha := "sha256:" + strings.Repeat("a", 64)
	checks := map[string]any{}
	for _, name := range []string{"egress", "credentials", "state_redirect", "safe_interrupt_resume", "session_reuse", "cost_bound", "render_coverage"} {
		checks[name] = map[string]any{"outcome": "pass"}
	}
	report := map[string]any{
		"schema_version": 1, "adapter": map[string]any{}, "launch": map[string]any{}, "harness": map[string]any{}, "runner": map[string]any{"binary_path": "/fixture/runner", "binary_sha256": sha},
		"soul_start": map[string]any{"initiator": "hq", "hq_launch_receipt": map[string]any{"uri": "fixture:hq", "sha256": sha}, "machine_observation": map[string]any{"uri": "fixture:machine", "sha256": sha}},
		"host":       map[string]any{"id": "fixture-host", "os": "darwin"}, "profile_in_force": "managed-protected", "renders": []any{}, "cost_bound": "estimate", "evaluation_cells": []any{},
		"suite_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "run_id": "fixture-run", "outcome": "pass", "checks": checks, "gates": map[string]any{"T01": map[string]any{"outcome": "pass"}}, "recorded_at": "2026-11-21T00:00:00Z",
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage(HostPurpose, raw))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	e := Envelope{SchemaVersion: 1, Purpose: HostPurpose, HostID: "fixture-host", SignerID: "fixture-signer", ReportSHA256: digest(raw), ReportBase64URL: base64.RawURLEncoding.EncodeToString(raw), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(sig)}
	envelope, _ := json.Marshal(e)
	if _, err := VerifyHostReport(envelope, VerifiedPolicy{}, now); err == nil {
		t.Fatal("unverified policy")
	}
	if _, err := VerifyHostReport(envelope, verified, now); err != nil {
		t.Fatal(err)
	}
	p.RevocationSnapshot.RevokedEvidenceSignerIDs = []string{"fixture-signer"}
	verified.value = p
	if _, err := VerifyHostReport(envelope, verified, now); err == nil {
		t.Fatal("revoked signer")
	}
	p.RevocationSnapshot.RevokedEvidenceSignerIDs = nil
	verified.value = p
	e.HostID = "other-host"
	bad, _ := json.Marshal(e)
	if _, err := VerifyHostReport(bad, verified, now); err == nil {
		t.Fatal("wrong host")
	}
	if _, err := canonicalBytes(append([]byte(`{"a":1,"a":2}`), 0x0a), MaxReportBytes); err == nil {
		t.Fatal("duplicate key")
	}
}
