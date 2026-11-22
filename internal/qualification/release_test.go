package qualification

import (
	"crypto/ecdsa"
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

func TestReleasedReportsBindFixedPhysicalGates(t *testing.T) {
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	policy, _, _ := fixturePolicy(t, now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	verified := VerifiedPolicy{value: policy, verified: true, at: now}
	sha := "sha256:" + strings.Repeat("a", 64)
	evidence := map[string]any{"uri": "fixture:evidence", "sha256": sha}
	checks := map[string]any{}
	for _, name := range []string{"egress", "credentials", "state_redirect", "safe_interrupt_resume", "session_reuse", "cost_bound", "render_coverage"} {
		checks[name] = map[string]any{"outcome": "pass", "evidence": []any{evidence}}
	}
	gate := map[string]any{"outcome": "pass", "evidence": evidence}
	protected := map[string]any{
		"schema_version":   1,
		"adapter":          map[string]any{"id": "fixture-adapter", "version": "1.0.0", "package_sha256": sha},
		"launch":           map[string]any{"executable": "/fixture/adapter", "executable_sha256": sha, "argv": []any{"run"}, "code_inputs": []any{}},
		"harness":          map[string]any{"name": "fixture-harness", "version": "1.0.0", "binary_path": "/fixture/harness", "binary_sha256": sha},
		"runner":           map[string]any{"binary_path": "/fixture/runner", "binary_sha256": sha},
		"soul_start":       map[string]any{"initiator": "hq", "hq_launch_receipt": evidence, "machine_observation": evidence},
		"host":             map[string]any{"id": "fixture-host", "os": "darwin", "os_version": "27.0", "architecture": "arm64", "profile": "fixture-profile", "evidence": []any{evidence}},
		"profile_in_force": "managed-protected", "renders": []any{"text"}, "cost_bound": "estimate",
		"evaluation_cells": []any{map[string]any{"role": "assistant", "model": "fixture-model", "provider": "fixture-provider", "revision": "fixture-revision", "evidence": evidence}},
		"suite_revision":   strings.Repeat("a", 40), "run_id": "fixture-protected", "outcome": "pass", "checks": checks,
		"gates": map[string]any{"T01": gate, "T02": gate, "T03": gate}, "recorded_at": now.Add(-time.Hour).Format(time.RFC3339),
	}
	sign := func(report map[string]any) ([]byte, []byte) {
		t.Helper()
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(preimage(HostPurpose, raw))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		envelope, err := json.Marshal(Envelope{SchemaVersion: 1, Purpose: HostPurpose, HostID: "fixture-host", SignerID: "fixture-signer", ReportSHA256: digest(raw), ReportBase64URL: base64.RawURLEncoding.EncodeToString(raw), SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature)})
		if err != nil {
			t.Fatal(err)
		}
		return envelope, raw
	}
	protectedEnvelope, protectedRaw := sign(protected)
	cooperative := make(map[string]any, len(protected))
	for k, v := range protected {
		cooperative[k] = v
	}
	cooperative["profile_in_force"] = "managed-cooperative"
	cooperative["run_id"] = "fixture-cooperative"
	cooperative["gates"] = map[string]any{"T21": gate}
	cooperativeEnvelope, cooperativeRaw := sign(cooperative)
	qualification := make(map[string]any, len(protected))
	for k, v := range protected {
		qualification[k] = v
	}
	delete(qualification, "gates")
	for _, name := range []string{"suite_revision", "run_id", "outcome", "checks"} {
		delete(qualification, name)
	}
	qualification["conformance"] = map[string]any{"suite_revision": protected["suite_revision"], "run_id": protected["run_id"], "outcome": "pass", "checks": checks, "report": map[string]any{"uri": "fixture:protected", "sha256": digest(protectedRaw)}}
	qualificationRaw, err := json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	release := VerifiedRelease{verified: true, bundleSHA256: sha, qualificationSHA256: digest(qualificationRaw), ownerKeyID: policy.OwnerKeyID, policyRevision: policy.PolicyRevision, hostReports: []reportReference{{URI: "fixture:protected", SHA256: digest(protectedRaw)}, {URI: "fixture:cooperative", SHA256: digest(cooperativeRaw)}}}
	if err := VerifyReleasedReports(release, verified, qualificationRaw, [][]byte{protectedEnvelope, cooperativeEnvelope}, now); err != nil {
		t.Fatal(err)
	}
	gotProtected, gotCooperative, err := VerifyHostReportsForRelease(verified, qualificationRaw, protectedEnvelope, cooperativeEnvelope, now)
	if err != nil || gotProtected != digest(protectedRaw) || gotCooperative != digest(cooperativeRaw) {
		t.Fatalf("producer preflight: %s %s %v", gotProtected, gotCooperative, err)
	}
	if _, _, err := VerifyHostReportsForRelease(verified, qualificationRaw, cooperativeEnvelope, protectedEnvelope, now); err == nil {
		t.Fatal("reversed profile envelopes accepted")
	}
	withoutBundle := release
	withoutBundle.bundleSHA256 = ""
	if err := VerifyReleasedReports(withoutBundle, verified, qualificationRaw, [][]byte{protectedEnvelope, cooperativeEnvelope}, now); err == nil {
		t.Fatal("producer preflight promoted to release verification")
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"adapter package", func(m map[string]any) {
			m["adapter"].(map[string]any)["package_sha256"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{"runner digest", func(m map[string]any) {
			m["runner"].(map[string]any)["binary_sha256"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{"host version", func(m map[string]any) { m["host"].(map[string]any)["os_version"] = "28.0" }},
		{"missing Machine observation", func(m map[string]any) { delete(m["soul_start"].(map[string]any), "machine_observation") }},
		{"failed T21", func(m map[string]any) { m["gates"].(map[string]any)["T21"].(map[string]any)["outcome"] = "fail" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(cooperative)
			if err != nil {
				t.Fatal(err)
			}
			var changed map[string]any
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("decode")
			}
			tc.edit(changed)
			changedEnvelope, changedRaw := sign(changed)
			changedRelease := release
			changedRelease.hostReports = append([]reportReference(nil), release.hostReports...)
			changedRelease.hostReports[1].SHA256 = digest(changedRaw)
			if err := VerifyReleasedReports(changedRelease, verified, qualificationRaw, [][]byte{protectedEnvelope, changedEnvelope}, now); err == nil {
				t.Fatal("changed signed physical result accepted")
			}
		})
	}
	encoded, err := json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	var changedQualification map[string]any
	if json.Unmarshal(encoded, &changedQualification) != nil {
		t.Fatal("decode")
	}
	changedQualification["runner"].(map[string]any)["binary_sha256"] = "sha256:" + strings.Repeat("b", 64)
	changedBytes, err := json.Marshal(changedQualification)
	if err != nil {
		t.Fatal(err)
	}
	changedRelease := release
	changedRelease.qualificationSHA256 = digest(changedBytes)
	if err := VerifyReleasedReports(changedRelease, verified, changedBytes, [][]byte{protectedEnvelope, cooperativeEnvelope}, now); err == nil {
		t.Fatal("qualification runner differs from host report")
	}
}

func TestFixedQualificationStatementBindings(t *testing.T) {
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	policy, _, _ := fixturePolicy(t, now)
	qualSHA := "sha256:" + strings.Repeat("a", 64)
	ref := func(c string) map[string]any {
		return map[string]any{"uri": "fixture:host-" + c, "sha256": "sha256:" + strings.Repeat(c, 64)}
	}
	statement := map[string]any{
		"_type":         statementType,
		"subject":       []any{map[string]any{"name": "qualification.json", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}}},
		"predicateType": predicateType,
		"predicate": map[string]any{
			"host_reports": []any{ref("b"), ref("c")},
			"expires_at":   now.Add(time.Hour).Format(time.RFC3339),
			"release": map[string]any{
				"source_repository": policy.ReleaseWorkflow.Repository,
				"source_commit":     policy.ReleaseWorkflow.SourceCommit,
				"workflow":          policy.ReleaseWorkflow.WorkflowPath,
			},
		},
	}
	check := func(value map[string]any, want bool) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fixedStatement(raw, policy, qualSHA, now)
		if (err == nil) != want {
			t.Fatalf("statement accepted=%v, want %v: %v", err == nil, want, err)
		}
	}
	check(statement, true)
	predicate := statement["predicate"].(map[string]any)
	predicate["host_reports"] = []any{ref("b"), ref("b")}
	check(statement, false)
	predicate["host_reports"] = []any{ref("b"), ref("c")}
	statement["subject"] = []any{map[string]any{"name": "qualification.json", "digest": map[string]any{"sha256": strings.Repeat("d", 64)}}}
	check(statement, false)
	statement["subject"] = []any{map[string]any{"name": "qualification.json", "digest": map[string]any{"sha256": strings.Repeat("a", 64)}}}
	predicate["release"].(map[string]any)["source_commit"] = strings.Repeat("d", 40)
	check(statement, false)
	predicate["release"].(map[string]any)["source_commit"] = policy.ReleaseWorkflow.SourceCommit
	predicate["expires_at"] = now.Format(time.RFC3339)
	check(statement, false)
}

func TestReleaseRequiresPinnedLocalMaterial(t *testing.T) {
	now := time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC)
	policy, _, _ := fixturePolicy(t, now)
	verified := VerifiedPolicy{value: policy, verified: true, at: now}
	if _, err := VerifyReleaseAttestation(VerifiedPolicy{}, []byte("{}"), []byte("{}"), []byte("{}"), digest([]byte("{}")), now); err == nil {
		t.Fatal("unverified policy accepted")
	}
	if _, err := VerifyReleaseAttestation(verified, []byte("{}"), []byte("{}"), []byte("{}"), digest([]byte("{}")), now); err == nil {
		t.Fatal("untrusted root accepted")
	}
	policy.ReleaseWorkflow.TrustRootSHA256 = digest([]byte("{}"))
	verified.value = policy
	if _, err := VerifyReleaseAttestation(verified, []byte("{}"), []byte("{}"), []byte("{}"), digest([]byte("different")), now); err == nil {
		t.Fatal("bundle digest mismatch accepted")
	}
}
