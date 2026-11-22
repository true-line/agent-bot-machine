package qualification

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBridgeV2StatementAndQualification(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	p, _, _ := fixturePolicy(t, now)
	p.ReleaseWorkflow.SourceCommit = strings.Repeat("c", 40)
	qualification, err := os.ReadFile("testdata/bridge-v2-qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/bridge-v2-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	refs, build, err := fixedStatementV2(statement, p, digest(qualification), now)
	if err != nil {
		t.Fatal("contract v2 statement refused", err)
	}
	_, qrefs, qbuild, err := qualificationObjectV2(qualification)
	if err != nil || refs != qrefs || build != qbuild {
		t.Fatal("contract v2 qualification refs refused", err)
	}
	protectedReport, err := os.ReadFile("testdata/bridge-v2-synthetic.json")
	if err != nil || qrefs.ProtectedReport.Payload.SHA256 != digest(protectedReport) {
		t.Fatal("contract v2 protected report fixture digest drift", err)
	}
	var value map[string]any
	if err := json.Unmarshal(statement, &value); err != nil {
		t.Fatal(err)
	}
	value["predicateType"] = predicateType
	old, _ := json.Marshal(value)
	if _, _, err := fixedStatementV2(old, p, digest(qualification), now); err == nil {
		t.Fatal("old predicate accepted")
	}
	if err := json.Unmarshal(statement, &value); err != nil {
		t.Fatal(err)
	}
	value["predicate"].(map[string]any)["host_reports"].(map[string]any)["protected_report"].(map[string]any)["signature_purpose"] = HostPurpose
	wrong, _ := json.Marshal(value)
	if _, _, err := fixedStatementV2(wrong, p, digest(qualification), now); err == nil {
		t.Fatal("v1 protected purpose accepted")
	}
}

func TestBridgeV2ReleasedReportsBindBothEnvelopes(t *testing.T) {
	// Release evidence transport may be unavailable after the signed inputs
	// are installed. The local report binding and cooperative T21 path still
	// verify when proxy access is unavailable. Package-private trust
	// tokens here exercise binding, not production release admission.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	protectedRaw, err := os.ReadFile("testdata/bridge-v2-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := fixturePolicy(t, now)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p.EvidenceSigners[0].HostID = "fixture-qualification-mac"
	p.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	policy := VerifiedPolicy{value: p, verified: true, at: now, version: 2}
	protectedEnvelope := signedV2(t, protectedRaw, key, HostPurposeV2)
	var cooperative map[string]any
	if err := json.Unmarshal(protectedRaw, &cooperative); err != nil {
		t.Fatal(err)
	}
	delete(cooperative, "bridge")
	cooperative["schema_version"] = float64(1)
	cooperative["profile_in_force"] = "managed-cooperative"
	cooperative["run_id"] = "fixture-cooperative-run"
	evidence := cooperative["gates"].(map[string]any)["T01"].(map[string]any)["evidence"]
	cooperative["gates"] = map[string]any{"T21": map[string]any{"outcome": "pass", "evidence": evidence}}
	cooperativeRaw, err := json.Marshal(cooperative)
	if err != nil {
		t.Fatal(err)
	}
	cooperativeEnvelope := signedV2(t, cooperativeRaw, key, HostPurpose)
	if _, err := VerifyHostReport(cooperativeEnvelope, policy, now); err != nil {
		t.Fatal("local cooperative T21 report failed during evidence-store outage", err)
	}
	var qualification map[string]any
	qraw, err := os.ReadFile("testdata/bridge-v2-qualification.json")
	if err != nil || json.Unmarshal(qraw, &qualification) != nil {
		t.Fatal("read qualification", err)
	}
	conformance := qualification["conformance"].(map[string]any)
	// The contract's shape-only fixture uses a different recorded_at; a
	// release candidate must bind the primary signed run exactly.
	var protectedFields map[string]any
	if err := json.Unmarshal(protectedRaw, &protectedFields); err != nil {
		t.Fatal(err)
	}
	qualification["recorded_at"] = protectedFields["recorded_at"]
	protectedRef := qualificationReportRef{2, HostPurposeV2, reportReference{"fixture:protected-payload", digest(protectedRaw)}, reportReference{"fixture:protected-envelope", digest(protectedEnvelope)}}
	cooperativeRef := qualificationReportRef{1, HostPurpose, reportReference{"fixture:cooperative-payload", digest(cooperativeRaw)}, reportReference{"fixture:cooperative-envelope", digest(cooperativeEnvelope)}}
	conformance["protected_report"] = protectedRef
	conformance["cooperative_report"] = cooperativeRef
	qraw, err = json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	pair := qualificationReportPair{protectedRef, cooperativeRef}
	_, _, buildClaim, err := qualificationObjectV2(qraw)
	if err != nil {
		t.Fatal(err)
	}
	// Package-private synthetic trust token exercises byte binding. The
	// production verifier has no constructor until a separate owner-pinned
	// Souls build root and approved tree are implemented.
	buildVerified := VerifiedSoulsBuild{verified: true, build: buildClaim}
	release := VerifiedRelease{verified: true, qualificationSHA256: digest(qraw), ownerKeyID: p.OwnerKeyID, policyRevision: p.PolicyRevision, v2Reports: &pair, v2SoulsBuild: &buildClaim}
	if err := VerifyReleasedReportsV2(release, policy, qraw, protectedEnvelope, cooperativeEnvelope, VerifiedSoulsBuild{}, now); err == nil {
		t.Fatal("unverified Souls build accepted")
	}
	if err := VerifyReleasedReportsV2(release, policy, qraw, protectedEnvelope, cooperativeEnvelope, buildVerified, now); err != nil {
		t.Fatal("valid synthetic v2 release binding refused", err)
	}
	if err := VerifyReleasedReportsV2(release, policy, qraw, cooperativeEnvelope, protectedEnvelope, buildVerified, now); err == nil {
		t.Fatal("swapped profiles accepted")
	}
	tampered := protectedRef
	tampered.Signature.SHA256 = digest(cooperativeEnvelope)
	conformance["protected_report"] = tampered
	badQ, _ := json.Marshal(qualification)
	badRelease := release
	badRelease.qualificationSHA256 = digest(badQ)
	if err := VerifyReleasedReportsV2(badRelease, policy, badQ, protectedEnvelope, cooperativeEnvelope, buildVerified, now); err == nil {
		t.Fatal("substituted envelope digest accepted")
	}
}
