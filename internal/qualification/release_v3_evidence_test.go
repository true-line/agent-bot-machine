package qualification

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

func TestReleasedReportsV3RequiresBothRunChains(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	machinePub, machineKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, _ := fixturePolicy(t, now)
	policy.EvidenceSigners[0].HostID = "fixture-physical-mac"
	policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	policy.FrozenSoulMapping = &FrozenSoulMapping{
		SoulID:                  "agent_11111111-1111-1111-1111-111111111111",
		ArtifactSHA256:          strings.Repeat("b", 64),
		ClaimedDefinitionDigest: "sha256:" + strings.Repeat("b", 64),
		DefinitionMeasurement:   "sha256:27c6f3b4c768a2f5b2fe4f5f58c829eef7d02e111517937fea100d0aa15a2ede",
	}
	verified := VerifiedPolicy{value: policy, verified: true, at: now, version: 3}
	qualificationRaw, err := os.ReadFile("testdata/measurement-v3-qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	var qualification map[string]any
	if json.Unmarshal(qualificationRaw, &qualification) != nil {
		t.Fatal("qualification fixture")
	}
	conformance := qualification["conformance"].(map[string]any)
	type chain struct{ report, execution, commitment []byte }
	var runs [2]chain
	for i, name := range []string{"protected", "cooperative"} {
		report, err := os.ReadFile("testdata/stage2a-report-v3-" + name + "-synthetic.json")
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if json.Unmarshal(report, &document) != nil {
			t.Fatal("report fixture")
		}
		run := document["run_evidence"].(map[string]any)
		candidate, err := reportCandidateV3(report)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := canonicalFieldV3(report, "measurement_binding")
		if err != nil {
			t.Fatal(err)
		}
		pre := signedMachineRecordV3(t, map[string]any{
			"schema_version": 1, "kind": "stage2a-execution-completion",
			"report_candidate_sha256":    digest(candidate),
			"reservation_sha256":         run["reservation"].(map[string]any)["sha256"],
			"finalization_sha256":        run["finalization"].(map[string]any)["sha256"],
			"challenge_sha256":           run["challenge_sha256"],
			"measurement_binding_sha256": digest(binding),
			"completed_at":               "2026-11-22T05:59:59Z",
		}, ExecutionCompletionPurposeV3, machineKey)
		run["execution_completion"] = map[string]any{"uri": "fixture:" + name + "-execution-completion", "sha256": digest(pre)}
		report, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		hostEnvelope := signedReportV3(t, report, hostKey)
		committedAt := "2026-11-22T06:00:01Z"
		if name == "cooperative" {
			committedAt = "2026-11-22T06:01:01Z"
		}
		post := signedMachineRecordV3(t, map[string]any{
			"schema_version": 1, "kind": "stage2a-report-commitment",
			"execution_completion_sha256": digest(pre),
			"report_payload_sha256":       digest(report),
			"report_envelope_sha256":      digest(hostEnvelope),
			"committed_at":                committedAt,
		}, ReportCommitmentPurposeV3, machineKey)
		refName := name + "_report"
		ref := conformance[refName].(map[string]any)
		ref["payload"].(map[string]any)["sha256"] = digest(report)
		ref["signature"].(map[string]any)["sha256"] = digest(hostEnvelope)
		ref["completed_run"].(map[string]any)["sha256"] = digest(post)
		runs[i] = chain{hostEnvelope, pre, post}
	}
	qualificationRaw, err = json.Marshal(qualification)
	if err != nil {
		t.Fatal(err)
	}
	_, refs, _, _, err := qualificationObjectV3(qualificationRaw, now)
	if err != nil {
		t.Fatal("qualification fixture and report refs", err)
	}
	release := VerifiedRelease{
		verified: true, qualificationSHA256: digest(qualificationRaw),
		ownerKeyID: policy.OwnerKeyID, policyRevision: policy.PolicyRevision,
		v3Reports: &refs, v3SoulArtifact: strings.Repeat("b", 64),
		v3ExpiresAt: now.Add(time.Minute),
	}
	if err := verifyV3ReportPairClaims(verified, qualificationRaw, runs[0].report, runs[1].report, now); err != nil {
		t.Fatal("pair claims", err)
	}
	for i, run := range runs {
		expected := refs.ProtectedReport.CompletedRun.SHA256
		if i == 1 {
			expected = refs.CooperativeReport.CompletedRun.SHA256
		}
		if err := VerifyCompletedRunV3(run.report, run.execution, run.commitment, machinePub, expected, verified, now); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	verify := func(r VerifiedRelease, q []byte, p, c chain) error {
		return VerifyReleasedReportsV3(r, verified, q,
			p.report, c.report, p.execution, c.execution,
			p.commitment, c.commitment, machinePub, now)
	}
	if err := verify(release, qualificationRaw, runs[0], runs[1]); err != nil {
		t.Fatal("valid synthetic released two-run set refused", err)
	}
	if verify(release, qualificationRaw, runs[0], chain{report: runs[1].report, execution: runs[0].execution, commitment: runs[1].commitment}) == nil {
		t.Fatal("reused protected completion accepted for cooperative run")
	}
	if verify(release, qualificationRaw, runs[0], chain{report: runs[1].report, execution: runs[1].execution}) == nil {
		t.Fatal("missing cooperative report commitment accepted")
	}
	release.v3Reports = nil
	if verify(release, qualificationRaw, runs[0], runs[1]) == nil {
		t.Fatal("release without v3 Statement report refs accepted")
	}
}
