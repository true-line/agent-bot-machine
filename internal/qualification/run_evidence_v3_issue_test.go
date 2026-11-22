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
	"testing"
	"time"
)

func TestIssueCompletedRunV3TwoRecords(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&host.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, _ := fixturePolicy(t, now)
	policy.EvidenceSigners[0].HostID = "fixture-physical-mac"
	policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	verified := VerifiedPolicy{value: policy, verified: true, at: now, version: 3}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(preimage []byte) ([]byte, error) { return ed25519.Sign(key, preimage), nil }
	fixture, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var candidate map[string]any
	if json.Unmarshal(fixture, &candidate) != nil {
		t.Fatal("fixture")
	}
	delete(candidate["run_evidence"].(map[string]any), "execution_completion")
	candidateBytes, err := canonicalMarshalRecordV3(candidate)
	if err != nil {
		t.Fatal(err)
	}
	pre, report, err := IssueExecutionCompletionV3(candidateBytes, "fixture:issued-execution", now.Add(-time.Hour-time.Second), now, pub, sign)
	if err != nil {
		t.Fatal("pre-sign issuance", err)
	}
	if VerifyExecutionCompletionBeforeSignV3(report, pre, pub, now) != nil {
		t.Fatal("issued pre-sign record refused")
	}
	hostEnvelope := signedReportV3(t, report, host)
	post, postDigest, err := IssueReportCommitmentV3(hostEnvelope, pre, verified, now, pub, sign)
	if err != nil {
		t.Fatal("post-sign issuance", err)
	}
	if VerifyCompletedRunV3(hostEnvelope, pre, post, pub, postDigest, verified, now) != nil {
		t.Fatal("issued completed run refused")
	}
	badSign := func([]byte) ([]byte, error) { return make([]byte, ed25519.SignatureSize), nil }
	if _, _, err := IssueExecutionCompletionV3(candidateBytes, "fixture:issued-execution", now.Add(-time.Hour-time.Second), now, pub, badSign); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if _, _, err := IssueReportCommitmentV3(hostEnvelope, pre, verified, now, pub, badSign); err == nil {
		t.Fatal("wrong post signer accepted")
	}
	if _, _, err := IssueReportCommitmentV3(hostEnvelope, nil, verified, now, pub, sign); err == nil {
		t.Fatal("missing completion accepted")
	}
	if _, _, err := IssueExecutionCompletionV3(fixture, "fixture:issued-execution", now.Add(-time.Hour-time.Second), now, pub, sign); err == nil {
		t.Fatal("candidate with completion reference accepted")
	}
}
