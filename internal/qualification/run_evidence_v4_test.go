package qualification

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Source: soul-contracts #83, f39c6140, synthetic data only. These fixtures
// prove byte joins, not a physical case or a designated host signer.
func TestV4PreSignCompletionContractVectors(t *testing.T) {
	fixture, err := os.ReadFile("testdata/stage2a-v4-completion-contracts83.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]struct {
		Report       string `json:"report_jcs"`
		Envelope     string `json:"completion_envelope_jcs"`
		Commitment   string `json:"commitment_envelope_jcs"`
		HostEnvelope string `json:"host_envelope_jcs"`
		PublicKey    string `json:"machine_public_key_base64url"`
	}
	if json.Unmarshal(fixture, &cases) != nil || len(cases) != 2 {
		t.Fatal("invalid pinned Contracts vector")
	}
	for _, profile := range []string{"protected", "cooperative"} {
		t.Run(profile, func(t *testing.T) {
			vector := cases[profile]
			key, err := base64.RawURLEncoding.Strict().DecodeString(vector.PublicKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				t.Fatal("invalid pinned Machine fixture key")
			}
			report, envelope := []byte(vector.Report), []byte(vector.Envelope)
			var recorded struct {
				RecordedAt string `json:"recorded_at"`
			}
			if json.Unmarshal(report, &recorded) != nil {
				t.Fatal("invalid fixture report")
			}
			when, err := time.Parse(time.RFC3339Nano, recorded.RecordedAt)
			if err != nil {
				t.Fatal(err)
			}
			now := when.Add(2 * time.Second)
			if err := reportShapeV4(report); err != nil {
				t.Fatal("v4 shape:", err)
			}
			if _, err := qSignedRecordV3(envelope, ExecutionCompletionPurposeV4, 2, key); err != nil {
				t.Fatal("completion signature:", err)
			}
			if err := VerifyExecutionCompletionBeforeSignV4(report, envelope, key, now); err != nil {
				t.Fatal("valid Contracts v4 pre-sign chain refused:", err)
			}
			hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			policy, _, _ := fixturePolicy(t, now)
			policy.EvidenceSigners[0].HostID = "synthetic-host"
			policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
			verified := VerifiedPolicy{value: policy, verified: true, at: now, version: 3}
			sum := sha256.Sum256(preimage(HostPurposeV4, report))
			r, s, err := ecdsa.Sign(rand.Reader, hostKey, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			signature := make([]byte, 64)
			r.FillBytes(signature[:32])
			s.FillBytes(signature[32:])
			hostEnvelope, err := canonicalMarshalRecordV3(Envelope{
				SchemaVersion: 4, Purpose: HostPurposeV4, HostID: "synthetic-host", SignerID: policy.EvidenceSigners[0].ID,
				ReportSHA256: digest(report), ReportBase64URL: base64.RawURLEncoding.EncodeToString(report),
				SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyHostReportV4(hostEnvelope, verified, now); err != nil {
				t.Fatal("designated v4 host signature refused:", err)
			}
			if _, err := VerifyHostReportV3(hostEnvelope, verified, now); err == nil {
				t.Fatal("v4 purpose substituted for v3")
			}
			baseX, baseY := elliptic.P256().ScalarBaseMult([]byte{1})
			fixtureSPKI, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: baseX, Y: baseY})
			if err != nil {
				t.Fatal(err)
			}
			fixturePolicyValue, _, _ := fixturePolicy(t, now)
			fixturePolicyValue.EvidenceSigners[0].HostID = "synthetic-host"
			fixturePolicyValue.EvidenceSigners[0].ID = "synthetic-signer"
			fixturePolicyValue.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(fixtureSPKI)
			fixturePolicyVerified := VerifiedPolicy{value: fixturePolicyValue, verified: true, at: now, version: 3}
			qFixture, err := os.ReadFile("testdata/stage2a-q-v3-profile-join-contracts-draft.json")
			if err != nil {
				t.Fatal(err)
			}
			var qVectors struct {
				Profiles map[string]struct {
					Reservation string `json:"reservation_envelope_jcs"`
					Wire        string `json:"q_wire_jcs"`
					Index       string `json:"q_index_envelope_jcs"`
					EOF         string `json:"q_eof_envelope_jcs"`
				} `json:"profiles"`
			}
			if json.Unmarshal(qFixture, &qVectors) != nil {
				t.Fatal("invalid pinned Q vectors")
			}
			qVector := qVectors.Profiles[profile]
			qVerified, err := VerifyQEvidenceForSignedReportV4([]byte(vector.HostEnvelope), envelope,
				[]byte(qVector.Reservation), []byte(qVector.Wire), []byte(qVector.Index), []byte(qVector.EOF),
				fixturePolicyVerified, key, now)
			if err != nil || !qVerified.verified || qVerified.Profile != "managed-"+profile {
				t.Fatal("signed v4 report refused its raw Q chain:", err)
			}
			if _, err := VerifyQEvidenceForSignedReportV4([]byte(vector.HostEnvelope), envelope,
				[]byte(qVector.Reservation), []byte(qVector.Wire), []byte(qVector.Index), nil,
				fixturePolicyVerified, key, now); err == nil {
				t.Fatal("missing clean Q EOF accepted")
			}
			otherProfile := "protected"
			if profile == "protected" {
				otherProfile = "cooperative"
			}
			otherQ := qVectors.Profiles[otherProfile]
			if _, err := VerifyQEvidenceForSignedReportV4([]byte(vector.HostEnvelope), envelope,
				[]byte(otherQ.Reservation), []byte(otherQ.Wire), []byte(otherQ.Index), []byte(otherQ.EOF),
				fixturePolicyVerified, key, now); err == nil {
				t.Fatal("other profile's Q chain accepted")
			}
			if err := VerifyCompletedRunV4([]byte(vector.HostEnvelope), envelope, []byte(vector.Commitment),
				key, digest([]byte(vector.Commitment)), fixturePolicyVerified, now); err != nil {
				t.Fatal("valid Contracts v4 completed chain refused:", err)
			}
			machinePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
			if !bytes.Equal(machinePrivate.Public().(ed25519.PublicKey), key) {
				t.Fatal("Contracts fixture Machine key changed")
			}
			sign := func(message []byte) ([]byte, error) { return ed25519.Sign(machinePrivate, message), nil }
			candidate, err := canonicalCandidateV4(report)
			if err != nil {
				t.Fatal(err)
			}
			prePayload, err := verifyMachineRecordV4(envelope, ExecutionCompletionPurposeV4, key)
			if err != nil {
				t.Fatal(err)
			}
			var pre executionCompletionV4
			if json.Unmarshal(prePayload, &pre) != nil {
				t.Fatal("invalid Contracts pre-sign fixture")
			}
			completed, err := parseTime(pre.CompletedAt)
			if err != nil {
				t.Fatal(err)
			}
			var runRef struct {
				ExecutionCompletion reportReference `json:"execution_completion"`
			}
			var doc struct {
				RunEvidence json.RawMessage `json:"run_evidence"`
			}
			if json.Unmarshal(report, &doc) != nil || json.Unmarshal(doc.RunEvidence, &runRef) != nil {
				t.Fatal("invalid Contracts report ref")
			}
			issuedPre, issuedReport, err := IssueExecutionCompletionV4(candidate,
				runRef.ExecutionCompletion.URI, pre.CohortID, completed, now, key, sign)
			if err != nil || !bytes.Equal(issuedPre, envelope) || !bytes.Equal(issuedReport, report) {
				t.Fatal("Machine A issuer differs from pinned Contracts pre-sign bytes:", err)
			}
			postPayload, err := verifyMachineRecordV4([]byte(vector.Commitment), ReportCommitmentPurposeV4, key)
			if err != nil {
				t.Fatal(err)
			}
			var post reportCommitmentV4
			if json.Unmarshal(postPayload, &post) != nil {
				t.Fatal("invalid Contracts post-sign fixture")
			}
			committed, err := parseTime(post.CommittedAt)
			if err != nil {
				t.Fatal(err)
			}
			atCommit := fixturePolicyVerified
			atCommit.at = committed
			issuedPost, issuedDigest, err := IssueReportCommitmentV4([]byte(vector.HostEnvelope),
				envelope, atCommit, committed, key, sign)
			if err != nil || !bytes.Equal(issuedPost, []byte(vector.Commitment)) || issuedDigest != digest(issuedPost) {
				t.Fatal("Machine A issuer differs from pinned Contracts post-sign bytes:", err)
			}
			if VerifyCompletedRunV4([]byte(vector.HostEnvelope), envelope, []byte(vector.Commitment),
				key, digest([]byte("other")), fixturePolicyVerified, now) == nil {
				t.Fatal("wrong release commitment digest accepted")
			}
			wrongKey := append(ed25519.PublicKey(nil), key...)
			wrongKey[0] ^= 1
			if VerifyExecutionCompletionBeforeSignV4(report, envelope, wrongKey, now) == nil {
				t.Fatal("other Machine key accepted")
			}
			if VerifyExecutionCompletionBeforeSignV4(report, envelope, key, when.Add(-time.Second)) == nil {
				t.Fatal("future report accepted")
			}
			var document map[string]any
			if json.Unmarshal(report, &document) != nil {
				t.Fatal("invalid fixture report object")
			}
			run := document["run_evidence"].(map[string]any)
			q := run["q_session"].(map[string]any)
			delete(q, "clean_eof_envelope")
			changed, err := canonicalMarshalRecordV3(document)
			if err != nil {
				t.Fatal(err)
			}
			if VerifyExecutionCompletionBeforeSignV4(changed, envelope, key, now) == nil {
				t.Fatal("missing signed Q EOF accepted")
			}
		})
	}
}

func TestV4CanonicalBytesUnicodeAndDuplicateRefusal(t *testing.T) {
	if _, err := canonicalObjectV4([]byte(`{"é":"東京"}`), 100); err != nil {
		t.Fatal("canonical UTF-8 refused:", err)
	}
	for _, raw := range []string{
		`{"a":1,"a":2}`,
		`{"a":{"x":1,"x":2}}`,
		`{"a":1.0}`,
		`{"é":"\u6771\u4eac"}`,
	} {
		if _, err := canonicalObjectV4([]byte(raw), 100); err == nil {
			t.Errorf("noncanonical or duplicate JSON accepted: %s", raw)
		}
	}
}
