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

func signedMachineRecordV3(t *testing.T, payload map[string]any, purpose string, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	envelope, err := json.Marshal(map[string]any{
		"schema_version":              1,
		"purpose":                     purpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(pub),
		"payload_sha256":              digest(raw),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(raw),
		"signature_base64url":         base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, preimage(purpose, raw))),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestCompletedRunV3RequiresBothImmutableRecords(t *testing.T) {
	now := time.Date(2026, 11, 22, 7, 0, 0, 0, time.UTC)
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&hostKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, _ := fixturePolicy(t, now)
	policy.EvidenceSigners[0].HostID = "fixture-physical-mac"
	policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	verified := VerifiedPolicy{value: policy, verified: true, at: now, version: 3}
	machinePub, machineKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	fields, err := strictObject(report, MaxReportBytes)
	if err != nil {
		t.Fatal(err)
	}
	var run struct {
		Reservation     reportReference `json:"reservation"`
		Finalization    reportReference `json:"finalization"`
		ChallengeSHA256 string          `json:"challenge_sha256"`
	}
	if json.Unmarshal(fields["run_evidence"], &run) != nil {
		t.Fatal("fixture run evidence")
	}
	candidate, err := reportCandidateV3(report)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := canonicalFieldV3(report, "measurement_binding")
	if err != nil {
		t.Fatal(err)
	}
	pre := signedMachineRecordV3(t, map[string]any{
		"schema_version":             1,
		"kind":                       "stage2a-execution-completion",
		"report_candidate_sha256":    digest(candidate),
		"reservation_sha256":         run.Reservation.SHA256,
		"finalization_sha256":        run.Finalization.SHA256,
		"challenge_sha256":           run.ChallengeSHA256,
		"measurement_binding_sha256": digest(binding),
		"completed_at":               "2026-11-22T05:59:59Z",
	}, ExecutionCompletionPurposeV3, machineKey)
	var document map[string]any
	if json.Unmarshal(report, &document) != nil {
		t.Fatal("fixture report")
	}
	document["run_evidence"].(map[string]any)["execution_completion"] = map[string]any{
		"uri": "fixture:protected-execution-completion", "sha256": digest(pre),
	}
	report, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	hostEnvelope := signedReportV3(t, report, hostKey)
	if err := VerifyExecutionCompletionBeforeSignV3(report, pre, machinePub, now); err != nil {
		t.Fatal("valid pre-sign execution completion refused", err)
	}
	if VerifyExecutionCompletionBeforeSignV3(report, nil, machinePub, now) == nil {
		t.Fatal("host report signing admitted without a completion record")
	}
	post := signedMachineRecordV3(t, map[string]any{
		"schema_version":              1,
		"kind":                        "stage2a-report-commitment",
		"execution_completion_sha256": digest(pre),
		"report_payload_sha256":       digest(report),
		"report_envelope_sha256":      digest(hostEnvelope),
		"committed_at":                "2026-11-22T06:00:01Z",
	}, ReportCommitmentPurposeV3, machineKey)
	if err := VerifyCompletedRunV3(hostEnvelope, pre, post, machinePub, digest(post), verified, now); err != nil {
		t.Fatal("valid synthetic two-record chain refused", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		host, pre, post []byte
		key             ed25519.PublicKey
		expected        string
	}{
		{"wrong Machine trust pin", hostEnvelope, pre, post, otherPub, digest(post)},
		{"missing pre-sign record", hostEnvelope, nil, post, machinePub, digest(post)},
		{"missing post-sign record", hostEnvelope, pre, nil, machinePub, digest(post)},
		{"wrong Statement digest", hostEnvelope, pre, post, machinePub, digest(pre)},
		{"changed report envelope", append(append([]byte{}, hostEnvelope...), ' '), pre, post, machinePub, digest(post)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyCompletedRunV3(tc.host, tc.pre, tc.post, tc.key, tc.expected, verified, now) == nil {
				t.Fatal("broken completed-run chain accepted")
			}
		})
	}
}
