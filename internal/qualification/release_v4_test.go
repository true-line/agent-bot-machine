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
	"math/big"
	"os"
	"testing"
	"time"
)

// The source bytes are pinned from Contracts #83 at the recorded head. They
// validate the release format and byte joins, not signing-time or T evidence.
func TestV4QualificationAndStatementContractBytes(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-release-v4-contracts83.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceHead    string `json:"source_head"`
		Qualification string `json:"qualification_jcs"`
		Statement     string `json:"statement_jcs"`
	}
	if json.Unmarshal(raw, &fixture) != nil || fixture.SourceHead != "e250b0dbfc4a1d73f4a624b06e5f00896c455fcb" {
		t.Fatal("pinned Contracts v4 release bytes unavailable")
	}
	now := time.Date(2026, 11, 22, 14, 17, 0, 0, time.UTC)
	qualification := []byte(fixture.Qualification)
	fields, refs, build, recorded, err := qualificationObjectV4(qualification, now)
	if err != nil || !validV4Pair(refs) || !validSoulsBuild(build) || recorded.After(now) {
		t.Fatal("v4 qualification refused:", err)
	}
	var artifact string
	if json.Unmarshal(fields["soul_artifact_sha256"], &artifact) != nil {
		t.Fatal("invalid frozen artifact")
	}
	policy, _, _ := fixturePolicy(t, now)
	policy.ReleaseWorkflow.SourceCommit = "cccccccccccccccccccccccccccccccccccccccc"
	statementRefs, statementBuild, expires, err := fixedStatementV4([]byte(fixture.Statement), policy,
		digest(qualification), artifact, recorded, now)
	if err != nil || statementRefs != refs || statementBuild != build || !expires.After(now) {
		t.Fatal("v4 Statement refused exact subject and refs:", err)
	}
	wrongPurpose := bytes.Replace(qualification, []byte(HostPurposeV4), []byte(HostPurposeV3), 1)
	if bytes.Equal(wrongPurpose, qualification) {
		t.Fatal("fixture missing v4 purpose")
	}
	if _, _, _, _, err := qualificationObjectV4(wrongPurpose, now); err == nil {
		t.Fatal("older host purpose accepted")
	}
	wrongSubject := bytes.Replace([]byte(fixture.Statement), []byte(digest(qualification)[7:]),
		[]byte("0000000000000000000000000000000000000000000000000000000000000000"), 1)
	if _, _, _, err := fixedStatementV4(wrongSubject, policy, digest(qualification), artifact, recorded, now); err == nil {
		t.Fatal("changed qualification subject accepted")
	}
	vectorsRaw, err := os.ReadFile("testdata/stage2a-v4-completion-contracts83.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]struct {
		Report       string `json:"report_jcs"`
		HostEnvelope string `json:"host_envelope_jcs"`
		Completion   string `json:"completion_envelope_jcs"`
		Commitment   string `json:"commitment_envelope_jcs"`
		MachineKey   string `json:"machine_public_key_base64url"`
	}
	if json.Unmarshal(vectorsRaw, &vectors) != nil || len(vectors) != 2 {
		t.Fatal("invalid pinned v4 report vectors")
	}
	baseX, baseY := elliptic.P256().ScalarBaseMult([]byte{1})
	spki, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: baseX, Y: baseY})
	if err != nil {
		t.Fatal(err)
	}
	policy.EvidenceSigners[0].HostID = "synthetic-host"
	policy.EvidenceSigners[0].ID = "synthetic-signer"
	policy.EvidenceSigners[0].PublicKeySPKIDERBase64 = base64.StdEncoding.EncodeToString(spki)
	var report struct {
		MeasurementBinding json.RawMessage `json:"measurement_binding"`
	}
	if json.Unmarshal([]byte(vectors["protected"].Report), &report) != nil {
		t.Fatal("invalid protected report")
	}
	binding, err := parseHRMeasurementBindingV3(report.MeasurementBinding)
	if err != nil {
		t.Fatal(err)
	}
	policy.FrozenSoulMapping = &FrozenSoulMapping{SoulID: binding.Base.SoulID, ArtifactSHA256: artifact,
		ClaimedDefinitionDigest: binding.Base.ClaimedDefinitionDigest,
		DefinitionMeasurement:   binding.Base.DefinitionMeasurement}
	verified := VerifiedPolicy{value: policy, verified: true, version: 3, at: now}
	key, err := base64.RawURLEncoding.Strict().DecodeString(vectors["protected"].MachineKey)
	if err != nil || len(key) != ed25519.PublicKeySize || vectors["cooperative"].MachineKey != vectors["protected"].MachineKey {
		t.Fatal("invalid independent Machine fixture key")
	}
	p, c := vectors["protected"], vectors["cooperative"]
	pRaw, err := VerifyHostReportV4([]byte(p.HostEnvelope), verified, now)
	if err != nil {
		t.Fatal("protected host signature:", err)
	}
	cRaw, err := VerifyHostReportV4([]byte(c.HostEnvelope), verified, now)
	if err != nil {
		t.Fatal("cooperative host signature:", err)
	}
	if verifyV4ReportPairClaims(verified, fields, pRaw, cRaw, artifact, recorded, now) == nil {
		t.Fatal("reused start and launch IDs accepted as distinct physical runs")
	}
	for _, run := range []struct {
		host, completion, commitment []byte
	}{
		{[]byte(p.HostEnvelope), []byte(p.Completion), []byte(p.Commitment)},
		{[]byte(c.HostEnvelope), []byte(c.Completion), []byte(c.Commitment)},
	} {
		if err := VerifyCompletedRunV4(run.host, run.completion, run.commitment, key,
			digest(run.commitment), verified, now); err != nil {
			t.Fatal("v4 signed run chain:", err)
		}
	}
	// Derive a second, distinct synthetic start and re-sign its A and host
	// envelopes. Its Q references are not raw-verified by this candidate check.
	var cooperativeDoc map[string]any
	if json.Unmarshal(cRaw, &cooperativeDoc) != nil {
		t.Fatal("decode cooperative report")
	}
	bindingDoc := cooperativeDoc["measurement_binding"].(map[string]any)
	bindingDoc["start_id"] = "st_0123456789abcdef01234568"
	bindingDoc["launch_id"] = "ln_0123456789abcdef01234568"
	bindingDoc["snapshots"].(map[string]any)["launch_inputs"].(map[string]any)["inode"] = "12347"
	completionURI := cooperativeDoc["run_evidence"].(map[string]any)["execution_completion"].(map[string]any)["uri"].(string)
	delete(cooperativeDoc["run_evidence"].(map[string]any), "execution_completion")
	candidate, err := canonicalMarshalRecordV3(cooperativeDoc)
	if err != nil {
		t.Fatal(err)
	}
	privateMachine := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	if !bytes.Equal(privateMachine.Public().(ed25519.PublicKey), key) {
		t.Fatal("fixture Machine signer changed")
	}
	signMachine := func(message []byte) ([]byte, error) { return ed25519.Sign(privateMachine, message), nil }
	completedAt := time.Date(2026, 11, 22, 14, 15, 26, 0, time.UTC)
	cNewCompletion, cNewReport, err := IssueExecutionCompletionV4(candidate, completionURI,
		"synthetic-cohort-cooperative", completedAt, now, key, signMachine)
	if err != nil {
		t.Fatal("issue distinct synthetic completion:", err)
	}
	hostPrivate := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: baseX, Y: baseY}, D: big.NewInt(1)}
	sum := sha256.Sum256(preimage(HostPurposeV4, cNewReport))
	r, s, err := ecdsa.Sign(rand.Reader, hostPrivate, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	cNewHost, err := canonicalMarshalRecordV3(Envelope{SchemaVersion: 4, Purpose: HostPurposeV4,
		HostID: "synthetic-host", SignerID: "synthetic-signer", ReportSHA256: digest(cNewReport),
		ReportBase64URL:    base64.RawURLEncoding.EncodeToString(cNewReport),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	committedAt := time.Date(2026, 11, 22, 14, 15, 29, 0, time.UTC)
	atCommit := verified
	atCommit.at = committedAt
	cNewCommitment, _, err := IssueReportCommitmentV4(cNewHost, cNewCompletion, atCommit,
		committedAt, key, signMachine)
	if err != nil {
		t.Fatal("issue distinct synthetic commitment:", err)
	}
	var qDoc, statementDoc map[string]any
	if json.Unmarshal(qualification, &qDoc) != nil || json.Unmarshal([]byte(fixture.Statement), &statementDoc) != nil {
		t.Fatal("decode release candidate")
	}
	cooperativeRef := qDoc["conformance"].(map[string]any)["cooperative_report"].(map[string]any)
	cooperativeRef["payload"].(map[string]any)["sha256"] = digest(cNewReport)
	cooperativeRef["signature"].(map[string]any)["sha256"] = digest(cNewHost)
	cooperativeRef["completed_run"].(map[string]any)["sha256"] = digest(cNewCommitment)
	qualified, err := canonicalMarshalRecordV3(qDoc)
	if err != nil {
		t.Fatal(err)
	}
	statementDoc["predicate"].(map[string]any)["host_reports"].(map[string]any)["cooperative_report"] = cooperativeRef
	statementDoc["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = digest(qualified)[7:]
	statement, err := canonicalMarshalRecordV3(statementDoc)
	if err != nil {
		t.Fatal(err)
	}
	check := func(statement, cooperativeCommitment []byte) error {
		return VerifyV4ReleaseCandidateClaims(verified, qualified, statement,
			[]byte(p.HostEnvelope), cNewHost, []byte(p.Completion), cNewCompletion,
			[]byte(p.Commitment), cooperativeCommitment, VerifiedSoulsBuild{verified: true, build: build},
			ed25519.PublicKey(key), now)
	}
	if err := check(statement, cNewCommitment); err != nil {
		t.Fatal("synthetic v4 release candidate refused:", err)
	}
	_, signedRefs, signedBuild, _, err := qualificationObjectV4(qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	// This locally fabricated receipt exercises only the binding to a release
	// verifier result. It is not a Sigstore bundle or physical qualification.
	release := VerifiedRelease{verified: true, bundleSHA256: digest([]byte("synthetic bundle")),
		qualificationSHA256: digest(qualified), ownerKeyID: policy.OwnerKeyID,
		policyRevision: policy.PolicyRevision, v4Reports: &signedRefs,
		v4SoulsBuild: &signedBuild, v4SoulArtifact: artifact, v4ExpiresAt: expires}
	signedCheck := func(receipt VerifiedRelease) error {
		return VerifyV4SignedReleaseCandidateClaims(receipt, verified, qualified, statement,
			[]byte(p.HostEnvelope), cNewHost, []byte(p.Completion), cNewCompletion,
			[]byte(p.Commitment), cNewCommitment, VerifiedSoulsBuild{verified: true, build: build},
			ed25519.PublicKey(key), now)
	}
	if err := signedCheck(release); err != nil {
		t.Fatal("matching synthetic release receipt refused:", err)
	}
	changedReceipt := release
	changedReceipt.qualificationSHA256 = digest(qualification)
	if signedCheck(changedReceipt) == nil {
		t.Fatal("release receipt for other qualification bytes accepted")
	}
	changedReceipt = release
	changedReceipt.v4Reports = &refs
	if signedCheck(changedReceipt) == nil {
		t.Fatal("release receipt for other host report bytes accepted")
	}
	if check(statement, []byte(p.Commitment)) == nil {
		t.Fatal("protected commitment substituted for cooperative")
	}
	if check(wrongSubject, cNewCommitment) == nil {
		t.Fatal("changed Statement subject accepted")
	}
}
