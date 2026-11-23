package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	ExecutionCompletionPurposeV3 = "agent-bot/stage2a-execution-completion/v1"
	ReportCommitmentPurposeV3    = "agent-bot/stage2a-report-commitment/v1"
)

// machineRecordV3 uses the same purpose-NUL-JCS-payload signature envelope as
// Machine's one-use records. The public key must come from the installed,
// release-pinned Machine identity; an embedded key is never a trust anchor.
type machineRecordV3 struct {
	SchemaVersion            int    `json:"schema_version"`
	Purpose                  string `json:"purpose"`
	IssuerPublicKeyBase64URL string `json:"issuer_public_key_base64url"`
	PayloadSHA256            string `json:"payload_sha256"`
	PayloadBase64URL         string `json:"payload_base64url"`
	SignatureBase64URL       string `json:"signature_base64url"`
}

type executionCompletionV3 struct {
	SchemaVersion            int    `json:"schema_version"`
	Kind                     string `json:"kind"`
	ReportCandidateSHA256    string `json:"report_candidate_sha256"`
	ReservationSHA256        string `json:"reservation_sha256"`
	FinalizationSHA256       string `json:"finalization_sha256"`
	ChallengeSHA256          string `json:"challenge_sha256"`
	MeasurementBindingSHA256 string `json:"measurement_binding_sha256"`
	CompletedAt              string `json:"completed_at"`
}

type reportCommitmentV3 struct {
	SchemaVersion             int    `json:"schema_version"`
	Kind                      string `json:"kind"`
	ExecutionCompletionSHA256 string `json:"execution_completion_sha256"`
	ReportPayloadSHA256       string `json:"report_payload_sha256"`
	ReportEnvelopeSHA256      string `json:"report_envelope_sha256"`
	CommittedAt               string `json:"committed_at"`
}

func verifyMachineRecordV3(envelope []byte, purpose string, machineKey ed25519.PublicKey) ([]byte, error) {
	if len(machineKey) != ed25519.PublicKeySize {
		return nil, ErrUnqualified
	}
	fields, err := canonicalBytes(envelope, MaxReportBytes*2)
	if err != nil || !hasFields(fields, "schema_version", "purpose", "issuer_public_key_base64url", "payload_sha256", "payload_base64url", "signature_base64url") {
		return nil, ErrUnqualified
	}
	var record machineRecordV3
	if json.Unmarshal(envelope, &record) != nil || record.SchemaVersion != 1 || record.Purpose != purpose ||
		record.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(machineKey) {
		return nil, ErrUnqualified
	}
	payload, err := decode(record.PayloadBase64URL, MaxReportBytes)
	if err != nil || digest(payload) != record.PayloadSHA256 {
		return nil, ErrUnqualified
	}
	if _, err := canonicalBytes(payload, MaxReportBytes); err != nil {
		return nil, ErrUnqualified
	}
	sig, err := decode(record.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(machineKey, preimage(purpose, payload), sig) {
		return nil, ErrUnqualified
	}
	return payload, nil
}

// reportCandidateV3 removes only the reference to the pre-sign record. All
// observed run facts, measured inputs and physical results remain committed.
func reportCandidateV3(report []byte) ([]byte, error) {
	if _, err := canonicalBytes(report, MaxReportBytes); err != nil {
		return nil, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(report))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil {
		return nil, ErrUnqualified
	}
	run, ok := document["run_evidence"].(map[string]any)
	if !ok || run["execution_completion"] == nil {
		return nil, ErrUnqualified
	}
	delete(run, "execution_completion")
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(document) != nil {
		return nil, ErrUnqualified
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func canonicalFieldV3(report []byte, field string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(report))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil || document[field] == nil {
		return nil, ErrUnqualified
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(document[field]) != nil {
		return nil, ErrUnqualified
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func verifyExecutionCompletionV3(report, executionEnvelope []byte,
	machineKey ed25519.PublicKey, now time.Time) (time.Time, time.Time, error) {
	refused := func() (time.Time, time.Time, error) { return time.Time{}, time.Time{}, ErrUnqualified }
	if now.IsZero() || reportShapeV3(report) != nil {
		return refused()
	}
	fields, err := canonicalBytes(report, MaxReportBytes)
	if err != nil {
		return refused()
	}
	var refs struct {
		Reservation         reportReference `json:"reservation"`
		Finalization        reportReference `json:"finalization"`
		ExecutionCompletion reportReference `json:"execution_completion"`
		ChallengeSHA256     string          `json:"challenge_sha256"`
	}
	if json.Unmarshal(fields["run_evidence"], &refs) != nil ||
		digest(executionEnvelope) != refs.ExecutionCompletion.SHA256 {
		return refused()
	}
	prePayload, err := verifyMachineRecordV3(executionEnvelope, ExecutionCompletionPurposeV3, machineKey)
	if err != nil {
		return refused()
	}
	preFields, err := strictObject(prePayload, MaxReportBytes)
	if err != nil || !hasFields(preFields, "schema_version", "kind", "report_candidate_sha256", "reservation_sha256", "finalization_sha256", "challenge_sha256", "measurement_binding_sha256", "completed_at") {
		return refused()
	}
	var pre executionCompletionV3
	if json.Unmarshal(prePayload, &pre) != nil || pre.SchemaVersion != 1 || pre.Kind != "stage2a-execution-completion" {
		return refused()
	}
	candidate, err := reportCandidateV3(report)
	if err != nil {
		return refused()
	}
	binding, err := canonicalFieldV3(report, "measurement_binding")
	if err != nil || pre.ReportCandidateSHA256 != digest(candidate) ||
		pre.ReservationSHA256 != refs.Reservation.SHA256 ||
		pre.FinalizationSHA256 != refs.Finalization.SHA256 ||
		pre.ChallengeSHA256 != refs.ChallengeSHA256 ||
		pre.MeasurementBindingSHA256 != digest(binding) {
		return refused()
	}
	var reportRecorded string
	if json.Unmarshal(fields["recorded_at"], &reportRecorded) != nil {
		return refused()
	}
	completed, e1 := parseTime(pre.CompletedAt)
	recorded, e2 := parseTime(reportRecorded)
	if e1 != nil || e2 != nil || completed.After(recorded) || recorded.After(now) {
		return refused()
	}
	return completed, recorded, nil
}

// VerifyExecutionCompletionBeforeSignV3 is the A-local gate before requesting
// keyd's host signature. The pre-sign record is authenticated against the
// release-pinned Machine key and the complete candidate report. This verifies
// the record, not the issuer's physical observation process.
func VerifyExecutionCompletionBeforeSignV3(report, executionEnvelope []byte,
	machineKey ed25519.PublicKey, now time.Time) error {
	_, _, err := verifyExecutionCompletionV3(report, executionEnvelope, machineKey, now)
	return err
}

// VerifyCompletedRunV3 authenticates the pre-sign execution completion and
// post-sign report commitment against the exact designated-host envelope.
// expectedCommitmentSHA256 must be the release Statement's completed_run
// digest. This is an offline component check; the caller must also verify the
// release, installed bytes, local record resolution and real host custody.
func VerifyCompletedRunV3(reportEnvelope, executionEnvelope, commitmentEnvelope []byte,
	machineKey ed25519.PublicKey, expectedCommitmentSHA256 string,
	policy VerifiedPolicy, now time.Time) error {
	if !validSHA(expectedCommitmentSHA256) || digest(commitmentEnvelope) != expectedCommitmentSHA256 {
		return ErrUnqualified
	}
	report, err := VerifyHostReportV3(reportEnvelope, policy, now)
	if err != nil {
		return ErrUnqualified
	}
	completed, recorded, err := verifyExecutionCompletionV3(report, executionEnvelope, machineKey, now)
	if err != nil {
		return ErrUnqualified
	}
	postPayload, err := verifyMachineRecordV3(commitmentEnvelope, ReportCommitmentPurposeV3, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	postFields, err := strictObject(postPayload, MaxReportBytes)
	if err != nil || !hasFields(postFields, "schema_version", "kind", "execution_completion_sha256", "report_payload_sha256", "report_envelope_sha256", "committed_at") {
		return ErrUnqualified
	}
	var post reportCommitmentV3
	if json.Unmarshal(postPayload, &post) != nil || post.SchemaVersion != 1 || post.Kind != "stage2a-report-commitment" ||
		post.ExecutionCompletionSHA256 != digest(executionEnvelope) ||
		post.ReportPayloadSHA256 != digest(report) || post.ReportEnvelopeSHA256 != digest(reportEnvelope) {
		return ErrUnqualified
	}
	committed, err := parseTime(post.CommittedAt)
	if err != nil || committed.Before(recorded) || committed.Before(completed) || committed.After(now) {
		return ErrUnqualified
	}
	return nil
}
