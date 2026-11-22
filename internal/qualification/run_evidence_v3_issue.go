package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// MachineRecordSignerV3 signs a purpose-NUL-canonical-payload preimage. The
// production caller must obtain this signer from Machine A's secure account;
// these byte builders do not authenticate physical observations on their own.
type MachineRecordSignerV3 func([]byte) ([]byte, error)

func issueMachineRecordV3(payload any, purpose string, key ed25519.PublicKey, sign MachineRecordSignerV3) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize || sign == nil {
		return nil, ErrUnqualified
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrUnqualified
	}
	canonical, err := canonicalizeRecordV3(raw)
	if err != nil {
		return nil, ErrUnqualified
	}
	signature, err := sign(preimage(purpose, canonical))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, preimage(purpose, canonical), signature) {
		return nil, ErrUnqualified
	}
	envelope, err := canonicalMarshalRecordV3(machineRecordV3{
		SchemaVersion: 1, Purpose: purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(key),
		PayloadSHA256:            digest(canonical),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(canonical),
		SignatureBase64URL:       base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, ErrUnqualified
	}
	if _, err := verifyMachineRecordV3(envelope, purpose, key); err != nil {
		return nil, ErrUnqualified
	}
	return envelope, nil
}

func canonicalMarshalRecordV3(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnqualified
	}
	return canonicalizeRecordV3(raw)
}

func canonicalizeRecordV3(raw []byte) ([]byte, error) {
	if !isASCII(raw) || len(raw) == 0 || len(raw) > MaxReportBytes*2 {
		return nil, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ErrUnqualified
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil, ErrUnqualified
	}
	result := bytes.TrimSuffix(output.Bytes(), []byte("\n"))
	if _, err := canonicalBytes(result, MaxReportBytes*2); err != nil {
		return nil, ErrUnqualified
	}
	return result, nil
}

// IssueExecutionCompletionV3 builds the immutable pre-sign record from a
// canonical candidate report with only run_evidence.execution_completion
// absent. A's caller must first authenticate the run, reservation,
// finalization, measured input custody, and physical results independently.
// The returned report inserts the exact record digest at completionURI.
func IssueExecutionCompletionV3(candidate []byte, completionURI string, completedAt, now time.Time,
	key ed25519.PublicKey, sign MachineRecordSignerV3) ([]byte, []byte, error) {
	if completedAt.IsZero() || now.IsZero() || completedAt.After(now) ||
		!reportRef(reportReference{URI: completionURI, SHA256: digest([]byte("pending"))}) {
		return nil, nil, ErrUnqualified
	}
	fields, err := canonicalBytes(candidate, MaxReportBytes)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	runFields, err := strictObject(fields["run_evidence"], MaxReportBytes)
	if err != nil || !hasFields(runFields, "reservation", "finalization", "challenge_sha256") {
		return nil, nil, ErrUnqualified
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(candidate))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		return nil, nil, ErrUnqualified
	}
	run := document["run_evidence"].(map[string]any)
	run["execution_completion"] = map[string]any{"uri": completionURI, "sha256": digest([]byte("pending"))}
	probe, err := canonicalMarshalRecordV3(document)
	if err != nil || reportShapeV3(probe) != nil {
		return nil, nil, ErrUnqualified
	}
	var refs struct {
		Reservation     reportReference `json:"reservation"`
		Finalization    reportReference `json:"finalization"`
		ChallengeSHA256 string          `json:"challenge_sha256"`
	}
	if json.Unmarshal(fields["run_evidence"], &refs) != nil {
		return nil, nil, ErrUnqualified
	}
	binding, err := canonicalFieldV3(probe, "measurement_binding")
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	var recordedAt string
	if json.Unmarshal(fields["recorded_at"], &recordedAt) != nil {
		return nil, nil, ErrUnqualified
	}
	recorded, err := parseTime(recordedAt)
	if err != nil || completedAt.After(recorded) || recorded.After(now) {
		return nil, nil, ErrUnqualified
	}
	envelope, err := issueMachineRecordV3(executionCompletionV3{
		SchemaVersion: 1, Kind: "stage2a-execution-completion",
		ReportCandidateSHA256: digest(candidate), ReservationSHA256: refs.Reservation.SHA256,
		FinalizationSHA256: refs.Finalization.SHA256, ChallengeSHA256: refs.ChallengeSHA256,
		MeasurementBindingSHA256: digest(binding), CompletedAt: completedAt.UTC().Format(time.RFC3339Nano),
	}, ExecutionCompletionPurposeV3, key, sign)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	run["execution_completion"] = map[string]any{"uri": completionURI, "sha256": digest(envelope)}
	report, err := canonicalMarshalRecordV3(document)
	if err != nil || VerifyExecutionCompletionBeforeSignV3(report, envelope, key, now) != nil {
		return nil, nil, ErrUnqualified
	}
	return envelope, report, nil
}

// IssueReportCommitmentV3 seals the exact report and host signature envelope
// after host signing. The caller must publish both immutable records and use
// the returned digest as completed_run in the release Statement.
func IssueReportCommitmentV3(hostEnvelope, completionEnvelope []byte, policy VerifiedPolicy,
	committedAt time.Time, key ed25519.PublicKey, sign MachineRecordSignerV3) ([]byte, string, error) {
	if committedAt.IsZero() {
		return nil, "", ErrUnqualified
	}
	report, err := VerifyHostReportV3(hostEnvelope, policy, committedAt)
	if err != nil || VerifyExecutionCompletionBeforeSignV3(report, completionEnvelope, key, committedAt) != nil {
		return nil, "", ErrUnqualified
	}
	envelope, err := issueMachineRecordV3(reportCommitmentV3{
		SchemaVersion: 1, Kind: "stage2a-report-commitment",
		ExecutionCompletionSHA256: digest(completionEnvelope), ReportPayloadSHA256: digest(report),
		ReportEnvelopeSHA256: digest(hostEnvelope), CommittedAt: committedAt.UTC().Format(time.RFC3339Nano),
	}, ReportCommitmentPurposeV3, key, sign)
	if err != nil || VerifyCompletedRunV3(hostEnvelope, completionEnvelope, envelope, key, digest(envelope), policy, committedAt) != nil {
		return nil, "", ErrUnqualified
	}
	return envelope, digest(envelope), nil
}
