package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	ExecutionCompletionPurposeV4 = "agent-bot/stage2a-execution-completion/v2"
	ReportCommitmentPurposeV4    = "agent-bot/stage2a-report-commitment/v2"
)

type qSessionRefsV4 struct {
	FramedWire         reportReference `json:"framed_wire"`
	FrameIndexEnvelope reportReference `json:"frame_index_envelope"`
	CleanEOFEnvelope   reportReference `json:"clean_eof_envelope"`
}

type runRefsV4 struct {
	Reservation               reportReference `json:"reservation"`
	Finalization              reportReference `json:"finalization"`
	BridgeAssignment          reportReference `json:"bridge_assignment"`
	CooperativePublishOrder   reportReference `json:"cooperative_publish_order"`
	CooperativePublishOutcome reportReference `json:"cooperative_publish_outcome"`
	CooperativeWatchedRequest reportReference `json:"cooperative_watched_request"`
	ExecutionCompletion       reportReference `json:"execution_completion"`
	ChallengeSHA256           string          `json:"challenge_sha256"`
	QSession                  qSessionRefsV4  `json:"q_session"`
}

// Unlike the earlier ASCII-only report parser, v4 accepts the exact UTF-8
// RFC 8785 serialization, including Unicode names. Duplicate keys at any
// nesting level are refused before canonicalization.
func canonicalObjectV4(raw []byte, max int) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := uniqueValueV4(decoder)
	if err != nil {
		return nil, ErrUnqualified
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrUnqualified
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrUnqualified
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrUnqualified
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, ErrUnqualified
	}
	return fields, nil
}

func uniqueValueV4(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			nameToken, err := decoder.Token()
			name, ok := nameToken.(string)
			if err != nil || !ok {
				return nil, ErrUnqualified
			}
			if _, exists := object[name]; exists {
				return nil, ErrUnqualified
			}
			value, err := uniqueValueV4(decoder)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim('}') {
			return nil, ErrUnqualified
		}
		return object, nil
	case json.Delim('['):
		var values []any
		for decoder.More() {
			value, err := uniqueValueV4(decoder)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if close, err := decoder.Token(); err != nil || close != json.Delim(']') {
			return nil, ErrUnqualified
		}
		return values, nil
	default:
		return token, nil
	}
}

func canonicalCandidateV4(report []byte) ([]byte, error) {
	if _, err := canonicalObjectV4(report, MaxReportBytes); err != nil {
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
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, ErrUnqualified
	}
	return jsoncanonicalizer.Transform(raw)
}

func canonicalFieldV4(report []byte, field string) ([]byte, error) {
	fields, err := canonicalObjectV4(report, MaxReportBytes)
	if err != nil || fields[field] == nil {
		return nil, ErrUnqualified
	}
	return jsoncanonicalizer.Transform(fields[field])
}

func verifyMachineRecordV4(envelope []byte, purpose string, machineKey ed25519.PublicKey) ([]byte, error) {
	if len(machineKey) != ed25519.PublicKeySize {
		return nil, ErrUnqualified
	}
	fields, err := canonicalObjectV4(envelope, 64<<10)
	if err != nil || !hasFields(fields, "schema_version", "purpose", "issuer_public_key_base64url", "payload_sha256", "payload_base64url", "signature_base64url") {
		return nil, ErrUnqualified
	}
	var record machineRecordV3
	if json.Unmarshal(envelope, &record) != nil || record.SchemaVersion != 2 || record.Purpose != purpose ||
		record.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(machineKey) {
		return nil, ErrUnqualified
	}
	payload, err := decode(record.PayloadBase64URL, 48<<10)
	if err != nil || digest(payload) != record.PayloadSHA256 {
		return nil, ErrUnqualified
	}
	if _, err := canonicalObjectV4(payload, 48<<10); err != nil {
		return nil, ErrUnqualified
	}
	sig, err := decode(record.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(machineKey, preimage(purpose, payload), sig) {
		return nil, ErrUnqualified
	}
	return payload, nil
}

func reportShapeV4(raw []byte) error {
	fields, err := canonicalObjectV4(raw, MaxReportBytes)
	if err != nil || !validV3Renders(fields["renders"]) {
		return ErrUnqualified
	}
	var profile string
	if json.Unmarshal(fields["profile_in_force"], &profile) != nil {
		return ErrUnqualified
	}
	names := []string{"adapter", "checks", "cost_bound", "evaluation_cells", "gates", "harness", "host", "launch", "outcome", "profile_in_force", "recorded_at", "renders", "run_id", "runner", "schema_version", "soul_start", "suite_revision", "measurement_binding", "run_evidence"}
	if profile == "managed-protected" {
		names = append(names, "bridge")
	} else if profile != "managed-cooperative" {
		return ErrUnqualified
	}
	if !hasFields(fields, names...) {
		return ErrUnqualified
	}
	var report reportDocument
	if json.Unmarshal(raw, &report) != nil || report.SchemaVersion != 4 {
		return ErrUnqualified
	}
	var binding hrMeasurementBindingV3
	if profile == "managed-protected" {
		binding, err = parseHRMeasurementBindingV3(fields["measurement_binding"])
	} else {
		binding, err = parseCooperativeMeasurementBindingV3(fields["measurement_binding"])
	}
	if err != nil || binding.Base.HostID != report.Host.ID ||
		binding.Base.ProfileInForce != profile {
		return ErrUnqualified
	}
	// Reuse the established v1/v2 checks for all unchanged report fields.
	prior := make(map[string]json.RawMessage, len(fields))
	for name, value := range fields {
		if name != "measurement_binding" && name != "run_evidence" {
			prior[name] = value
		}
	}
	if profile == "managed-protected" {
		prior["schema_version"] = []byte("2")
	} else {
		prior["schema_version"] = []byte("1")
	}
	priorRaw, err := json.Marshal(prior)
	if err != nil {
		return ErrUnqualified
	}
	if profile == "managed-protected" {
		if reportShapeV2(priorRaw) != nil {
			return ErrUnqualified
		}
	} else if reportShape(priorRaw) != nil {
		return ErrUnqualified
	}
	_, err = reportRefsV4(fields["run_evidence"], profile)
	return err
}

func reportRefsV4(raw json.RawMessage, profile string) (runRefsV4, error) {
	var refs runRefsV4
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil {
		return refs, ErrUnqualified
	}
	names := []string{"reservation", "execution_completion", "challenge_sha256", "q_session"}
	if profile == "managed-protected" {
		names = append(names, "finalization")
	} else if profile == "managed-cooperative" {
		names = append(names, "bridge_assignment", "cooperative_publish_order", "cooperative_publish_outcome", "cooperative_watched_request")
	} else {
		return refs, ErrUnqualified
	}
	if !hasFields(fields, names...) || json.Unmarshal(raw, &refs) != nil || !validSHA(refs.ChallengeSHA256) {
		return refs, ErrUnqualified
	}
	qFields, err := strictObject(fields["q_session"], MaxReportBytes)
	if err != nil || !hasFields(qFields, "framed_wire", "frame_index_envelope", "clean_eof_envelope") {
		return refs, ErrUnqualified
	}
	seenURI := map[string]bool{}
	seenSHA := map[string]bool{}
	for _, name := range append(append([]string(nil), names...), "framed_wire", "frame_index_envelope", "clean_eof_envelope") {
		if name == "challenge_sha256" || name == "q_session" {
			continue
		}
		var ref reportReference
		if qFields[name] != nil {
			if json.Unmarshal(qFields[name], &ref) != nil {
				return refs, ErrUnqualified
			}
		} else if json.Unmarshal(fields[name], &ref) != nil {
			return refs, ErrUnqualified
		}
		refFields := fields[name]
		if qFields[name] != nil {
			refFields = qFields[name]
		}
		object, err := strictObject(refFields, MaxReportBytes)
		if err != nil || !hasFields(object, "uri", "sha256") || !reportRef(ref) || seenURI[ref.URI] || seenSHA[ref.SHA256] {
			return refs, ErrUnqualified
		}
		seenURI[ref.URI], seenSHA[ref.SHA256] = true, true
	}
	return refs, nil
}

type executionCompletionV4 struct {
	SchemaVersion                   int    `json:"schema_version"`
	Kind                            string `json:"kind"`
	ProfileInForce                  string `json:"profile_in_force"`
	HostID                          string `json:"host_id"`
	InstallationID                  string `json:"installation_id"`
	SoulID                          string `json:"soul_id"`
	StartID                         string `json:"start_id"`
	LaunchID                        string `json:"launch_id"`
	CohortID                        string `json:"cohort_id"`
	ReportCandidateSHA256           string `json:"report_candidate_sha256"`
	ReservationSHA256               string `json:"reservation_sha256"`
	FinalizationSHA256              string `json:"finalization_sha256,omitempty"`
	BridgeAssignmentSHA256          string `json:"bridge_assignment_sha256,omitempty"`
	CooperativePublishOrderSHA256   string `json:"cooperative_publish_order_sha256,omitempty"`
	CooperativePublishOutcomeSHA256 string `json:"cooperative_publish_outcome_sha256,omitempty"`
	ChallengeSHA256                 string `json:"challenge_sha256"`
	MeasurementBindingSHA256        string `json:"measurement_binding_sha256"`
	QFramedWireSHA256               string `json:"q_framed_wire_sha256"`
	QFrameIndexEnvelopeSHA256       string `json:"q_frame_index_envelope_sha256"`
	QCleanEOFEnvelopeSHA256         string `json:"q_clean_eof_envelope_sha256"`
	CompletedAt                     string `json:"completed_at"`
}

// VerifyExecutionCompletionBeforeSignV4 joins the immutable signed A record
// to the exact v4 report candidate and Q digest references. It does not
// authenticate the physical observation process or grant T credit.
func VerifyExecutionCompletionBeforeSignV4(report, completionEnvelope []byte,
	machineKey ed25519.PublicKey, now time.Time) error {
	if now.IsZero() || reportShapeV4(report) != nil {
		return ErrUnqualified
	}
	fields, err := canonicalObjectV4(report, MaxReportBytes)
	if err != nil {
		return ErrUnqualified
	}
	var profile string
	if json.Unmarshal(fields["profile_in_force"], &profile) != nil {
		return ErrUnqualified
	}
	run, err := reportRefsV4(fields["run_evidence"], profile)
	if err != nil || digest(completionEnvelope) != run.ExecutionCompletion.SHA256 {
		return ErrUnqualified
	}
	payload, err := verifyMachineRecordV4(completionEnvelope, ExecutionCompletionPurposeV4, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	completionFields, err := strictObject(payload, MaxReportBytes)
	names := []string{"schema_version", "kind", "profile_in_force", "host_id", "installation_id", "soul_id", "start_id", "launch_id", "cohort_id", "report_candidate_sha256", "reservation_sha256", "challenge_sha256", "measurement_binding_sha256", "q_framed_wire_sha256", "q_frame_index_envelope_sha256", "q_clean_eof_envelope_sha256", "completed_at"}
	if profile == "managed-protected" {
		names = append(names, "finalization_sha256")
	} else {
		names = append(names, "bridge_assignment_sha256", "cooperative_publish_order_sha256", "cooperative_publish_outcome_sha256")
	}
	if err != nil || !hasFields(completionFields, names...) {
		return ErrUnqualified
	}
	var pre executionCompletionV4
	if json.Unmarshal(payload, &pre) != nil || pre.SchemaVersion != 2 || pre.Kind != "stage2a-execution-completion" ||
		pre.ProfileInForce != profile || pre.ReservationSHA256 != run.Reservation.SHA256 ||
		pre.ChallengeSHA256 != run.ChallengeSHA256 ||
		pre.QFramedWireSHA256 != run.QSession.FramedWire.SHA256 ||
		pre.QFrameIndexEnvelopeSHA256 != run.QSession.FrameIndexEnvelope.SHA256 ||
		pre.QCleanEOFEnvelopeSHA256 != run.QSession.CleanEOFEnvelope.SHA256 || pre.CohortID == "" {
		return ErrUnqualified
	}
	if profile == "managed-protected" {
		if pre.FinalizationSHA256 != run.Finalization.SHA256 {
			return ErrUnqualified
		}
	} else if pre.BridgeAssignmentSHA256 != run.BridgeAssignment.SHA256 ||
		pre.CooperativePublishOrderSHA256 != run.CooperativePublishOrder.SHA256 ||
		pre.CooperativePublishOutcomeSHA256 != run.CooperativePublishOutcome.SHA256 {
		return ErrUnqualified
	}
	var host struct {
		ID string `json:"id"`
	}
	// Explicit tags are needed because these names contain underscores.
	var ids struct {
		InstallationID string `json:"installation_id"`
		SoulID         string `json:"soul_id"`
		StartID        string `json:"start_id"`
		LaunchID       string `json:"launch_id"`
		HostID         string `json:"host_id"`
	}
	if json.Unmarshal(fields["host"], &host) != nil || json.Unmarshal(fields["measurement_binding"], &ids) != nil ||
		pre.HostID != host.ID || pre.HostID != ids.HostID || pre.InstallationID != ids.InstallationID ||
		pre.SoulID != ids.SoulID || pre.StartID != ids.StartID || pre.LaunchID != ids.LaunchID {
		return ErrUnqualified
	}
	candidate, err := canonicalCandidateV4(report)
	if err != nil || pre.ReportCandidateSHA256 != digest(candidate) {
		return ErrUnqualified
	}
	bindingBytes, err := canonicalFieldV4(report, "measurement_binding")
	if err != nil || pre.MeasurementBindingSHA256 != digest(bindingBytes) {
		return ErrUnqualified
	}
	var recordedAt string
	if json.Unmarshal(fields["recorded_at"], &recordedAt) != nil {
		return ErrUnqualified
	}
	completed, e1 := parseTime(pre.CompletedAt)
	recorded, e2 := parseTime(recordedAt)
	if e1 != nil || e2 != nil || completed.After(recorded) || recorded.After(now) {
		return ErrUnqualified
	}
	return nil
}

type reportCommitmentV4 struct {
	SchemaVersion             int    `json:"schema_version"`
	Kind                      string `json:"kind"`
	ProfileInForce            string `json:"profile_in_force"`
	HostID                    string `json:"host_id"`
	SignerID                  string `json:"signer_id"`
	InstallationID            string `json:"installation_id"`
	SoulID                    string `json:"soul_id"`
	StartID                   string `json:"start_id"`
	LaunchID                  string `json:"launch_id"`
	CohortID                  string `json:"cohort_id"`
	ExecutionCompletionSHA256 string `json:"execution_completion_sha256"`
	ReportPayloadSHA256       string `json:"report_payload_sha256"`
	ReportEnvelopeSHA256      string `json:"report_envelope_sha256"`
	CommittedAt               string `json:"committed_at"`
}

// VerifyCompletedRunV4 is an offline signed-chain component. Its expected
// commitment digest must come from the independently verified release
// Statement. This function alone never grants Stage 2a acceptance.
func VerifyCompletedRunV4(hostEnvelope, completionEnvelope, commitmentEnvelope []byte,
	machineKey ed25519.PublicKey, expectedCommitmentSHA256 string,
	policy VerifiedPolicy, now time.Time) error {
	if now.IsZero() || !validSHA(expectedCommitmentSHA256) ||
		digest(commitmentEnvelope) != expectedCommitmentSHA256 {
		return ErrUnqualified
	}
	report, err := VerifyHostReportV4(hostEnvelope, policy, now)
	if err != nil || VerifyExecutionCompletionBeforeSignV4(report, completionEnvelope, machineKey, now) != nil {
		return ErrUnqualified
	}
	preRaw, err := verifyMachineRecordV4(completionEnvelope, ExecutionCompletionPurposeV4, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	var pre executionCompletionV4
	if json.Unmarshal(preRaw, &pre) != nil {
		return ErrUnqualified
	}
	postRaw, err := verifyMachineRecordV4(commitmentEnvelope, ReportCommitmentPurposeV4, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	postFields, err := canonicalObjectV4(postRaw, MaxReportBytes)
	if err != nil || !hasFields(postFields, "schema_version", "kind", "profile_in_force", "host_id", "signer_id",
		"installation_id", "soul_id", "start_id", "launch_id", "cohort_id", "execution_completion_sha256",
		"report_payload_sha256", "report_envelope_sha256", "committed_at") {
		return ErrUnqualified
	}
	var post reportCommitmentV4
	if json.Unmarshal(postRaw, &post) != nil || post.SchemaVersion != 2 || post.Kind != "stage2a-report-commitment" ||
		post.ProfileInForce != pre.ProfileInForce || post.HostID != pre.HostID ||
		post.InstallationID != pre.InstallationID || post.SoulID != pre.SoulID ||
		post.StartID != pre.StartID || post.LaunchID != pre.LaunchID || post.CohortID != pre.CohortID ||
		post.ExecutionCompletionSHA256 != digest(completionEnvelope) ||
		post.ReportPayloadSHA256 != digest(report) || post.ReportEnvelopeSHA256 != digest(hostEnvelope) {
		return ErrUnqualified
	}
	hostSignature, err := parseEnvelope(hostEnvelope, HostPurposeV4)
	if err != nil || post.HostID != hostSignature.HostID || post.SignerID != hostSignature.SignerID {
		return ErrUnqualified
	}
	var recordedAt string
	fields, err := canonicalObjectV4(report, MaxReportBytes)
	if err != nil || json.Unmarshal(fields["recorded_at"], &recordedAt) != nil {
		return ErrUnqualified
	}
	completed, e1 := parseTime(pre.CompletedAt)
	recorded, e2 := parseTime(recordedAt)
	committed, e3 := parseTime(post.CommittedAt)
	if e1 != nil || e2 != nil || e3 != nil || committed.Before(completed) ||
		committed.Before(recorded) || committed.After(now) {
		return ErrUnqualified
	}
	return nil
}

// issueMachineRecordV4 builds an exact JCS A-signed envelope. Production must
// supply sign from the secure-admin Machine identity, never from a report or
// untrusted caller-provided key.
func issueMachineRecordV4(payload any, purpose string, machineKey ed25519.PublicKey,
	sign MachineRecordSignerV3) ([]byte, error) {
	if len(machineKey) != ed25519.PublicKeySize || sign == nil {
		return nil, ErrUnqualified
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrUnqualified
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, ErrUnqualified
	}
	if _, err := canonicalObjectV4(canonical, 48<<10); err != nil {
		return nil, ErrUnqualified
	}
	signature, err := sign(preimage(purpose, canonical))
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(machineKey, preimage(purpose, canonical), signature) {
		return nil, ErrUnqualified
	}
	envelope, err := json.Marshal(machineRecordV3{
		SchemaVersion: 2, Purpose: purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(machineKey),
		PayloadSHA256:            digest(canonical), PayloadBase64URL: base64.RawURLEncoding.EncodeToString(canonical),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, ErrUnqualified
	}
	envelope, err = jsoncanonicalizer.Transform(envelope)
	if err != nil {
		return nil, ErrUnqualified
	}
	if _, err := verifyMachineRecordV4(envelope, purpose, machineKey); err != nil {
		return nil, ErrUnqualified
	}
	return envelope, nil
}

// IssueExecutionCompletionV4 seals a fully assembled candidate report, except
// for its self-referential execution_completion ref. The caller must first
// authenticate all Q and physical source bytes and the reviewed cohort.
func IssueExecutionCompletionV4(candidate []byte, completionURI, cohortID string,
	completedAt, now time.Time, machineKey ed25519.PublicKey,
	sign MachineRecordSignerV3) ([]byte, []byte, error) {
	if completedAt.IsZero() || now.IsZero() || completedAt.After(now) || cohortID == "" || len(cohortID) > 128 ||
		!reportRef(reportReference{URI: completionURI, SHA256: digest([]byte("pending"))}) {
		return nil, nil, ErrUnqualified
	}
	fields, err := canonicalObjectV4(candidate, MaxReportBytes)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	var profile string
	if json.Unmarshal(fields["profile_in_force"], &profile) != nil {
		return nil, nil, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(candidate))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil {
		return nil, nil, ErrUnqualified
	}
	run, ok := document["run_evidence"].(map[string]any)
	if !ok || run["execution_completion"] != nil {
		return nil, nil, ErrUnqualified
	}
	run["execution_completion"] = map[string]any{"uri": completionURI, "sha256": digest([]byte("pending"))}
	probeRaw, err := json.Marshal(document)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	probe, err := jsoncanonicalizer.Transform(probeRaw)
	if err != nil || reportShapeV4(probe) != nil {
		return nil, nil, ErrUnqualified
	}
	derivedCandidate, err := canonicalCandidateV4(probe)
	if err != nil || !bytes.Equal(derivedCandidate, candidate) {
		return nil, nil, ErrUnqualified
	}
	probeFields, err := canonicalObjectV4(probe, MaxReportBytes)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	refs, err := reportRefsV4(probeFields["run_evidence"], profile)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	var ids struct {
		InstallationID string `json:"installation_id"`
		SoulID         string `json:"soul_id"`
		StartID        string `json:"start_id"`
		LaunchID       string `json:"launch_id"`
		HostID         string `json:"host_id"`
	}
	if json.Unmarshal(probeFields["measurement_binding"], &ids) != nil {
		return nil, nil, ErrUnqualified
	}
	binding, err := canonicalFieldV4(probe, "measurement_binding")
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	var recordedAt string
	if json.Unmarshal(probeFields["recorded_at"], &recordedAt) != nil {
		return nil, nil, ErrUnqualified
	}
	recorded, err := parseTime(recordedAt)
	if err != nil || completedAt.After(recorded) || recorded.After(now) {
		return nil, nil, ErrUnqualified
	}
	payload := executionCompletionV4{
		SchemaVersion: 2, Kind: "stage2a-execution-completion", ProfileInForce: profile,
		HostID: ids.HostID, InstallationID: ids.InstallationID, SoulID: ids.SoulID,
		StartID: ids.StartID, LaunchID: ids.LaunchID, CohortID: cohortID,
		ReportCandidateSHA256: digest(candidate), ReservationSHA256: refs.Reservation.SHA256,
		ChallengeSHA256: refs.ChallengeSHA256, MeasurementBindingSHA256: digest(binding),
		QFramedWireSHA256:         refs.QSession.FramedWire.SHA256,
		QFrameIndexEnvelopeSHA256: refs.QSession.FrameIndexEnvelope.SHA256,
		QCleanEOFEnvelopeSHA256:   refs.QSession.CleanEOFEnvelope.SHA256,
		CompletedAt:               completedAt.UTC().Format(time.RFC3339Nano),
	}
	if profile == "managed-protected" {
		payload.FinalizationSHA256 = refs.Finalization.SHA256
	} else {
		payload.BridgeAssignmentSHA256 = refs.BridgeAssignment.SHA256
		payload.CooperativePublishOrderSHA256 = refs.CooperativePublishOrder.SHA256
		payload.CooperativePublishOutcomeSHA256 = refs.CooperativePublishOutcome.SHA256
	}
	envelope, err := issueMachineRecordV4(payload, ExecutionCompletionPurposeV4, machineKey, sign)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	run["execution_completion"] = map[string]any{"uri": completionURI, "sha256": digest(envelope)}
	finalRaw, err := json.Marshal(document)
	if err != nil {
		return nil, nil, ErrUnqualified
	}
	report, err := jsoncanonicalizer.Transform(finalRaw)
	if err != nil || VerifyExecutionCompletionBeforeSignV4(report, envelope, machineKey, now) != nil {
		return nil, nil, ErrUnqualified
	}
	return envelope, report, nil
}

// IssueReportCommitmentV4 seals the raw host envelope only after its
// owner-designated signature and pre-sign completion have verified.
func IssueReportCommitmentV4(hostEnvelope, completionEnvelope []byte,
	policy VerifiedPolicy, committedAt time.Time, machineKey ed25519.PublicKey,
	sign MachineRecordSignerV3) ([]byte, string, error) {
	if committedAt.IsZero() {
		return nil, "", ErrUnqualified
	}
	report, err := VerifyHostReportV4(hostEnvelope, policy, committedAt)
	if err != nil || VerifyExecutionCompletionBeforeSignV4(report, completionEnvelope, machineKey, committedAt) != nil {
		return nil, "", ErrUnqualified
	}
	preRaw, err := verifyMachineRecordV4(completionEnvelope, ExecutionCompletionPurposeV4, machineKey)
	if err != nil {
		return nil, "", ErrUnqualified
	}
	var pre executionCompletionV4
	if json.Unmarshal(preRaw, &pre) != nil {
		return nil, "", ErrUnqualified
	}
	hostSignature, err := parseEnvelope(hostEnvelope, HostPurposeV4)
	if err != nil {
		return nil, "", ErrUnqualified
	}
	envelope, err := issueMachineRecordV4(reportCommitmentV4{
		SchemaVersion: 2, Kind: "stage2a-report-commitment", ProfileInForce: pre.ProfileInForce,
		HostID: pre.HostID, SignerID: hostSignature.SignerID, InstallationID: pre.InstallationID,
		SoulID: pre.SoulID, StartID: pre.StartID, LaunchID: pre.LaunchID, CohortID: pre.CohortID,
		ExecutionCompletionSHA256: digest(completionEnvelope), ReportPayloadSHA256: digest(report),
		ReportEnvelopeSHA256: digest(hostEnvelope), CommittedAt: committedAt.UTC().Format(time.RFC3339Nano),
	}, ReportCommitmentPurposeV4, machineKey, sign)
	if err != nil || VerifyCompletedRunV4(hostEnvelope, completionEnvelope, envelope, machineKey,
		digest(envelope), policy, committedAt) != nil {
		return nil, "", ErrUnqualified
	}
	return envelope, digest(envelope), nil
}
