package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"
)

const stage2aDriverReceiptPurpose = "agent-bot/stage2a-owner-driver-capture/v1"

type stage2aDriverReceipt struct {
	Schema                   string                `json:"schema"`
	SessionID                string                `json:"session_id"`
	InstallationID           string                `json:"installation_id"`
	StartID                  string                `json:"start_id"`
	ReservationSHA256        string                `json:"reservation_sha256"`
	TestPlanSHA256           string                `json:"test_plan_sha256"`
	Phase                    stage2aDriverRunPhase `json:"phase"`
	Driver                   qualificationFile     `json:"driver"`
	Socket                   string                `json:"socket"`
	Argv                     []string              `json:"argv"`
	PID                      int                   `json:"pid"`
	UID                      uint32                `json:"uid"`
	GID                      uint32                `json:"gid"`
	StartSeconds             int64                 `json:"start_seconds"`
	StartMicros              int32                 `json:"start_micros"`
	QIndexSHA256             string                `json:"q_index_sha256,omitempty"`
	QEOFSHA256               string                `json:"q_eof_sha256,omitempty"`
	QWireSHA256              string                `json:"q_wire_sha256,omitempty"`
	QRequestFramesSHA256     string                `json:"q_request_frames_sha256"`
	QObservationFramesSHA256 string                `json:"q_observation_frames_sha256"`
	CaseFramesBase64URL      string                `json:"case_frames_base64url"`
	OSWitnessSHA256          []string              `json:"os_witness_sha256"`
	IssuedAt                 string                `json:"issued_at"`
}

// A signs the exact case exchange and its join to the completed independent
// Q session. This receipt commits to capture and corroboration, with no verdict.
func issueStage2aDriverReceipt(session stage2aQualificationSessionResultV1, phase stage2aDriverRunPhase,
	review stage2aDriverReview, peer stage2aQualificationDriverPeer, trace []stage2aDriverEvidence,
	now time.Time, key ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize || sign == nil {
		return nil, errStage2aReservationAuthority
	}
	receipt, err := stage2aDriverReceiptPayload(session, phase, review, peer, trace, now)
	if err != nil {
		return nil, err
	}
	return signStage2aEnvelope(receipt, 1, stage2aDriverReceiptPurpose, key, sign)
}

// Verification rejoins the signed receipt to the independently validated Q
// transcript, the exact archived frames and the expected reviewed process.
func verifyStage2aDriverReceipt(raw []byte, session stage2aQualificationSessionResultV1, phase stage2aDriverRunPhase,
	review stage2aDriverReview, peer stage2aQualificationDriverPeer, trace []stage2aDriverEvidence,
	key ed25519.PublicKey) error {
	payload, err := verifyStage2aStoredARecordV3(raw, stage2aDriverReceiptPurpose, 1, key)
	if err != nil {
		return errStage2aReservationAuthority
	}
	var received stage2aDriverReceipt
	if json.Unmarshal(payload, &received) != nil {
		return errStage2aReservationAuthority
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, received.IssuedAt)
	if err != nil {
		return errStage2aReservationAuthority
	}
	expected, err := stage2aDriverReceiptPayload(session, phase, review, peer, trace, issuedAt)
	if err != nil {
		return errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(expected)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aDriverReceiptPayload(session stage2aQualificationSessionResultV1, phase stage2aDriverRunPhase,
	review stage2aDriverReview, peer stage2aQualificationDriverPeer, trace []stage2aDriverEvidence,
	now time.Time) (stage2aDriverReceipt, error) {
	kernel := peer.kernel
	if review.Schema != stage2aDriverCaseSchema || review.testPlanSHA256 != session.begin.TestPlanSHA256 ||
		review.Executable.Path != peer.execPath ||
		!qualificationDigest.MatchString(review.Executable.SHA256) || !slices.Equal(review.Argv, peer.argv) ||
		kernel.EffectiveUID == 0 || kernel.EffectiveUID == uint32(session.peer.uid) ||
		!stage2aQualificationKernelMatches(kernel, peer.pid, int(kernel.EffectiveUID), int(kernel.PrimaryGroupGID)) ||
		kernel.StartMicros < 0 || kernel.StartMicros >= 1_000_000 || now.Before(session.eofObservedAt) ||
		now.After(session.eofObservedAt.Add(30*time.Second)) {
		return stage2aDriverReceipt{}, errStage2aReservationAuthority
	}
	frames, err := joinStage2aDriverFrames(session, phase, trace)
	if err != nil {
		return stage2aDriverReceipt{}, err
	}
	begin := session.begin
	witnesses := make([]string, 0, len(trace))
	for _, pair := range trace {
		witnesses = append(witnesses, stage2aQualificationSHA256(pair.osWitness))
	}
	return stage2aDriverReceipt{
		Schema: stage2aDriverCaseSchema, SessionID: begin.SessionID, ReservationSHA256: begin.ReservationSHA256,
		InstallationID: begin.InstallationID, StartID: begin.StartID, TestPlanSHA256: begin.TestPlanSHA256,
		Phase: phase, Driver: review.Executable, Socket: review.Socket, Argv: review.Argv,
		PID: peer.pid, UID: kernel.EffectiveUID, GID: kernel.PrimaryGroupGID,
		StartSeconds: kernel.StartSeconds, StartMicros: kernel.StartMicros,
		QRequestFramesSHA256: session.requestsSHA256, QObservationFramesSHA256: session.observationsSHA256,
		CaseFramesBase64URL: base64.RawURLEncoding.EncodeToString(frames), OSWitnessSHA256: witnesses, IssuedAt: now.UTC().Format(time.RFC3339Nano),
	}, nil
}

func joinStage2aDriverFrames(session stage2aQualificationSessionResultV1, phase stage2aDriverRunPhase,
	trace []stage2aDriverEvidence) ([]byte, error) {
	begin := session.begin
	schedule := stage2aDriverSchedule(begin.Profile, phase)
	if len(schedule) == 0 || len(schedule) != len(trace) || verifyStage2aQualificationPairedFramesV1(session) != nil {
		return nil, errStage2aReservationAuthority
	}
	requests := bytes.NewReader(session.requestFrames)
	challenges := make(map[string]bool, len(schedule))
	artifacts := make(map[string]bool, len(schedule))
	var wire bytes.Buffer
	for i, step := range schedule {
		pair := trace[i]
		commandReader, responseReader := bytes.NewReader(pair.request), bytes.NewReader(pair.response)
		raw, commandErr := readStage2aQualificationFrame(commandReader)
		response, responseErr := readStage2aQualificationFrame(responseReader)
		if commandErr != nil || responseErr != nil || commandReader.Len() != 0 || responseReader.Len() != 0 {
			return nil, errStage2aReservationAuthority
		}
		command, err := parseStage2aDriverCommand(raw, begin, phase, i+1, step)
		if err != nil || challenges[command.Challenge] {
			return nil, errStage2aReservationAuthority
		}
		challenges[command.Challenge] = true
		capture, err := parseStage2aDriverResponse(response, raw)
		corroboration := stage2aDriverCorroboration{artifact: pair.artifact, osWitness: pair.osWitness}
		if err != nil || artifacts[capture.ArtifactSHA] || !corroboration.matches(capture.ArtifactSHA) {
			return nil, errStage2aReservationAuthority
		}
		artifacts[capture.ArtifactSHA] = true
		probe, err := readStage2aDriverPhaseProbe(requests, phase)
		if err != nil || probe.Gate != step.Gate || probe.EventID != step.Event ||
			probe.StimulusRef == nil || probe.StimulusRef.SHA256 != capture.ArtifactSHA ||
			probe.StimulusRef.URI != stage2aDriverStimulusURI(begin.SessionID, step.Event) {
			return nil, errStage2aReservationAuthority
		}
		wire.Write(pair.request)
		wire.Write(pair.response)
	}
	if _, err := readStage2aDriverPhaseProbe(requests, phase); err == nil || wire.Len() > 24<<10 {
		return nil, errStage2aReservationAuthority
	}
	return wire.Bytes(), nil
}

func readStage2aDriverPhaseProbe(requests *bytes.Reader, phase stage2aDriverRunPhase) (stage2aQualificationObserveV1, error) {
	for requests.Len() != 0 {
		var probe stage2aQualificationObserveV1
		raw, err := readStage2aQualificationFrame(requests)
		if err != nil || json.Unmarshal(raw, &probe) != nil {
			break
		}
		if probe.Phase == string(phase) {
			return probe, nil
		}
	}
	return stage2aQualificationObserveV1{}, errStage2aReservationAuthority
}

func stage2aDriverStimulusURI(sessionID, event string) string {
	return "urn:stage2a:owner-driver:" + sessionID + ":" + event
}
