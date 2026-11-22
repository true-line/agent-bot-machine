//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/qwts/managed-machine/internal/qualification"
	"golang.org/x/sys/unix"
)

func verifyStage2aStoredARecordV3(raw []byte, purpose string, version int, key ed25519.PublicKey) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || len(key) != ed25519.PublicKeySize || stage2aStrictJSON(raw) != nil {
		return nil, errStage2aReservationAuthority
	}
	var fields map[string]json.RawMessage
	var envelope stage2aSignedReservation
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 || json.Unmarshal(raw, &envelope) != nil ||
		envelope.SchemaVersion != version || envelope.Purpose != purpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(key) {
		return nil, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errStage2aReservationAuthority
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || len(payload) == 0 || len(payload) > 48<<10 ||
		base64.RawURLEncoding.EncodeToString(payload) != envelope.PayloadBase64URL ||
		stage2aReservationSHA256(payload) != envelope.PayloadSHA256 || stage2aStrictJSON(payload) != nil {
		return nil, errStage2aReservationAuthority
	}
	payloadCanonical, err := marshalStage2aReservationJCS(json.RawMessage(payload))
	if err != nil || !bytes.Equal(payloadCanonical, payload) {
		return nil, errStage2aReservationAuthority
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, append([]byte(purpose+"\x00"), payload...), signature) {
		return nil, errStage2aReservationAuthority
	}
	return payload, nil
}

// stage2aQualificationBundleV1 is one A-owned atomic file. The signed pre
// record, host envelope and signed post record remain distinct byte strings
// inside it; a partial write or crash cannot expose a completed bundle.
// A later offline verifier resolves each exact digest from this file.
type stage2aQualificationBundleV1 struct {
	SchemaVersion                        int    `json:"schema_version"`
	Kind                                 string `json:"kind"`
	InstallationID                       string `json:"installation_id"`
	StartID                              string `json:"start_id"`
	SessionID                            string `json:"session_id"`
	BeginFrameBase64URL                  string `json:"begin_frame_base64url"`
	ReadyFrameBase64URL                  string `json:"ready_frame_base64url"`
	FinishRequestFrameBase64URL          string `json:"finish_request_frame_base64url"`
	FinishedFrameBase64URL               string `json:"finished_frame_base64url"`
	CleanEOFObserved                     bool   `json:"clean_eof_observed"`
	EOFObservedAt                        string `json:"eof_observed_at"`
	QSourceSHA256                        string `json:"q_source_sha256"`
	QUID                                 int    `json:"q_uid"`
	QGID                                 int    `json:"q_gid"`
	TestPlanSHA256                       string `json:"test_plan_sha256"`
	RequestsSHA256                       string `json:"requests_sha256"`
	RequestsBase64URL                    string `json:"requests_base64url"`
	ObservationsSHA256                   string `json:"observations_sha256"`
	ObservationsBase64URL                string `json:"observations_base64url"`
	ReservationEnvelopeBase64URL         string `json:"reservation_envelope_base64url"`
	FinalizationEnvelopeBase64URL        string `json:"finalization_envelope_base64url"`
	StopEnvelopeBase64URL                string `json:"stop_envelope_base64url"`
	ExecutionCompletionEnvelopeBase64URL string `json:"execution_completion_envelope_base64url"`
	HostReportEnvelopeBase64URL          string `json:"host_report_envelope_base64url"`
	ReportCommitmentEnvelopeBase64URL    string `json:"report_commitment_envelope_base64url"`
}

func stage2aQualificationTranscriptV1(raw []byte, sessionID, challengeSHA string) (int, error) {
	if len(raw) == 0 || len(raw) > 128*(stage2aQualificationFrameMax+4) ||
		len(sessionID) != 32 || !stage2aQualificationHex(sessionID) || !stage2aQualificationDigest(challengeSHA) {
		return 0, errStage2aReservationAuthority
	}
	reader := bytes.NewReader(raw)
	count := 0
	lastSequence := 0
	for reader.Len() > 0 {
		if reader.Len() < 4 {
			return 0, errStage2aReservationAuthority
		}
		var header [4]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return 0, errStage2aReservationAuthority
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 || length > stage2aQualificationFrameMax || int(length) > reader.Len() || count >= 128 {
			return 0, errStage2aReservationAuthority
		}
		frame := make([]byte, length)
		if _, err := io.ReadFull(reader, frame); err != nil || stage2aQualificationCanonical(frame) != nil {
			return 0, errStage2aReservationAuthority
		}
		var fields map[string]json.RawMessage
		var envelope struct {
			Schema          string `json:"schema"`
			Kind            string `json:"kind"`
			SessionID       string `json:"session_id"`
			ChallengeSHA256 string `json:"challenge_sha256"`
			Sequence        int    `json:"sequence"`
			RequestSHA256   string `json:"request_sha256"`
			CapturedAt      string `json:"captured_at"`
			Gate            string `json:"gate"`
		}
		if json.Unmarshal(frame, &fields) != nil || json.Unmarshal(frame, &envelope) != nil ||
			envelope.Schema != stage2aQualificationSchemaV1 || envelope.Kind != "observation" ||
			envelope.SessionID != sessionID || envelope.ChallengeSHA256 != challengeSHA ||
			envelope.Sequence <= lastSequence || envelope.Sequence > 1024 ||
			!stage2aQualificationDigest(envelope.RequestSHA256) ||
			!stage2aQualificationTimestampV1.MatchString(envelope.CapturedAt) ||
			(envelope.Gate != "T01" && envelope.Gate != "T02" && envelope.Gate != "T03" && envelope.Gate != "T21") ||
			(len(fields) != 12 && len(fields) != 13) {
			return 0, errStage2aReservationAuthority
		}
		for _, key := range []string{"schema", "kind", "session_id", "challenge_sha256", "sequence", "request_sha256", "captured_at", "gate", "phase", "event_id", "processes", "paths"} {
			if fields[key] == nil {
				return 0, errStage2aReservationAuthority
			}
		}
		if len(fields) == 13 && fields["stimulus_ref"] == nil {
			return 0, errStage2aReservationAuthority
		}
		lastSequence = envelope.Sequence
		count++
	}
	return count, nil
}

func stage2aExactAdminRecord(dir *os.File, name string, uid, gid uint32, expected []byte, maximum int64) error {
	if len(expected) == 0 || int64(len(expected)) > maximum {
		return errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return errStage2aReservationAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600) != nil ||
		checkDarwinACLs([]string{filepath.Join(dir.Name(), name)}) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil || !bytes.Equal(raw, expected) {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aQualificationStopBindsInstalled(installed Stage2aMeasurementBinding, q Stage2aStopRequest) bool {
	return installed.InstallationID == q.InstallationID && installed.StartID == q.StartID &&
		installed.LaunchID == q.LaunchID && installed.PlanID == q.PlanID &&
		installed.InstalledPlanDigest == q.PlanDigest && installed.HQEpoch == q.HQEpoch
}

func stage2aQualificationSessionBindsRun(session stage2aQualificationSessionResultV1,
	q Stage2aStopRequest, installed Stage2aMeasurementBinding, expectedQSourceSHA256,
	expectedTestPlanSHA256, expectedCohortID string, expectedPathRoots []string,
	expectedQUID, expectedQGID int) bool {
	return stage2aQualificationDigest(expectedQSourceSHA256) && session.sourceSHA256 == expectedQSourceSHA256 &&
		stage2aQualificationDigest(expectedTestPlanSHA256) && session.begin.TestPlanSHA256 == expectedTestPlanSHA256 &&
		stage2aQualificationPrintable(expectedCohortID, 128) && session.begin.CohortID == expectedCohortID &&
		len(expectedPathRoots) > 0 && reflect.DeepEqual(session.begin.PathRoots, expectedPathRoots) &&
		session.begin.ReservationSHA256 == q.ReservationSHA256 &&
		session.begin.InstallationID == q.InstallationID && session.begin.StartID == q.StartID &&
		session.begin.SoulID == installed.SoulID && session.begin.HostID == installed.HostID &&
		session.begin.Profile == installed.ProfileInForce &&
		session.peer.uid == expectedQUID && session.peer.gid == expectedQGID &&
		session.begin.QUID == expectedQUID && session.begin.QGID == expectedQGID &&
		expectedQUID > 399 && expectedQGID > 0
}

func verifyStage2aQualificationARecordChainV3(q Stage2aStopRequest, installed Stage2aMeasurementBinding,
	reservation, finalization, stop []byte, machineKey ed25519.PublicKey) error {
	if !validStage2aStopRequest(q) || len(machineKey) != ed25519.PublicKeySize {
		return errStage2aReservationAuthority
	}
	reservationPayload, reservationErr := verifyStage2aStoredARecordV3(reservation, stage2aAdminReservationPurpose, 2, machineKey)
	finalizationPayload, finalizationErr := verifyStage2aStoredARecordV3(finalization, Stage2aFinalizationPurpose, 1, machineKey)
	stopPayload, stopErr := verifyStage2aStoredARecordV3(stop, Stage2aStopPurpose, 1, machineKey)
	if reservationErr != nil || finalizationErr != nil || stopErr != nil {
		return errStage2aReservationAuthority
	}
	var reserved stage2aReservationPayload
	var finalized Stage2aFinalizationPayload
	var stopped Stage2aStopPayload
	if json.Unmarshal(reservationPayload, &reserved) != nil || json.Unmarshal(finalizationPayload, &finalized) != nil ||
		json.Unmarshal(stopPayload, &stopped) != nil ||
		q.ReservationSHA256 != stage2aQualificationSHA256(reservation) ||
		reserved.Assignment.InstallationID != q.InstallationID || reserved.Assignment.StartID != q.StartID ||
		reserved.Assignment.LaunchID != q.LaunchID || reserved.Assignment.PlanID != q.PlanID ||
		reserved.Assignment.PlanDigest != q.PlanDigest || reserved.Assignment.HQEpoch != q.HQEpoch ||
		!reflect.DeepEqual(reserved.MeasurementBinding, installed) ||
		!reflect.DeepEqual(finalized.Stage2aStopRequest, q) ||
		stopped.ReservationSHA256 != q.ReservationSHA256 || stopped.InstallationID != q.InstallationID ||
		stopped.StartID != q.StartID || stopped.LaunchID != q.LaunchID ||
		stopped.PlanID != q.PlanID || stopped.PlanDigest != q.PlanDigest ||
		stopped.HQEpoch != q.HQEpoch || !stopped.BothUIDsIdle {
		return errStage2aReservationAuthority
	}
	return nil
}

// persistStage2aQualificationBundleV3 is an A-only durable sink after the
// independent Q session and physical corroboration. It verifies the exact
// signed chain, installed-plan binding and A-owned reservation/final/stop
// files before publishing one immutable file. This helper does not itself
// decide that Q's observations prove T01/T02/T03/T21; no positive call site
// exists until the authenticated physical observer is integrated.
func persistStage2aQualificationBundleV3(store stage2aAdminClaimStore, q Stage2aStopRequest,
	installed Stage2aMeasurementBinding, session stage2aQualificationSessionResultV1,
	expectedQSourceSHA256, expectedTestPlanSHA256, expectedCohortID string,
	expectedPathRoots []string, expectedQUID, expectedQGID int,
	reservation, finalization, stop, pre, host, post []byte,
	policy qualification.VerifiedPolicy, machineKey ed25519.PublicKey, now time.Time) (string, string, error) {
	if !validStage2aStopRequest(q) || verifyStage2aQualificationPairedFramesV1(session) != nil ||
		!stage2aQualificationSessionBindsRun(session, q, installed, expectedQSourceSHA256,
			expectedTestPlanSHA256, expectedCohortID, expectedPathRoots, expectedQUID, expectedQGID) ||
		expectedQUID == int(store.uid) ||
		len(machineKey) != ed25519.PublicKeySize || now.IsZero() ||
		qualification.VerifyCompletedRunV3(host, pre, post, machineKey, stage2aQualificationSHA256(post), policy, now) != nil {
		return "", "", errStage2aReservationAuthority
	}
	if verifyStage2aQualificationARecordChainV3(q, installed, reservation, finalization, stop, machineKey) != nil {
		return "", "", errStage2aReservationAuthority
	}
	if count, err := stage2aQualificationTranscriptV1(session.observationFrames,
		session.begin.SessionID, session.challengeSHA256); err != nil || count != session.count {
		return "", "", errStage2aReservationAuthority
	}
	report, err := qualification.VerifyHostReportV3(host, policy, now)
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	var document struct {
		MeasurementBinding Stage2aMeasurementBinding `json:"measurement_binding"`
		ProfileInForce     string                    `json:"profile_in_force"`
		RunEvidence        struct {
			Reservation struct {
				SHA256 string `json:"sha256"`
			} `json:"reservation"`
			Finalization struct {
				SHA256 string `json:"sha256"`
			} `json:"finalization"`
			ExecutionCompletion struct {
				SHA256 string `json:"sha256"`
			} `json:"execution_completion"`
		} `json:"run_evidence"`
	}
	if json.Unmarshal(report, &document) != nil || !reflect.DeepEqual(document.MeasurementBinding, installed) ||
		document.ProfileInForce != session.begin.Profile ||
		!stage2aQualificationStopBindsInstalled(installed, q) ||
		document.RunEvidence.Reservation.SHA256 != stage2aQualificationSHA256(reservation) ||
		document.RunEvidence.Finalization.SHA256 != stage2aQualificationSHA256(finalization) ||
		document.RunEvidence.ExecutionCompletion.SHA256 != stage2aQualificationSHA256(pre) {
		return "", "", errStage2aReservationAuthority
	}
	dir, err := store.open()
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-closed-"+slot, store.uid, store.gid) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-admin-envelope-"+slot, store.uid, store.gid, reservation, 64<<10) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-b-final-"+slot+".json", store.uid, store.gid, finalization, 64<<10) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-stop-"+slot+".json", store.uid, store.gid, stop, 64<<10) != nil {
		return "", "", errStage2aReservationAuthority
	}
	bundle, err := marshalStage2aReservationJCS(stage2aQualificationBundleV1{
		SchemaVersion: 1, Kind: "stage2a-qualification-bundle", InstallationID: q.InstallationID,
		StartID: q.StartID, SessionID: session.begin.SessionID,
		BeginFrameBase64URL:         base64.RawURLEncoding.EncodeToString(session.beginFrame),
		ReadyFrameBase64URL:         base64.RawURLEncoding.EncodeToString(session.readyFrame),
		FinishRequestFrameBase64URL: base64.RawURLEncoding.EncodeToString(session.finishRequestFrame),
		FinishedFrameBase64URL:      base64.RawURLEncoding.EncodeToString(session.finishedFrame),
		CleanEOFObserved:            session.cleanEOFObserved,
		EOFObservedAt:               session.eofObservedAt.UTC().Format(time.RFC3339Nano),
		QSourceSHA256:               session.sourceSHA256, QUID: session.peer.uid, QGID: session.peer.gid,
		TestPlanSHA256:                       expectedTestPlanSHA256,
		RequestsSHA256:                       session.requestsSHA256,
		RequestsBase64URL:                    base64.RawURLEncoding.EncodeToString(session.requestFrames),
		ObservationsSHA256:                   session.observationsSHA256,
		ObservationsBase64URL:                base64.RawURLEncoding.EncodeToString(session.observationFrames),
		ReservationEnvelopeBase64URL:         base64.RawURLEncoding.EncodeToString(reservation),
		FinalizationEnvelopeBase64URL:        base64.RawURLEncoding.EncodeToString(finalization),
		StopEnvelopeBase64URL:                base64.RawURLEncoding.EncodeToString(stop),
		ExecutionCompletionEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(pre),
		HostReportEnvelopeBase64URL:          base64.RawURLEncoding.EncodeToString(host),
		ReportCommitmentEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(post),
	})
	if err != nil {
		return "", "", errStage2aReservationAuthority
	}
	name := ".stage2a-qualification-" + slot + ".json"
	if commitStage2aReservation(dir, name, bundle) != nil {
		return "", "", errStage2aReservationAuthority
	}
	return filepath.Join(store.path, name), stage2aQualificationSHA256(bundle), nil
}
