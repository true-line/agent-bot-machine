//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"
)

const (
	stage2aQualificationIndexPurposeV1 = "agent-bot/stage2a-q-frame-index/v1"
	stage2aQualificationEOFPurposeV1   = "agent-bot/stage2a-q-finished-eof/v1"
)

// The wire object carries the actual framed bytes, not a re-encoded version
// of Q's JSON. Its digest is signed before the host report can be requested.
type stage2aQualificationWireV1 struct {
	Schema                     string `json:"schema"`
	Kind                       string `json:"kind"`
	SessionID                  string `json:"session_id"`
	BeginFrameBase64URL        string `json:"begin_frame_base64url"`
	ReadyFrameBase64URL        string `json:"ready_frame_base64url"`
	RequestFramesBase64URL     string `json:"request_frames_base64url"`
	ObservationFramesBase64URL string `json:"observation_frames_base64url"`
	FinishRequestBase64URL     string `json:"finish_request_frame_base64url"`
	FinishedFrameBase64URL     string `json:"finished_frame_base64url"`
}

type stage2aQualificationPreSignIndexV1 struct {
	Schema                   string   `json:"schema"`
	Kind                     string   `json:"kind"`
	CohortID                 string   `json:"cohort_id"`
	InstallationID           string   `json:"installation_id"`
	SoulID                   string   `json:"soul_id"`
	StartID                  string   `json:"start_id"`
	HostID                   string   `json:"host_id"`
	Profile                  string   `json:"profile"`
	ReservationSHA256        string   `json:"reservation_sha256"`
	SessionID                string   `json:"session_id"`
	QChallengeSHA256         string   `json:"q_challenge_sha256"`
	LaunchChallengeSHA256    string   `json:"launch_challenge_sha256"`
	QSourceSHA256            string   `json:"q_source_sha256"`
	TestPlanSHA256           string   `json:"test_plan_sha256"`
	QSocketPath              string   `json:"q_socket_path"`
	QSocketDevice            uint64   `json:"q_socket_device"`
	QSocketInode             uint64   `json:"q_socket_inode"`
	QSocketBirthSeconds      int64    `json:"q_socket_birth_seconds"`
	QSocketBirthNanos        int64    `json:"q_socket_birth_nanos"`
	QPID                     int      `json:"q_pid"`
	QUID                     int      `json:"q_uid"`
	QGID                     int      `json:"q_gid"`
	QParentPID               int      `json:"q_parent_pid"`
	QProcessGroupID          int      `json:"q_process_group_id"`
	QStartSeconds            int64    `json:"q_start_seconds"`
	QStartMicros             int32    `json:"q_start_micros"`
	QExecutable              string   `json:"q_executable"`
	QArgv                    []string `json:"q_argv"`
	WireSHA256               string   `json:"wire_sha256"`
	OrderedFramesSHA256      string   `json:"ordered_frames_sha256"`
	BeginFrameSHA256         string   `json:"begin_frame_sha256"`
	ReadyFrameSHA256         string   `json:"ready_frame_sha256"`
	RequestFramesSHA256      string   `json:"request_frames_sha256"`
	ObservationFramesSHA256  string   `json:"observation_frames_sha256"`
	FinishRequestFrameSHA256 string   `json:"finish_request_frame_sha256"`
	FinishedFrameSHA256      string   `json:"finished_frame_sha256"`
	ObservationCount         int      `json:"observation_count"`
	IssuedAt                 string   `json:"issued_at"`
}

type stage2aQualificationEOFReceiptV1 struct {
	Schema              string `json:"schema"`
	Kind                string `json:"kind"`
	SessionID           string `json:"session_id"`
	IndexEnvelopeSHA256 string `json:"index_envelope_sha256"`
	WireSHA256          string `json:"wire_sha256"`
	FinishedFrameSHA256 string `json:"finished_frame_sha256"`
	ObservationCount    int    `json:"observation_count"`
	CleanEOFObserved    bool   `json:"clean_eof_observed"`
	NoTrailingBytes     bool   `json:"no_trailing_bytes"`
	EOFObservedAt       string `json:"eof_observed_at"`
	IssuedAt            string `json:"issued_at"`
}

type stage2aQualificationPreSignArtifactsV1 struct {
	WirePath, WireSHA256             string
	IndexPath, IndexSHA256           string
	EOFReceiptPath, EOFReceiptSHA256 string
	DriverPath, DriverSHA256         string
}

// issueStage2aQualificationPreSignV1 prepares two distinct A-signed records
// after the authenticated Q session has finished. The caller must durably
// publish the wire object and both envelopes, bind their digests into a
// segment, and finish that work before requesting keyd's host signature.
// There is no production caller or positive physical-gate verifier yet.
func issueStage2aQualificationPreSignV1(session stage2aQualificationSessionResultV1,
	launchChallengeSHA256 string, now time.Time, machineKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (wire, index, eofReceipt []byte, err error) {
	p := session.peer
	if verifyStage2aQualificationPairedFramesV1(session) != nil ||
		!validStage2aQualificationBeginV1(session.begin, now) ||
		!stage2aQualificationKernelMatches(p.kernel, p.pid, p.uid, p.gid) ||
		p.kernel.ProcessGroupID <= 0 || p.kernel.StartMicros < 0 || p.kernel.StartMicros >= 1_000_000 ||
		p.executable == "" || len(p.argv) < 3 || p.argv[0] != p.executable ||
		validateSoulExpectedArguments(p.executable, p.argv) != nil ||
		!stage2aAbsolutePath(p.socketPath) || filepath.Clean(p.socketPath) != p.socketPath ||
		p.socketDev == 0 || p.socketInode == 0 || p.socketBirthSeconds <= 0 ||
		p.socketBirthNanos < 0 || p.socketBirthNanos >= 1_000_000_000 ||
		!stage2aQualificationDigest(launchChallengeSHA256) ||
		launchChallengeSHA256 == session.challengeSHA256 ||
		len(machineKey) != ed25519.PublicKeySize || sign == nil || now.IsZero() ||
		now.Before(session.eofObservedAt) || now.After(session.eofObservedAt.Add(30*time.Second)) {
		return nil, nil, nil, errStage2aReservationAuthority
	}
	var ordered bytes.Buffer
	ordered.Write(session.beginFrame)
	ordered.Write(session.readyFrame)
	requests := bytes.NewReader(session.requestFrames)
	observations := bytes.NewReader(session.observationFrames)
	for i := 0; i < session.count; i++ {
		_, request, requestErr := readStage2aQualificationObservedFrame(requests)
		_, observation, observationErr := readStage2aQualificationObservedFrame(observations)
		if requestErr != nil || observationErr != nil {
			return nil, nil, nil, errStage2aReservationAuthority
		}
		ordered.Write(request)
		ordered.Write(observation)
	}
	if requests.Len() != 0 || observations.Len() != 0 {
		return nil, nil, nil, errStage2aReservationAuthority
	}
	ordered.Write(session.finishRequestFrame)
	ordered.Write(session.finishedFrame)
	w := stage2aQualificationWireV1{
		Schema: stage2aQualificationSchemaV1, Kind: "framed-wire", SessionID: session.begin.SessionID,
		BeginFrameBase64URL:        base64.RawURLEncoding.EncodeToString(session.beginFrame),
		ReadyFrameBase64URL:        base64.RawURLEncoding.EncodeToString(session.readyFrame),
		RequestFramesBase64URL:     base64.RawURLEncoding.EncodeToString(session.requestFrames),
		ObservationFramesBase64URL: base64.RawURLEncoding.EncodeToString(session.observationFrames),
		FinishRequestBase64URL:     base64.RawURLEncoding.EncodeToString(session.finishRequestFrame),
		FinishedFrameBase64URL:     base64.RawURLEncoding.EncodeToString(session.finishedFrame),
	}
	wire, err = marshalStage2aReservationJCS(w)
	if err != nil || len(wire) > 32<<20 {
		return nil, nil, nil, errStage2aReservationAuthority
	}
	idx := stage2aQualificationPreSignIndexV1{
		Schema: stage2aQualificationSchemaV1, Kind: "pre-sign-index",
		CohortID: session.begin.CohortID, InstallationID: session.begin.InstallationID,
		SoulID: session.begin.SoulID, StartID: session.begin.StartID, HostID: session.begin.HostID,
		Profile: session.begin.Profile, ReservationSHA256: session.begin.ReservationSHA256,
		SessionID: session.begin.SessionID, QChallengeSHA256: session.challengeSHA256,
		LaunchChallengeSHA256: launchChallengeSHA256, QSourceSHA256: session.sourceSHA256,
		TestPlanSHA256: session.begin.TestPlanSHA256, QSocketPath: p.socketPath,
		QSocketDevice: p.socketDev, QSocketInode: p.socketInode,
		QSocketBirthSeconds: p.socketBirthSeconds, QSocketBirthNanos: p.socketBirthNanos,
		QPID: p.pid, QUID: p.uid, QGID: p.gid, QParentPID: p.kernel.ParentPID,
		QProcessGroupID: p.kernel.ProcessGroupID, QStartSeconds: p.kernel.StartSeconds,
		QStartMicros: p.kernel.StartMicros, QExecutable: p.executable, QArgv: append([]string(nil), p.argv...),
		WireSHA256:               stage2aQualificationSHA256(wire),
		OrderedFramesSHA256:      stage2aQualificationSHA256(ordered.Bytes()),
		BeginFrameSHA256:         stage2aQualificationSHA256(session.beginFrame),
		ReadyFrameSHA256:         stage2aQualificationSHA256(session.readyFrame),
		RequestFramesSHA256:      session.requestsSHA256,
		ObservationFramesSHA256:  session.observationsSHA256,
		FinishRequestFrameSHA256: stage2aQualificationSHA256(session.finishRequestFrame),
		FinishedFrameSHA256:      stage2aQualificationSHA256(session.finishedFrame),
		ObservationCount:         session.count, IssuedAt: now.UTC().Format(time.RFC3339Nano),
	}
	index, err = signStage2aEnvelope(idx, 1, stage2aQualificationIndexPurposeV1, machineKey, sign)
	if err != nil || len(index) > 64<<10 {
		return nil, nil, nil, errStage2aReservationAuthority
	}
	receipt := stage2aQualificationEOFReceiptV1{
		Schema: stage2aQualificationSchemaV1, Kind: "finished-clean-eof",
		SessionID: session.begin.SessionID, IndexEnvelopeSHA256: stage2aQualificationSHA256(index),
		WireSHA256: idx.WireSHA256, FinishedFrameSHA256: idx.FinishedFrameSHA256,
		ObservationCount: session.count, CleanEOFObserved: true, NoTrailingBytes: true,
		EOFObservedAt: session.eofObservedAt.UTC().Format(time.RFC3339Nano),
		IssuedAt:      now.UTC().Format(time.RFC3339Nano),
	}
	eofReceipt, err = signStage2aEnvelope(receipt, 1, stage2aQualificationEOFPurposeV1, machineKey, sign)
	if err != nil || len(eofReceipt) > 64<<10 {
		return nil, nil, nil, errStage2aReservationAuthority
	}
	return wire, index, eofReceipt, nil
}

// The EOF receipt is published last. A crash or refused write can leave only
// earlier immutable objects; it never publishes a complete Q session. The
// future A host-report caller must consume these exact digests before signing.
func persistStage2aQualificationPreSignV1(store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1, reservation []byte,
	launchChallengeSHA256 string, now time.Time, machineKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (stage2aQualificationPreSignArtifactsV1, error) {
	var empty stage2aQualificationPreSignArtifactsV1
	if session.peer.uid == int(store.uid) || session.begin.ReservationSHA256 != stage2aQualificationSHA256(reservation) {
		return empty, errStage2aReservationAuthority
	}
	payload, err := verifyStage2aStoredARecordV3(reservation, stage2aAdminReservationPurpose, 2, machineKey)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	var reserved stage2aReservationPayload
	if json.Unmarshal(payload, &reserved) != nil ||
		launchChallengeSHA256 != reserved.AdmissionChallengeSHA256 ||
		reserved.Assignment.InstallationID != session.begin.InstallationID ||
		reserved.Assignment.StartID != session.begin.StartID ||
		reserved.Assignment.SoulID != session.begin.SoulID ||
		reserved.MeasurementBinding.InstallationID != session.begin.InstallationID ||
		reserved.MeasurementBinding.StartID != session.begin.StartID ||
		reserved.MeasurementBinding.SoulID != session.begin.SoulID ||
		reserved.MeasurementBinding.HostID != session.begin.HostID ||
		reserved.MeasurementBinding.ProfileInForce != session.begin.Profile {
		return empty, errStage2aReservationAuthority
	}
	return publishStage2aQualificationPreSign(store, session, reservation, launchChallengeSHA256, now, machineKey, sign)
}

func publishStage2aQualificationPreSign(store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1, reservation []byte,
	launchChallengeSHA256 string, now time.Time, machineKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (stage2aQualificationPreSignArtifactsV1, error) {
	return publishStage2aQualificationPreSignWithDriver(store, session, reservation, launchChallengeSHA256, now, machineKey, sign, nil)
}

func publishStage2aQualificationPreSignWithDriver(store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1, reservation []byte,
	launchChallengeSHA256 string, now time.Time, machineKey ed25519.PublicKey,
	sign func([]byte) ([]byte, error), driver *stage2aDriverPhaseCapture) (stage2aQualificationPreSignArtifactsV1, error) {
	var empty stage2aQualificationPreSignArtifactsV1
	dir, err := store.open()
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, session.begin.InstallationID)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(session.begin.InstallationID, session.begin.StartID)
	if store.checkDirectory(dir) != nil ||
		checkStage2aQualificationSessionBinding(dir, store, session) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-admin-envelope-"+slot,
			store.uid, store.gid, reservation, 64<<10) != nil {
		return empty, errStage2aReservationAuthority
	}
	if driver != nil && driver.phase == stage2aDriverProtectedT03Run &&
		(stage2aCheckSpentClaim(dir, stage2aActiveClaimName(session.begin.InstallationID), store.uid, store.gid) != nil ||
			requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil) {
		return empty, errStage2aReservationAuthority
	}
	wire, index, eofReceipt, err := issueStage2aQualificationPreSignV1(session,
		launchChallengeSHA256, now, machineKey, sign)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	prefix := ".stage2a-q-" + slot + "-" + session.begin.SessionID
	result := stage2aQualificationPreSignArtifactsV1{
		WirePath:         filepath.Join(store.path, prefix+"-wire.json"),
		WireSHA256:       stage2aQualificationSHA256(wire),
		IndexPath:        filepath.Join(store.path, prefix+"-index.json"),
		IndexSHA256:      stage2aQualificationSHA256(index),
		EOFReceiptPath:   filepath.Join(store.path, prefix+"-eof.json"),
		EOFReceiptSHA256: stage2aQualificationSHA256(eofReceipt),
	}
	var driverArchive []byte
	if driver != nil {
		driverArchive, err = marshalStage2aDriverArchive(*driver, session, result, now, machineKey, sign)
		if err != nil {
			return empty, errStage2aReservationAuthority
		}
		result.DriverPath = filepath.Join(store.path, prefix+"-driver.json")
		result.DriverSHA256 = stage2aQualificationSHA256(driverArchive)
	}
	if commitStage2aReservation(dir, filepath.Base(result.WirePath), wire) != nil ||
		commitStage2aReservation(dir, filepath.Base(result.IndexPath), index) != nil ||
		(driver != nil && commitStage2aReservation(dir, filepath.Base(result.DriverPath), driverArchive) != nil) ||
		commitStage2aReservation(dir, filepath.Base(result.EOFReceiptPath), eofReceipt) != nil {
		return empty, errStage2aReservationAuthority
	}
	return result, nil
}
