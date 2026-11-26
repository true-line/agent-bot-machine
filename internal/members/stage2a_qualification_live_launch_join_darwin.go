//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"time"
)

// stage2aLiveLaunchWitness joins a Q case to A's already authenticated
// protected start. RelaySocket is the HQ-observed claim in A's signed B
// finalization, not an independent A observation of B's private directory.
type stage2aLiveLaunchWitness struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	SessionID               string                  `json:"session_id"`
	QChallengeSHA256        string                  `json:"q_challenge_sha256"`
	ChallengeSHA256         string                  `json:"challenge_sha256"`
	DriverRequestSHA256     string                  `json:"driver_request_sha256"`
	ChildReceiptSHA256      string                  `json:"child_receipt_sha256"`
	FinalizationSHA256      string                  `json:"finalization_sha256"`
	HelloFinalizationSHA256 string                  `json:"hello_finalization_sha256"`
	BindReceiptSHA256       string                  `json:"bind_receipt_sha256"`
	Runner                  Stage2aLiveRoleIdentity `json:"runner"`
	Bridge                  Stage2aLiveRoleIdentity `json:"bridge"`
	ChildLauncher           Stage2aLiveRoleIdentity `json:"child_launcher"`
	Child                   Stage2aLiveRoleIdentity `json:"child"`
	Executable              string                  `json:"executable"`
	ExecutableSHA256        string                  `json:"executable_sha256"`
	SandboxPath             string                  `json:"sandbox_path"`
	SandboxSHA256           string                  `json:"sandbox_sha256"`
	EnvironmentSHA256       string                  `json:"environment_sha256"`
	RelaySocket             Stage2aRelayClaim       `json:"relay_socket_claim"`
}

func stage2aLiveJoinCommand(session *stage2aQualificationSessionV1,
	command stage2aDriverCommand, requestFrame []byte) bool {
	if session == nil || session.closed || session.peer.recheck() != nil ||
		command.Schema != stage2aDriverCaseSchema || command.Kind != "capture" ||
		command.Profile != "managed-protected" || command.Phase != stage2aDriverLiveStart ||
		command.Gate != "T03" || command.Event != "direct-route-refused" ||
		command.SessionID != session.begin.SessionID ||
		command.InstallationID != session.begin.InstallationID ||
		command.StartID != session.begin.StartID ||
		command.ReservationSHA256 != session.begin.ReservationSHA256 ||
		command.TestPlanSHA256 != session.begin.TestPlanSHA256 ||
		command.Profile != session.begin.Profile ||
		!stage2aQualificationDigest(session.challengeSHA256) ||
		len(requestFrame) < 5 || int(binary.BigEndian.Uint32(requestFrame[:4])) != len(requestFrame)-4 {
		return false
	}
	schedule := stage2aDriverSchedule(command.Profile, command.Phase)
	if command.Sequence < 1 || command.Sequence > len(schedule) ||
		schedule[command.Sequence-1].Gate != command.Gate ||
		schedule[command.Sequence-1].Event != command.Event {
		return false
	}
	deadline, err := time.Parse(time.RFC3339Nano, session.begin.DeadlineAt)
	if err != nil || !time.Now().Before(deadline) {
		return false
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(command.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != command.Challenge {
		return false
	}
	canonical, err := marshalStage2aReservationJCS(command)
	return err == nil && bytes.Equal(requestFrame[4:], canonical)
}

// observeStage2aLiveLaunchJoin is A-local: the caller supplies only A's
// authenticated Q session and exact driver command, never a PID or path.
// Call before and after raw transfer and require identical canonical bytes.
// It does not establish capture descriptor provenance or a T03 verdict.
func (s *Stage2aService) observeStage2aLiveLaunchJoin(session *stage2aQualificationSessionV1,
	command stage2aDriverCommand, requestFrame []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !stage2aLiveJoinCommand(session, command, requestFrame) || len(s.key) != ed25519.PrivateKeySize {
		return nil, errStage2aReservationAuthority
	}
	r := s.active[command.ReservationSHA256]
	if r == nil || r.digest != stage2aReservationSHA256(r.envelope) ||
		r.request.InstallationID != command.InstallationID || r.request.StartID != command.StartID ||
		r.payload.Assignment.InstallationID != command.InstallationID ||
		r.payload.Assignment.StartID != command.StartID ||
		r.payload.Assignment.LaunchID == "" ||
		r.childPID <= 1 || r.childLauncherPID <= 1 || r.runnerPID <= 1 || r.bridgePID <= 1 ||
		len(r.childReceiptEnvelope) == 0 || len(r.finalizationEnvelope) == 0 ||
		r.hello == nil || len(r.hello.finalizationEnvelope) == 0 || r.bindReceiptSHA256 == "" {
		return nil, errStage2aReservationAuthority
	}
	a := r.payload.Assignment
	q := Stage2aStopRequest{ReservationSHA256: r.digest, InstallationID: a.InstallationID,
		StartID: a.StartID, LaunchID: a.LaunchID, PlanID: a.PlanID,
		PlanDigest: a.PlanDigest, HQEpoch: a.HQEpoch}
	if r.hello == nil || r.hello.aborted || !r.hello.finalized ||
		!validStage2aStopRequest(q) || !stage2aMatchesStopSelectors(r, q, a.HQUID) {
		return nil, errStage2aReservationAuthority
	}
	r, p, _, err := s.current(a.HQUID, a.HQEpoch, r.digest)
	if err != nil || p.Binding.ProfileInForce != "managed-protected" ||
		stage2aRecheckExecutionCode(r, p) != nil ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
		return nil, errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil || snapshots.check() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+slot, store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+slot+".json", store.uid, store.gid, r.finalizationEnvelope) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-child-ready-"+slot+".json", store.uid, store.gid, r.childReceiptEnvelope, 8192) != nil ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil {
		return nil, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	childRaw, childErr := verifyStage2aStoredARecordV3(r.childReceiptEnvelope, Stage2aChildStartPurpose, 1, key)
	finalRaw, finalErr := verifyStage2aStoredARecordV3(r.finalizationEnvelope, Stage2aFinalizationPurpose, 1, key)
	var child Stage2aChildStartPayload
	var final Stage2aFinalizationPayload
	if childErr != nil || finalErr != nil || json.Unmarshal(childRaw, &child) != nil ||
		json.Unmarshal(finalRaw, &final) != nil ||
		!stage2aLiveJoinRecordsMatch(q, r, child, final) {
		return nil, errStage2aReservationAuthority
	}
	w := stage2aLiveLaunchWitness{Schema: "agent-bot-machine/stage2a-live-launch-join/v1",
		Stage2aStopRequest: q, SessionID: command.SessionID,
		QChallengeSHA256:        session.challengeSHA256,
		ChallengeSHA256:         stage2aQualificationSHA256([]byte(command.Challenge)),
		DriverRequestSHA256:     stage2aQualificationSHA256(requestFrame[4:]),
		ChildReceiptSHA256:      stage2aReservationSHA256(r.childReceiptEnvelope),
		FinalizationSHA256:      stage2aReservationSHA256(r.finalizationEnvelope),
		HelloFinalizationSHA256: stage2aReservationSHA256(r.hello.finalizationEnvelope),
		BindReceiptSHA256:       r.bindReceiptSHA256,
		Runner:                  child.Runner, Bridge: child.Bridge, ChildLauncher: child.ChildLauncher, Child: child.Child,
		Executable: child.Executable, ExecutableSHA256: child.ExecutableSHA256,
		SandboxPath: child.SandboxPath, SandboxSHA256: child.SandboxSHA256,
		EnvironmentSHA256: child.EnvironmentSHA256, RelaySocket: final.RelaySocket}
	result, err := marshalStage2aReservationJCS(w)
	if err != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return nil, errStage2aReservationAuthority
	}
	return result, nil
}

func stage2aLiveJoinRecordsMatch(q Stage2aStopRequest, r *stage2aLiveReservation,
	child Stage2aChildStartPayload, final Stage2aFinalizationPayload) bool {
	return r != nil && r.hello != nil && child.Schema == "agent-bot-machine/stage2a-child-start/v1" &&
		final.Schema == "agent-bot-machine/stage2a-finalization/v1" &&
		child.Stage2aStopRequest == q && final.Stage2aStopRequest == q &&
		child.FinalizationSHA256 == stage2aReservationSHA256(r.finalizationEnvelope) &&
		child.HelloFinalizationSHA256 == stage2aReservationSHA256(r.hello.finalizationEnvelope) &&
		child.GrantSHA256 == r.childGrantSHA256 &&
		child.BindReceiptSHA256 == r.bindReceiptSHA256 && final.BindReceiptSHA256 == r.bindReceiptSHA256 &&
		child.Runner == stage2aLiveRoleIdentity(r.runnerProcess) &&
		child.Bridge == stage2aLiveRoleIdentity(r.bridgeProcess) &&
		child.ChildLauncher == stage2aLiveRoleIdentity(r.childLauncherProcess) &&
		child.Child == stage2aLiveRoleIdentity(r.childProcess) &&
		final.BridgePID == r.bridgePID && final.RelaySocket.Path == child.RelaySocket
}
