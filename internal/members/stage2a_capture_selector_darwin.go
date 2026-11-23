//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"
)

func (s *Stage2aService) CaptureSelector(hqUID int, epoch string,
	q Stage2aCaptureSelectorRequest) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validStage2aStopRequest(q.Stage2aStopRequest) || epoch != q.HQEpoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return nil, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.protectedQ == nil || r.protectedQ.ctx.Err() != nil ||
		len(r.childReceiptEnvelope) == 0 ||
		stage2aReservationSHA256(r.childReceiptEnvelope) != q.ChildReceiptSHA256 ||
		r.childPID <= 1 || r.childLauncherPID <= 1 || r.runnerPID <= 1 || r.bridgePID <= 1 ||
		len(r.finalizationEnvelope) == 0 || r.bindReceiptSHA256 == "" ||
		r.hello == nil || r.hello.aborted || !r.hello.finalized {
		return nil, errStage2aReservationAuthority
	}
	run := r.protectedQ
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.closed || run.selector != nil || run.checkLive() != nil ||
		run.session.closed || run.session.peer.recheck() != nil ||
		run.session.sequence != 1+len(run.baseline.trace) ||
		len(run.baseline.trace) != len(stage2aDriverSchedule("managed-protected", stage2aDriverBeforeLaunch)) ||
		run.driver.peer.recheck() != nil || run.install.Review.DriverLive != true {
		return nil, errStage2aReservationAuthority
	}
	r, p, _, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || p.Binding.ProfileInForce != "managed-protected" ||
		stage2aRecheckExecutionCode(r, p) != nil ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
		return nil, errStage2aReservationAuthority
	}
	childRaw, err := verifyStage2aStoredARecordV3(r.childReceiptEnvelope,
		Stage2aChildStartPurpose, 1, s.key.Public().(ed25519.PublicKey))
	var child Stage2aChildStartPayload
	if err != nil || stage2aDecodeExact(childRaw, &child) != nil ||
		child.ProtectedControlProbe == nil ||
		child.ProtectedControlProbe.ProviderModel != p.BridgeQualification.Model ||
		child.ProtectedControlProbe.ProviderRequestSHA256 != p.BridgeQualification.RequestSHA256 ||
		!stage2aProtectedControlProbeSpecMatches(*child.ProtectedControlProbe,
			r.payload.Assignment.SoulStartAssignment,
			p.LaunchInputs.ComponentDigests["test_provider"]) {
		return nil, errStage2aReservationAuthority
	}
	currentPeerSpec, err := s.stage2aProtectedPeerSpec(hqUID, epoch, r, p,
		run.install.Review)
	if err != nil || !reflect.DeepEqual(currentPeerSpec, child.ProtectedControlProbe) {
		return nil, errStage2aReservationAuthority
	}
	dir, err := run.store.open()
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, run.store.uid, run.store.gid, q.InstallationID)
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	if run.store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), run.store.uid, run.store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, run.store.uid, run.store.gid) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-child-ready-"+slot+".json",
			run.store.uid, run.store.gid, r.childReceiptEnvelope, 8192) != nil ||
		requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil {
		return nil, errStage2aReservationAuthority
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, errStage2aReservationAuthority
	}
	now := time.Now()
	deadline, ok := run.ctx.Deadline()
	if !ok {
		return nil, errStage2aReservationAuthority
	}
	expires := minStage2aTime(now.Add(120*time.Second), deadline).Truncate(time.Millisecond)
	sequence := len(stage2aDriverSchedule("managed-protected", stage2aDriverBeforeLaunch)) +
		len(stage2aDriverSchedule("managed-protected", stage2aDriverLiveStart))
	selector := stage2aInnerACPCaptureSelectorV1{
		Schema: stage2aInnerACPCaptureSelectorSchemaV1, Stage2aStopRequest: q.Stage2aStopRequest,
		SessionID: run.session.begin.SessionID, Sequence: sequence,
		TestPlanSHA256:     run.session.begin.TestPlanSHA256,
		ChallengeBase64URL: base64.RawURLEncoding.EncodeToString(challenge[:]),
		ExpiresAtMS:        expires.UnixMilli(),
	}
	if !validStage2aInnerACPCaptureSelectorV1(selector, now) ||
		spendStage2aAdminName(dir, ".stage2a-capture-selector-"+slot, run.store.uid, run.store.gid) != nil {
		return nil, errStage2aReservationAuthority
	}
	wire, _, err := signStage2aInnerACPCaptureSelectorV1(selector, now, run.key, run.sign)
	if err != nil || run.checkLive() != nil {
		return nil, errStage2aReservationAuthority
	}
	run.selector = &selector
	// The selector is a short-lived one-use capture capability. A stalled HQ
	// capture cannot leave its Q session and owner-driver listener alive for
	// the longer reservation window after this capability expires.
	time.AfterFunc(time.Until(expires), run.abort)
	return json.RawMessage(wire), nil
}
