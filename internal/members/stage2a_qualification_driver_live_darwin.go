//go:build darwin

package members

import (
	"context"
	"crypto/ed25519"
	"log"
	"reflect"
)

type stage2aPendingT03 struct {
	ctx          context.Context
	cancel       context.CancelFunc
	baseline     chan struct{}
	request      chan stage2aT03DriverRequest
	result       chan stage2aT03DriverResult
	claimed      bool                     // guarded by Stage2aService.mu
	finishPaired func(func() error) error // set and used by the session worker
}

type stage2aT03DriverRequest struct {
	check   func() error
	capture stage2aProtectedT03Capture
	paired  func(func() error) error
}

type stage2aT03DriverResult struct {
	artifacts stage2aQualificationPreSignArtifactsV1
	err       error
}

// StartProtectedT03 resumes the owner-reviewed Q session after the paired
// positive intake has stored its receipt. The request handler may return
// immediately so HQ and R can deliver the subsequent live observations.
func (s *Stage2aService) StartProtectedT03(hqUID int, epoch string, q Stage2aStopRequest,
	paired func(func() error) error) {
	if paired == nil {
		return
	}
	s.mu.Lock()
	live := s.active[q.ReservationSHA256]
	enabled := stage2aMatchesStopSelectors(live, q, hqUID) && live.qT03 != nil
	s.mu.Unlock()
	if !enabled {
		return
	}
	go func() {
		if _, err := s.captureProtectedT03(hqUID, epoch, q, paired); err != nil {
			log.Printf("Stage 2a live T03 capture refused: %v", err)
		}
	}()
}

// captureProtectedT03 is the A-side continuation of authenticated positive
// provider intake. The caller supplies a local, challenge-bound stimulus and
// corroborator from that intake. Neither the owner driver nor Q may arm R.
func (s *Stage2aService) captureProtectedT03(hqUID int, epoch string, q Stage2aStopRequest,
	paired func(func() error) error) (stage2aQualificationPreSignArtifactsV1, error) {
	var empty stage2aQualificationPreSignArtifactsV1
	if paired == nil || !validStage2aStopRequest(q) || q.HQEpoch != epoch || len(s.key) != ed25519.PrivateKeySize {
		return empty, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	install, err := readStage2aQualificationQInstall()
	if err != nil || !install.Review.DriverLiveT03 || install.Review.InstallationID != q.InstallationID {
		return empty, errStage2aReservationAuthority
	}
	s.mu.Lock()
	live := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(live, q, hqUID) || live.qT03 == nil || live.qT03.claimed ||
		live.childPID <= 1 || len(live.childReceiptEnvelope) == 0 ||
		live.payload.MeasurementBinding.ProfileInForce != "managed-protected" {
		s.mu.Unlock()
		return empty, errStage2aReservationAuthority
	}
	pending := live.qT03
	pending.claimed = true
	receipt := stage2aQualificationSHA256(live.childReceiptEnvelope)
	s.mu.Unlock()

	checkLive := func() error {
		current, err := readStage2aQualificationQInstall()
		if pending.ctx.Err() != nil || err != nil || !reflect.DeepEqual(install, current) {
			return errStage2aReservationAuthority
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.checkProtectedT03Live(hqUID, epoch, q, live, receipt, key)
	}
	capture := func(ctx context.Context, command stage2aDriverCommand) (stage2aDriverCorroboration, error) {
		return s.captureStage2aT03(ctx, hqUID, epoch, q, command, install.Review.TestPlan, paired)
	}
	select {
	case pending.request <- stage2aT03DriverRequest{check: checkLive, capture: capture, paired: paired}:
	case <-pending.ctx.Done():
		return empty, errStage2aReservationAuthority
	}
	result := <-pending.result
	return result.artifacts, result.err
}

// Caller holds the service mutex. Q eligibility is tied to the same verified
// R/B generation and child receipt as protected execution.
func (s *Stage2aService) checkProtectedT03Live(hqUID int, epoch string, q Stage2aStopRequest,
	live *stage2aLiveReservation, receipt string, key ed25519.PublicKey) error {
	if s.active[q.ReservationSHA256] != live || !stage2aMatchesStopSelectors(live, q, hqUID) ||
		live.childPID <= 1 || stage2aQualificationSHA256(live.childReceiptEnvelope) != receipt ||
		live.bindReceiptSHA256 == "" || len(live.finalizationEnvelope) == 0 ||
		live.hello == nil || live.hello.aborted || !live.hello.finalized || len(live.hello.finalizationEnvelope) == 0 {
		return errStage2aReservationAuthority
	}
	policy, raw, err := loadStage2aActiveExecutionPolicy(key, hqUID, epoch, live)
	if err != nil || stage2aReservationSHA256(raw) != live.policyDigest ||
		checkStage2aGrantedRoleProcess(live.runnerPID, policy.Runner.UID, policy.Runner.GID, "runner", live.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(live.bridgePID, policy.Bridge.UID, policy.Bridge.GID, "bridge", live.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(live.childLauncherPID, policy.Runner.UID, policy.Runner.GID, "child", live.childLauncherProcess) != nil ||
		checkStage2aChildProcess(live.childPID, live.childLauncherPID, policy.Runner, policy.LaunchInputs, live.childProcess) != nil {
		return errStage2aReservationAuthority
	}
	store, _ := policy.stores()
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+slot, store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+slot+".json", store.uid, store.gid, live.finalizationEnvelope) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-child-ready-"+slot+".json", store.uid, store.gid, live.childReceiptEnvelope) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}
