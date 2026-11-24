//go:build darwin

package members

import (
	"crypto/ed25519"
	"os"
	"time"
)

const stage2aT03ReceiptLifetime = 30 * time.Second

// Stage2aT03AcceptPositive is called under the current HQ pairing lock. The
// owner-driver session checks the additional reviewed T03 pins before arming.
func (s *Stage2aService) Stage2aT03AcceptPositive(hqUID int, epoch string, q Stage2aT03ArmRequest) (string, error) {
	if !q.Receipt.valid() || !q.providerMatchesStart() {
		return "", errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var digest string
	err := s.withStage2aT03Start(hqUID, epoch, q.Stage2aStopRequest,
		func(r *stage2aLiveReservation, p stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
			startClaim := soulStartClaimName(q.InstallationID, q.StartID)
			_, configDigest, err := stage2aProviderConfig(p.BridgeQualification)
			if err != nil || !stage2aT03PositiveMatches(q.Receipt, r, p.BridgeQualification, "sha256:"+configDigest, time.Now()) ||
				stage2aCheckSpentClaim(dir, ".stage2a-provider-"+startClaim, store.uid, store.gid) != nil {
				return errStage2aReservationAuthority
			}
			raw, err := marshalStage2aReservationJCS(q)
			if err != nil {
				return err
			}
			if err := commitStage2aReservation(dir, ".stage2a-t03-positive-"+startClaim+".json", raw); err != nil {
				return err
			}
			r.t03Positive = &q
			digest = stage2aReservationSHA256(raw)
			return nil
		})
	return digest, err
}

func stage2aT03PositiveMatches(q Stage2aT03PositiveReceipt, r *stage2aLiveReservation,
	qualification Stage2aBridgeQualification, configDigest string, now time.Time) bool {
	age := now.Sub(time.UnixMilli(q.CompletedAtMS))
	return age >= 0 && age <= stage2aT03ReceiptLifetime &&
		q.ChildReceiptSHA256 == stage2aReservationSHA256(r.childReceiptEnvelope) &&
		q.FinalizationSHA256 == stage2aReservationSHA256(r.finalizationEnvelope) &&
		q.BindReceiptSHA256 == r.bindReceiptSHA256 && q.RelaySocket == r.payload.Assignment.Relay.SocketPath &&
		q.ProviderConfigSHA256 == configDigest && q.RequestSHA256 == qualification.RequestSHA256 &&
		q.Model == qualification.Model
}

// The caller holds s.mu and the current paired HQ guard. All checks and the
// supplied mutation use a single fresh view of the private start store.
func (s *Stage2aService) withStage2aT03Start(hqUID int, epoch string, q Stage2aStopRequest,
	use func(*stage2aLiveReservation, stage2aInstalledPolicy, stage2aAdminClaimStore, *os.File) error) error {
	if len(s.key) != ed25519.PrivateKeySize || !validStage2aStopRequest(q) || q.HQEpoch != epoch {
		return errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q, hqUID) || r.runModeV3 != stage2aCandidateRunV3 ||
		r.hello == nil || !r.hello.finalized || r.hello.aborted ||
		len(r.childReceiptEnvelope) == 0 || len(r.finalizationEnvelope) == 0 || r.liveSequence == 0 {
		return errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest || p.Binding.ProfileInForce != "managed-protected" ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
		return errStage2aReservationAuthority
	}
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return err
	}
	defer lock.Close()
	startClaim := soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+startClaim, store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+startClaim+".json", store.uid, store.gid, r.finalizationEnvelope) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-child-ready-"+startClaim+".json", store.uid, store.gid, r.childReceiptEnvelope) != nil {
		return errStage2aReservationAuthority
	}
	return use(r, p, store, dir)
}
