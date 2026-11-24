//go:build darwin

package members

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
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
			peer, err := observeStage2aT03RelayPeer(q.Receipt, r, p)
			if err != nil {
				return err
			}
			raw, err := marshalStage2aReservationJCS(q)
			if err != nil {
				return err
			}
			if err := commitStage2aReservation(dir, ".stage2a-t03-positive-"+startClaim+".json", raw); err != nil {
				return err
			}
			r.t03Positive = &q
			r.t03PositivePeer = &peer
			digest = stage2aReservationSHA256(raw)
			return nil
		})
	return digest, err
}

// B's audit token identifies the accepted Unix peer. A independently checks
// the still-live stock CLI image and its direct ACP parent, both against the
// installed R generation. The returned witness is committed by live Q.
type stage2aT03PeerWitness struct {
	Peer          Stage2aT03RelayPeer     `json:"peer"`
	PeerSHA256    string                  `json:"peer_sha256"`
	ACPChild      Stage2aLiveRoleIdentity `json:"acp_child"`
	CLI           Stage2aLiveRoleIdentity `json:"cli"`
	CLIExecutable string                  `json:"cli_executable"`
}

func observeStage2aT03RelayPeer(receipt Stage2aT03PositiveReceipt, r *stage2aLiveReservation,
	p stage2aInstalledPolicy) (stage2aT03PeerWitness, error) {
	var empty stage2aT03PeerWitness
	peer := receipt.Peer
	child := r.childProcess
	if !receipt.valid() || r.runtimeRefV3 == (stage2aDomainInventoryRefV3{}) ||
		peer.UID != uint32(p.Runner.UID) || peer.ParentPID != child.PID ||
		peer.ParentUID != child.EffectiveUID || peer.ParentStartSeconds != child.StartSeconds ||
		peer.ParentStartMicros != child.StartMicros || peer.PID == child.PID {
		return empty, errStage2aReservationAuthority
	}
	cli := filepath.Join(r.runtimeRefV3.Snapshot.Path, "runtime/bin/claude")
	observed, err := observeStage2aQualificationProcess(peer.PID, cli, nil, true)
	if err != nil || observed.Kernel.ParentPID != child.PID ||
		observed.Kernel.RealUID != peer.UID || observed.Kernel.EffectiveUID != peer.UID ||
		observed.Kernel.SavedUID != peer.UID ||
		observed.Kernel.RealGID != uint32(p.Runner.GID) ||
		observed.Kernel.PrimaryGroupGID != uint32(p.Runner.GID) ||
		observed.Kernel.SavedGID != uint32(p.Runner.GID) ||
		observed.Kernel.StartSeconds != peer.StartSeconds ||
		observed.Kernel.StartMicros != peer.StartMicros ||
		checkStage2aChildProcess(child.PID, r.childLauncherPID, p.Runner, p.LaunchInputs, child) != nil ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return empty, errStage2aReservationAuthority
	}
	return stage2aT03PeerWitness{Peer: peer, PeerSHA256: receipt.PeerSHA256,
		ACPChild: stage2aLiveRoleIdentity(child), CLI: stage2aLiveRoleIdentity(observed.Kernel),
		CLIExecutable: cli}, nil
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
