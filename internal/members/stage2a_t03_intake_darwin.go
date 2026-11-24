//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"
)

const stage2aT03ReceiptLifetime = 30 * time.Second

const stage2aT03CompletionSubkeyPurpose = "agent-bot-stage2a-b-completion-subkey-v1"
const stage2aT03CompletionOriginPurpose = "agent-bot-stage2a-b-completion-origin-v1"

type stage2aT03PrewriteState struct {
	Record       Stage2aT03BrokerPrewrite
	Peer         stage2aT03PeerWitness
	Receipt      string
	ObservedAtMS int64
}

// HQ forwards B's prepared-wire record under the paired Machine request
// while B still owns the accepted Unix connection. The receipt is one-use;
// only this live CLI observation can support the later B-authenticated write.
func (s *Stage2aService) Stage2aT03AcceptPrewrite(hqUID int, epoch string,
	q Stage2aT03PrewriteRequest) (string, error) {
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		!q.BrokerPrewrite.valid(epoch) ||
		q.BrokerPrewrite.Selectors.stop(epoch) != q.Stage2aStopRequest ||
		!stage2aPrefixedDigest.MatchString(q.ChildReceiptSHA256) {
		return "", errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var receipt string
	err := s.withStage2aT03Start(hqUID, epoch, q.Stage2aStopRequest,
		func(r *stage2aLiveReservation, p stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
			b := q.BrokerPrewrite
			startClaim := soulStartClaimName(q.InstallationID, q.StartID)
			if r.t03PrewriteSpent || r.t03Prewrite != nil || r.t03Positive != nil ||
				r.proofDigest != stage2aReservationSHA256(r.bridgeProof[:]) ||
				q.ChildReceiptSHA256 != stage2aReservationSHA256(r.childReceiptEnvelope) ||
				b.BindReceiptSHA256 != r.bindReceiptSHA256 ||
				b.RequestSHA256 != p.BridgeQualification.RequestSHA256 ||
				b.Model != p.BridgeQualification.Model ||
				stage2aCheckSpentClaim(dir, ".stage2a-provider-"+startClaim, store.uid, store.gid) != nil {
				return errStage2aReservationAuthority
			}
			peer, err := observeStage2aT03RelayPeer(b.Peer, b.PeerSHA256, r, p)
			if err != nil {
				return err
			}
			var token [32]byte
			if _, err := rand.Read(token[:]); err != nil {
				return errStage2aReservationAuthority
			}
			receipt = hex.EncodeToString(token[:])
			clear(token[:])
			r.t03Prewrite = &stage2aT03PrewriteState{Record: b, Peer: peer,
				Receipt: receipt, ObservedAtMS: time.Now().UnixMilli()}
			r.t03PrewriteSpent = true
			return nil
		})
	return receipt, err
}

// Stage2aT03AcceptPositive is called under the current HQ pairing lock. The
// owner-driver session checks the additional reviewed T03 pins before arming.
func (s *Stage2aService) Stage2aT03AcceptPositive(hqUID int, epoch string, q Stage2aT03ArmRequest) (string, error) {
	if !q.Receipt.valid() || !q.providerMatchesStart() || !q.BrokerCompletion.valid(q.HQEpoch) {
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
				r.t03Prewrite == nil || r.t03Positive != nil ||
				r.proofDigest != stage2aReservationSHA256(r.bridgeProof[:]) ||
				stage2aCheckSpentClaim(dir, ".stage2a-provider-"+startClaim, store.uid, store.gid) != nil {
				return errStage2aReservationAuthority
			}
			prewrite := r.t03Prewrite
			// A validly shaped completion gets one MAC attempt. A failed MAC or
			// finalization cannot leave a reusable receipt or an HQ MAC oracle.
			r.t03Prewrite = nil
			if !stage2aT03CompletionMatches(q, prewrite) ||
				!verifyStage2aT03CompletionOrigin(r.bridgeProof[:], q.BrokerCompletion, epoch) {
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
			peer := prewrite.Peer
			r.t03PositivePeer = &peer
			digest = stage2aReservationSHA256(raw)
			return nil
		})
	return digest, err
}

// B's audit token identifies the accepted Unix peer. A independently checks
// the still-live stock CLI image before B's final write. The witness persists
// across normal CLI exit and is committed only after B authenticates completion.
type stage2aT03PeerWitness struct {
	Peer          Stage2aT03RelayPeer     `json:"peer"`
	PeerSHA256    string                  `json:"peer_sha256"`
	ACPChild      Stage2aLiveRoleIdentity `json:"acp_child"`
	CLI           Stage2aLiveRoleIdentity `json:"cli"`
	CLIExecutable string                  `json:"cli_executable"`
}

func observeStage2aT03RelayPeer(peer Stage2aT03RelayPeer, peerSHA256 string, r *stage2aLiveReservation,
	p stage2aInstalledPolicy) (stage2aT03PeerWitness, error) {
	var empty stage2aT03PeerWitness
	child := r.childProcess
	if r.runtimeRefV3 == (stage2aDomainInventoryRefV3{}) ||
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
	return stage2aT03PeerWitness{Peer: peer, PeerSHA256: peerSHA256,
		ACPChild: stage2aLiveRoleIdentity(child), CLI: stage2aLiveRoleIdentity(observed.Kernel),
		CLIExecutable: cli}, nil
}

func stage2aT03CompletionMatches(q Stage2aT03ArmRequest, prewrite *stage2aT03PrewriteState) bool {
	if prewrite == nil {
		return false
	}
	c := q.BrokerCompletion
	if c.Selectors.stop(q.HQEpoch) != q.Stage2aStopRequest ||
		c.Stage2aT03BrokerPrewrite != prewrite.Record || c.PrewriteReceipt != prewrite.Receipt ||
		c.BindReceiptSHA256 != q.Receipt.BindReceiptSHA256 || c.Peer != q.Receipt.Peer ||
		c.PeerSHA256 != q.Receipt.PeerSHA256 || c.RequestSHA256 != q.Receipt.RequestSHA256 ||
		c.PromptSHA256 != q.Receipt.PromptSHA256 || c.Model != q.Receipt.Model ||
		c.ResponseWireSHA256 != q.Receipt.ResponseWireSHA256 ||
		c.ResponseWireBytes != q.Receipt.ResponseWireBytes || c.HTTPStatus != q.Receipt.HTTPStatus {
		return false
	}
	started, e1 := time.Parse(time.RFC3339Nano, c.WriteStartedAt)
	completed, e2 := time.Parse(time.RFC3339Nano, c.WriteCompletedAt)
	return e1 == nil && e2 == nil && started.UnixMilli() >= prewrite.ObservedAtMS &&
		completed.UnixMilli()-prewrite.ObservedAtMS <= stage2aT03ReceiptLifetime.Milliseconds() &&
		completed.UnixMilli() == q.Receipt.CompletedAtMS
}

func verifyStage2aT03CompletionOrigin(bridgeProof []byte, c Stage2aT03BrokerCompletion, epoch string) bool {
	if len(bridgeProof) != 32 || !c.valid(epoch) {
		return false
	}
	want, err := stage2aT03CompletionOriginMAC(bridgeProof, c)
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(c.CompletionOriginMAC)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func stage2aT03CompletionOriginMAC(bridgeProof []byte, c Stage2aT03BrokerCompletion) ([]byte, error) {
	if len(bridgeProof) != 32 {
		return nil, errStage2aReservationAuthority
	}
	body, err := c.canonicalBody()
	if err != nil {
		return nil, err
	}
	keyMAC := hmac.New(sha256.New, bridgeProof)
	_, _ = keyMAC.Write([]byte(stage2aT03CompletionSubkeyPurpose + "\x00" + c.Selectors.ReservationDigest))
	completionKey := keyMAC.Sum(nil)
	defer clear(completionKey)
	mac := hmac.New(sha256.New, completionKey)
	_, _ = mac.Write([]byte(stage2aT03CompletionOriginPurpose + "\x00"))
	_, _ = mac.Write(body)
	return mac.Sum(nil), nil
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
