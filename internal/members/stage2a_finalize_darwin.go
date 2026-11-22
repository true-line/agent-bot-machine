//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aLiveLease = 5 * time.Second

func stage2aMatchesStopSelectors(r *stage2aLiveReservation, q Stage2aStopRequest, hqUID int) bool {
	if r == nil || r.digest != q.ReservationSHA256 || r.digest != stage2aReservationSHA256(r.envelope) {
		return false
	}
	a := r.payload.Assignment
	return a.InstallationID == q.InstallationID && a.StartID == q.StartID &&
		a.LaunchID == q.LaunchID && a.PlanID == q.PlanID && a.PlanDigest == q.PlanDigest &&
		a.HQEpoch == q.HQEpoch && a.HQUID == hqUID
}

// FinalizeB signs HQ's paired attestation of the B readiness observation.
// A independently checks its spent B bind claim and the live B launcher, but
// cannot traverse B's private relay directory; HQ must inspect that socket.
func (s *Stage2aService) FinalizeB(hqUID int, epoch string, q Stage2aFinalizeBRequest) (Stage2aFinalizeBReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aFinalizeBReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		!strings.HasPrefix(q.BindReceiptSHA256, "sha256:") ||
		!stage2aLowerHex64(strings.TrimPrefix(q.BindReceiptSHA256, "sha256:")) ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.finalizationEnvelope) != 0 || len(r.bridgeAssignment) == 0 || r.bridgePID <= 1 ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	endpoints, err := DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, q.StartID)
	if err != nil || q.RelaySocket.Path != endpoints.Relay.SocketPath ||
		filepath.Dir(q.RelaySocket.Path) != p.RelayParent.Path ||
		q.RelaySocket.Socket.UID != uint32(p.Bridge.UID) ||
		q.RelaySocket.Socket.GID != uint32(p.Runner.GID) ||
		q.RelaySocket.Socket.Mode != endpoints.Relay.SocketMode ||
		!validStage2aKernelClaim(q.RelaySocket.Socket) {
		return reply, errStage2aReservationAuthority
	}
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	name := ".stage2a-b-final-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, name) != nil ||
		!time.Now().Before(expires) {
		return reply, errStage2aReservationAuthority
	}
	payload := Stage2aFinalizationPayload{Schema: "agent-bot-machine/stage2a-finalization/v1",
		Stage2aStopRequest: q.Stage2aStopRequest, BindReceiptSHA256: q.BindReceiptSHA256,
		RelaySocket: q.RelaySocket, BridgePID: r.bridgePID,
		FinalizedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aFinalizationPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || !time.Now().Before(expires) ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	if err := commitStage2aReservation(dir, name, envelope); err != nil {
		return reply, err
	}
	r.finalizationEnvelope = envelope
	r.bindReceiptSHA256 = q.BindReceiptSHA256
	return Stage2aFinalizeBReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:                 stage2aReservationSHA256(envelope),
		FinalizedLiveExpiresAt: minStage2aTime(expires, time.Now().Add(stage2aLiveLease)).UnixMilli()}, nil
}

// Live is a paired, short lease check. After finalization it can renew beyond
// the launch lease only while the installed policy, active claim, B bind claim,
// and kernel role processes still match. Stop removes the active claim.
func (s *Stage2aService) Live(hqUID int, epoch string, q Stage2aLiveRequest) (Stage2aLiveReply, error) {
	if !validStage2aLiveChallenge(q.Challenge) {
		return Stage2aLiveReply{}, errStage2aReservationAuthority
	}
	return s.live(hqUID, epoch, q.Stage2aStopRequest, q.Challenge)
}

// Provider's A-internal status check does not issue an R lease. Only the
// paired Live request with a fresh R challenge can receive a signed renewal.
func (s *Stage2aService) live(hqUID int, epoch string, q Stage2aStopRequest, challenge string) (Stage2aLiveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aLiveReply
	if !validStage2aStopRequest(q) || q.HQEpoch != epoch || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q, hqUID) || r.hello != nil && r.hello.aborted {
		return reply, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aInstalledPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest {
		return reply, errStage2aReservationAuthority
	}
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil {
		return reply, errStage2aReservationAuthority
	}
	if r.bridgePID > 1 && checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		r.runnerPID > 1 && checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		r.childLauncherPID > 1 && checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		r.childPID > 1 && checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	reply = Stage2aLiveReply{ReservationSHA256: q.ReservationSHA256, Phase: "prebind",
		BridgePID: r.bridgePID, RunnerPID: r.runnerPID}
	if len(r.finalizationEnvelope) == 0 {
		expires, err := time.Parse(time.RFC3339Nano, r.payload.Assignment.ExpiresAt)
		if err != nil || !time.Now().Before(expires) {
			return Stage2aLiveReply{}, errStage2aReservationExpired
		}
		return reply, nil
	}
	if r.bridgePID <= 1 || r.bindReceiptSHA256 == "" ||
		r.runnerPID <= 1 || r.runnerProcess.PID != r.runnerPID || r.bridgeProcess.PID != r.bridgePID ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil {
		return Stage2aLiveReply{}, errStage2aReservationAuthority
	}
	finalName := ".stage2a-b-final-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if stage2aCheckFinalizationFile(dir, finalName, store.uid, store.gid, r.finalizationEnvelope) != nil {
		return Stage2aLiveReply{}, errStage2aReservationAuthority
	}
	if r.childPID > 1 && stage2aCheckFinalizationFile(dir,
		".stage2a-child-ready-"+soulStartClaimName(q.InstallationID, q.StartID)+".json",
		store.uid, store.gid, r.childReceiptEnvelope) != nil {
		return Stage2aLiveReply{}, errStage2aReservationAuthority
	}
	issued := time.Now()
	approvedUntil, _ := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	lease := minStage2aTime(approvedUntil, issued.Add(stage2aLiveLease))
	if !lease.After(issued) || lease.UnixMilli() <= issued.UnixMilli() ||
		(challenge != "" && r.liveSequence >= (1<<53)-1) {
		return Stage2aLiveReply{}, errStage2aReservationExpired
	}
	reply.Phase = "finalized"
	reply.FinalizationSHA256 = stage2aReservationSHA256(r.finalizationEnvelope)
	reply.BindReceiptSHA256 = r.bindReceiptSHA256
	reply.FinalizedLiveExpiresAt = lease.UnixMilli()
	if challenge == "" {
		return reply, nil
	}
	sequence := r.liveSequence + 1
	envelope, err := signStage2aLiveLease(q, challenge, r, sequence, issued, lease,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 || !time.Now().Before(lease) {
		return Stage2aLiveReply{}, errStage2aReservationAuthority
	}
	r.liveSequence = sequence
	reply.LeaseEnvelopeBase64URL = base64.RawURLEncoding.EncodeToString(envelope)
	reply.LeaseSHA256 = stage2aReservationSHA256(envelope)
	reply.LeaseSequence = sequence
	return reply, nil
}

func signStage2aLiveLease(q Stage2aStopRequest, challenge string, r *stage2aLiveReservation,
	sequence uint64, issued, expires time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	if r == nil || !validStage2aStopRequest(q) || r.digest != q.ReservationSHA256 ||
		!validStage2aLiveChallenge(challenge) || sequence == 0 || sequence > (1<<53)-1 ||
		sequence != r.liveSequence+1 || r.runnerPID <= 1 || r.bridgePID <= 1 ||
		r.runnerProcess.PID != r.runnerPID || r.bridgeProcess.PID != r.bridgePID ||
		r.runnerProcess.StartSeconds <= 0 || r.bridgeProcess.StartSeconds <= 0 ||
		r.runnerProcess.EffectiveUID == 0 || r.bridgeProcess.EffectiveUID == 0 ||
		!stage2aPrefixedDigest.MatchString(r.bindReceiptSHA256) || len(r.finalizationEnvelope) == 0 ||
		!expires.After(issued) || expires.Sub(issued) > stage2aLiveLease ||
		expires.UnixMilli() <= issued.UnixMilli() {
		return nil, errStage2aReservationAuthority
	}
	payload := Stage2aLiveLeasePayload{
		Schema: "agent-bot-machine/stage2a-live-lease/v1", Stage2aStopRequest: q,
		FinalizationSHA256: stage2aReservationSHA256(r.finalizationEnvelope),
		BindReceiptSHA256:  r.bindReceiptSHA256, Challenge: challenge,
		Runner: stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		Sequence: sequence, IssuedAtMS: issued.UnixMilli(), ExpiresAtMS: expires.UnixMilli(),
	}
	if r.childPID > 1 && len(r.childReceiptEnvelope) > 0 {
		if r.hello == nil || r.hello.aborted || !r.hello.finalized || len(r.hello.finalizationEnvelope) == 0 {
			return nil, errStage2aReservationAuthority
		}
		payload.HelloFinalizationSHA256 = stage2aReservationSHA256(r.hello.finalizationEnvelope)
		launcher, child := stage2aLiveRoleIdentity(r.childLauncherProcess), stage2aLiveRoleIdentity(r.childProcess)
		payload.ChildLauncher, payload.Child = &launcher, &child
		payload.ChildReceiptSHA256 = stage2aReservationSHA256(r.childReceiptEnvelope)
	}
	return signStage2aEnvelope(payload, 1, Stage2aLiveLeasePurpose, key, sign)
}

func stage2aLiveRoleIdentity(proc soulKernelProcessSnapshot) Stage2aLiveRoleIdentity {
	return Stage2aLiveRoleIdentity{PID: proc.PID, UID: proc.EffectiveUID,
		GID: proc.PrimaryGroupGID, StartSeconds: proc.StartSeconds, StartMicros: proc.StartMicros}
}

func stage2aCheckFinalizationFile(dir *os.File, name string, uid, gid uint32, expected []byte) error {
	if len(expected) == 0 || len(expected) > 8192 {
		return errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || !bytes.Equal(raw, expected) {
		return errStage2aReservationAuthority
	}
	return nil
}
