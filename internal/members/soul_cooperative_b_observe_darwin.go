//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeBObservedPurposeV3 = "agent-bot/soul-cooperative-b-observed/v3"

type soulCooperativeBObservedPayloadV3 struct {
	Contract               string                  `json:"contract"`
	Kind                   string                  `json:"kind"`
	SchemaVersion          int                     `json:"schema_version"`
	ReservationSHA256      string                  `json:"reservation_sha256"`
	BridgeAssignmentSHA256 string                  `json:"bridge_assignment_sha256"`
	BindReceiptSHA256      string                  `json:"bind_receipt_sha256"`
	InstallationID         string                  `json:"installation_id"`
	StartID                string                  `json:"start_id"`
	LaunchID               string                  `json:"launch_id"`
	PlanID                 string                  `json:"plan_id"`
	PlanDigest             string                  `json:"plan_digest"`
	HQEpoch                string                  `json:"hq_epoch"`
	GrantNonce             string                  `json:"grant_nonce"`
	Launcher               Stage2aLiveRoleIdentity `json:"launcher"`
	Bridge                 Stage2aLiveRoleIdentity `json:"bridge"`
	RelaySocket            Stage2aRelayClaim       `json:"relay_socket"`
	RelaySocketBirthtimeNS string                  `json:"relay_socket_birthtime_ns"`
	ObservedAt             string                  `json:"observed_at"`
	ExpiresAt              string                  `json:"expires_at"`
}

func (s *Stage2aService) CooperativeObserveB(hqUID int, epoch string,
	q SoulCooperativeBObserveRequestV3, paired func(string, func() error) error,
) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeBObserveRequestV3(rawQ); err != nil ||
		paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.bridgeBindVerified || len(live.bridgeObservedEnvelope) != 0 ||
		live.bridgePID <= 1 || live.bridgeGrantNonce != q.GrantNonce ||
		live.bridgeSHA != q.BridgeAssignmentSHA256 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil || stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		p := installed.Policy
		launcher, err := cooperativeBRoleProcess(live.bridgePID, p)
		if err != nil || !sameSoulKernelProcess(launcher, live.bridgeProcess) {
			return errSoulCooperativeAuthority
		}
		reservationRaw, _, err := verifySoulCooperativePurposeV3(live.envelope, pub,
			soulCooperativeReservationPurposeV3)
		var reservation soulCooperativeReservationPayloadV3
		bridgeRaw, _, bridgeErr := verifySoulCooperativePurposeV3(live.bridgeEnvelope, pub,
			soulCooperativeBridgeAssignmentPurposeV3)
		var bridge soulCooperativeBridgeAssignmentPayloadV3
		if err != nil || bridgeErr != nil ||
			stage2aDecodeExact(reservationRaw, &reservation) != nil ||
			stage2aDecodeExact(bridgeRaw, &bridge) != nil ||
			reservation.Assignment.PlanID != q.PlanID || reservation.Assignment.PlanDigest != q.PlanDigest ||
			bridge.PlanID != q.PlanID || bridge.PlanDigest != q.PlanDigest ||
			bridge.ReservationSHA256 != q.ReservationSHA256 ||
			q.RelaySocket.Path != bridge.Endpoints.Relay.SocketPath ||
			!cooperativeBSocketReady(bridge.Endpoints.Relay) {
			return errSoulCooperativeAuthority
		}
		observed, err := observeSoulProcess(q.BridgePID, SoulBridgeBinary,
			[]string{SoulBridgeBinary, "--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"})
		child := observed.Kernel
		if err != nil || child.PID == launcher.PID || child.ParentPID != launcher.PID ||
			child.ProcessGroupID != child.PID || child.StartSeconds != q.BridgeStartSeconds ||
			child.StartMicros != q.BridgeStartMicros || child.RealUID != uint32(p.Bridge.UID) ||
			child.EffectiveUID != uint32(p.Bridge.UID) || child.SavedUID != uint32(p.Bridge.UID) ||
			child.RealGID != uint32(p.Bridge.GID) ||
			child.PrimaryGroupGID != uint32(p.Bridge.GID) || child.SavedGID != uint32(p.Bridge.GID) {
			return errSoulCooperativeAuthority
		}
		dir, err := unix.Open(filepath.Dir(q.RelaySocket.Path), stage2aDirectoryOpenFlags, 0)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer unix.Close(dir)
		var socket unix.Stat_t
		if unix.Fstatat(dir, filepath.Base(q.RelaySocket.Path), &socket, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			socket.Mode != unix.S_IFSOCK|uint16(bridge.Endpoints.Relay.SocketMode) ||
			socket.Uid != uint32(p.Bridge.UID) || socket.Gid != uint32(p.Runner.GID) ||
			q.RelaySocket.Socket.UID != socket.Uid || q.RelaySocket.Socket.GID != socket.Gid ||
			q.RelaySocket.Socket.Mode != uint32(socket.Mode&07777) ||
			q.RelaySocket.Socket.Device != strconv.FormatUint(uint64(uint32(socket.Dev)), 10) ||
			q.RelaySocket.Socket.Inode != strconv.FormatUint(socket.Ino, 10) {
			return errSoulCooperativeAuthority
		}
		if socket.Btim.Sec <= 0 || socket.Btim.Nsec < 0 || socket.Btim.Nsec >= 1_000_000_000 ||
			socket.Btim.Sec > (1<<63-1)/1_000_000_000 {
			return errSoulCooperativeAuthority
		}
		birthtimeNS := strconv.FormatInt(socket.Btim.Sec*1_000_000_000+socket.Btim.Nsec, 10)
		store := installed.claimStore()
		claimDir, err := store.open()
		if err != nil {
			return err
		}
		defer claimDir.Close()
		lock, err := lockStage2aReservation(claimDir, store.uid, store.gid, q.InstallationID)
		if err != nil {
			return err
		}
		defer lock.Close()
		name := ".cooperative-b-observed-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
		if store.checkDirectory(claimDir) != nil ||
			cooperativeActiveClaimMatches(claimDir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(claimDir, ".cooperative-b-bind-"+
				soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil ||
			requireUnspentStage2aReservation(claimDir, name) != nil {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		expires, err := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
		if err != nil || !now.Before(expires) ||
			!sameSoulKernelProcess(launcher, live.bridgeProcess) {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeBObservedPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-b-observed",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			BridgeAssignmentSHA256: q.BridgeAssignmentSHA256, BindReceiptSHA256: q.BindReceiptSHA256,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: epoch, GrantNonce: q.GrantNonce,
			Launcher: stage2aLiveRoleIdentity(launcher), Bridge: stage2aLiveRoleIdentity(child),
			RelaySocket: q.RelaySocket, RelaySocketBirthtimeNS: birthtimeNS,
			ObservedAt: now.Format(time.RFC3339Nano),
			ExpiresAt:  expires.Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(payload, 3, soulCooperativeBObservedPurposeV3, pub, s.sign)
		if err != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		launcherAgain, e1 := cooperativeBRoleProcess(live.bridgePID, p)
		childAgain, e2 := observeSoulKernelProcess(q.BridgePID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(launcher, launcherAgain) ||
			!sameSoulKernelProcess(child, childAgain) || !time.Now().Before(expires) ||
			!cooperativeBSocketReady(bridge.Endpoints.Relay) ||
			!cooperativeBSocketBirthtimeMatches(bridge.Endpoints.Relay, birthtimeNS) {
			return errSoulCooperativeAuthority
		}
		if err := commitStage2aReservation(claimDir, name, envelope); err != nil {
			return errSoulCooperativeAuthority
		}
		live.bridgeObservedEnvelope = envelope
		live.bridgeNativePID = child.PID
		live.bridgeNativeProcess = child
		live.bridgeRelayClaim = q.RelaySocket
		live.bridgeRelayBirthtimeNS = birthtimeNS
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
