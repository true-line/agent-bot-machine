//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func cooperativeBSocketReady(e soulCooperativeBEndpointV3) bool {
	if !cooperativeBParentReady(e) {
		return false
	}
	dir, err := unix.Open(e.Directory, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	var socket unix.Stat_t
	return unix.Fstatat(dir, filepath.Base(e.SocketPath), &socket, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		socket.Mode == unix.S_IFSOCK|uint16(e.SocketMode) &&
		socket.Uid == uint32(e.OwnerUID) && socket.Gid == uint32(e.GroupGID) &&
		checkDarwinACLs([]string{e.SocketPath}) == nil
}

func cooperativeBSocketMatchesClaim(e soulCooperativeBEndpointV3, claim Stage2aRelayClaim) bool {
	if claim.Path != e.SocketPath || !cooperativeBSocketReady(e) ||
		!validStage2aKernelClaim(claim.Socket) {
		return false
	}
	dir, err := unix.Open(e.Directory, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	var socket unix.Stat_t
	return unix.Fstatat(dir, filepath.Base(e.SocketPath), &socket, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		claim.Socket.UID == socket.Uid && claim.Socket.GID == socket.Gid &&
		claim.Socket.Mode == uint32(socket.Mode&07777) &&
		claim.Socket.Device == strconv.FormatUint(uint64(uint32(socket.Dev)), 10) &&
		claim.Socket.Inode == strconv.FormatUint(socket.Ino, 10)
}

// CooperativeVerifyB authenticates B's live HMAC bind while keeping the FD4
// key in A:B custody. The signed cooperative pair supplies all selectors and
// the broker path; a durable one-use claim rejects replay after A restart.
func (s *Stage2aService) CooperativeVerifyB(hqUID int, epoch string,
	q SoulCooperativeBVerifyRequestV3, paired func(string, func() error) error,
) (SoulCooperativeBVerifyReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeBVerifyReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || live.bridgePID <= 1 || live.digest != q.ReservationSHA256 ||
		live.bridgeSHA != q.BridgeAssignmentSHA256 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest ||
		live.request.HQEpoch != epoch || len(live.bridgeEnvelope) == 0 ||
		stage2aReservationSHA256(live.bridgeEnvelope) != live.bridgeSHA ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(live.bridgeProof[:])) != live.bridgeProofSHA {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		current, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(current.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil || stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		p := current.Policy
		process, err := cooperativeBRoleProcess(live.bridgePID, p)
		if err != nil || !sameSoulKernelProcess(process, live.bridgeProcess) {
			return errSoulCooperativeAuthority
		}
		bridgeRaw, _, err := verifySoulCooperativePurposeV3(live.bridgeEnvelope, pub,
			soulCooperativeBridgeAssignmentPurposeV3)
		var bridge soulCooperativeBridgeAssignmentPayloadV3
		reservationRaw, _, reservationErr := verifySoulCooperativePurposeV3(live.envelope, pub,
			soulCooperativeReservationPurposeV3)
		var reservation soulCooperativeReservationPayloadV3
		if err != nil || stage2aDecodeExact(bridgeRaw, &bridge) != nil ||
			reservationErr != nil || stage2aDecodeExact(reservationRaw, &reservation) != nil ||
			reservation.Assignment.PlanID != q.PlanID ||
			reservation.Assignment.PlanDigest != q.PlanDigest ||
			bridge.ReservationSHA256 != live.digest || bridge.Bridge.UID != p.Bridge.UID ||
			bridge.Bridge.GID != p.Bridge.GID || bridge.InstallationID != q.InstallationID ||
			bridge.StartID != q.StartID || bridge.LaunchID != q.LaunchID ||
			bridge.PlanID != q.PlanID || bridge.PlanDigest != q.PlanDigest ||
			bridge.HQEpoch != epoch || !cooperativeBSocketReady(bridge.Endpoints.Broker) ||
			verifySoulCooperativeBBindV3(live.bridgeProof[:], q, p.Bridge.UID,
				bridge.Endpoints.Broker.SocketPath) != nil {
			return errSoulCooperativeAuthority
		}
		store := current.claimStore()
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
		name := ".cooperative-b-bind-" + soulStartClaimName(q.InstallationID, q.StartID)
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil ||
			time.Since(live.issuedAt) > 30*time.Second {
			return errSoulCooperativeAuthority
		}
		if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
			return errSoulCooperativeAuthority
		}
		return nil
	})
	if err != nil || !ran {
		return reply, errSoulCooperativeAuthority
	}
	live.bridgeBindVerified = true
	return SoulCooperativeBVerifyReplyV3{Verified: true}, nil
}
