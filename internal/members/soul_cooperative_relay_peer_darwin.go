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

type soulCooperativeRelayPeerPayloadV3 struct {
	Contract                       string                             `json:"contract"`
	Kind                           string                             `json:"kind"`
	SchemaVersion                  int                                `json:"schema_version"`
	ProfileInForce                 string                             `json:"profile_in_force"`
	HostID                         string                             `json:"host_id"`
	InstallationID                 string                             `json:"installation_id"`
	StartID                        string                             `json:"start_id"`
	LaunchID                       string                             `json:"launch_id"`
	HQEpoch                        string                             `json:"hq_epoch"`
	ReservationSHA256              string                             `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256       string                             `json:"assignment_envelope_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                             `json:"member_b_authority_envelope_sha256"`
	BridgeObservedSHA256           string                             `json:"bridge_observed_sha256"`
	ReadySHA256                    string                             `json:"ready_sha256"`
	BLeaseSHA256                   string                             `json:"b_lease_sha256"`
	BLeaseSequence                 uint64                             `json:"b_lease_sequence"`
	MemberLeaseSHA256              string                             `json:"member_lease_sha256"`
	MemberLeaseSequence            uint64                             `json:"member_lease_sequence"`
	MemberID                       string                             `json:"member_id"`
	MemberLaunchID                 string                             `json:"member_launch_id"`
	MemberSelector                 string                             `json:"member_selector"`
	BridgeProcess                  Stage2aLiveRoleIdentity            `json:"bridge_process"`
	AdapterProcess                 stage2aMemberObservedProcess       `json:"adapter_process"`
	RelaySocket                    Stage2aRelayClaim                  `json:"relay_socket"`
	RelaySocketBirthtimeNS         string                             `json:"relay_socket_birthtime_ns"`
	CLIPath                        string                             `json:"cli_path"`
	CLISHA256                      string                             `json:"cli_sha256"`
	Peer                           SoulCooperativeRelayPeerSnapshotV3 `json:"peer"`
	ChallengeNonceBase64URL        string                             `json:"challenge_nonce_base64url"`
	IssuedAt                       string                             `json:"issued_at"`
	ExpiresAt                      string                             `json:"expires_at"`
}

func soulCooperativeCLIInSealedR(ref stage2aDomainInventoryRefV3, path, sha string) bool {
	if ref.Domain != "R-runtime" || !stage2aAbsolutePath(path) ||
		!stage2aPrefixedDigest.MatchString(sha) ||
		recheckHQStage2aDomainFiles(ref) != nil {
		return false
	}
	_, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil {
		return false
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != ref.InventoryDigest || inv.Domain != "R-runtime" ||
		inv.InstallationID != ref.InstallationID {
		return false
	}
	found := 0
	for _, row := range inv.Files {
		if row.Path == "runtime/bin/claude" {
			if row.Kind != "regular" || row.Mode != "0550" || row.ComponentID != "adapter" ||
				row.SHA256 != sha || filepath.Join(ref.Snapshot.Path, filepath.FromSlash(row.Path)) != path {
				return false
			}
			found++
		}
	}
	return found == 1 && recheckHQStage2aDomainFiles(ref) == nil
}

// CooperativeRelayPeer signs one request-scoped CLI warrant after A verifies
// its process, parent adapter and current two independent live leases. B
// supplies PIDVersion from the accepted relay socket and must recheck that
// same audit token before each HTTP request; A independently binds PID/start.
func (s *Stage2aService) CooperativeRelayPeer(hqUID int, epoch string,
	q SoulCooperativeRelayPeerRequestV3,
	paired func(string, func() error) error) (SoulCooperativeRelayPeerReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeRelayPeerReplyV3
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeRelayPeerRequestV3(rawQ); err != nil ||
		paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || len(live.memberReadyEnvelope) == 0 ||
		q.ReadySHA256 != stage2aReservationSHA256(live.memberReadyEnvelope) ||
		q.BridgeObservedSHA256 != stage2aReservationSHA256(live.bridgeObservedEnvelope) ||
		q.BLeaseSHA256 != live.bridgeLiveSHA ||
		q.BLeaseSequence != live.bridgeLiveSequence ||
		q.BridgePID != live.bridgeNativePID ||
		q.BridgeStartSeconds != live.bridgeNativeProcess.StartSeconds ||
		q.BridgeStartMicros != live.bridgeNativeProcess.StartMicros ||
		q.RelaySocket != live.bridgeRelayClaim ||
		q.RelaySocketBirthtimeNS != live.bridgeRelayBirthtimeNS ||
		len(live.peerNonces) >= 256 || live.peerNonces[q.ChallengeNonceBase64URL] ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	state := live.childGrants[q.MemberID]
	if state == nil || state.childPID <= 1 ||
		state.memberLaunchID != q.MemberLaunchID || state.memberSelector != q.MemberSelector ||
		q.MemberLeaseSHA256 != state.lastLeaseSHA ||
		q.MemberLeaseSequence != state.lastSequence ||
		q.Peer.ParentPID != state.childPID ||
		q.Peer.ParentStartSeconds != state.child.StartSeconds ||
		q.Peer.ParentStartMicros != state.child.StartMicros ||
		q.Peer.ParentUID != int(state.child.EffectiveUID) ||
		q.Peer.UID != int(state.child.EffectiveUID) {
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
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) ||
			!cooperativeBSocketBirthtimeMatches(soulCooperativeBEndpointV3{
				Directory: installed.RelayDirectory.Path, SocketPath: q.RelaySocket.Path,
				SocketMode: q.RelaySocket.Socket.Mode, OwnerUID: int(q.RelaySocket.Socket.UID),
				GroupGID: int(q.RelaySocket.Socket.GID)}, q.RelaySocketBirthtimeNS) {
			return errSoulCooperativeAuthority
		}
		readyRaw, err := verifyStage2aStoredARecordV3(live.memberReadyEnvelope,
			stage2aCooperativeReadyPurpose, 3, pub)
		var ready soulCooperativeReadyPayloadV3
		bLeaseRaw, bLeaseErr := verifyStage2aStoredARecordV3(live.bridgeLiveEnvelope,
			SoulCooperativeBLivePurposeV3, 3, pub)
		var bLease soulCooperativeBLivePayloadV3
		memberLeaseRaw, memberLeaseErr := verifyStage2aStoredARecordV3(state.lastLeaseEnvelope,
			stage2aCooperativeLeasePurpose, 3, pub)
		var memberLease stage2aCooperativeLeasePayload
		assignmentRaw, assignmentErr := verifyStage2aStoredARecordV3(live.memberEnvelope,
			stage2aMemberSetAssignmentPurpose, 1, pub)
		var assignment soulCooperativeMemberSetAssignmentV3
		if err != nil || bLeaseErr != nil || memberLeaseErr != nil || assignmentErr != nil ||
			stage2aDecodeExact(readyRaw, &ready) != nil ||
			stage2aDecodeExact(bLeaseRaw, &bLease) != nil ||
			stage2aDecodeExact(memberLeaseRaw, &memberLease) != nil ||
			stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
			ready.ProfileInForce != "managed-cooperative" ||
			ready.BridgeObservedSHA256 != q.BridgeObservedSHA256 ||
			bLease.ReadySHA256 != q.ReadySHA256 ||
			bLease.Sequence != q.BLeaseSequence ||
			memberLease.ReadyEnvelopeSHA256 != q.ReadySHA256 ||
			memberLease.Sequence != q.MemberLeaseSequence ||
			memberLease.MemberID != q.MemberID ||
			assignment.ProfileInForce != "managed-cooperative" ||
			assignment.ReservationSHA256 != live.digest {
			return errSoulCooperativeAuthority
		}
		selected := -1
		for i, assigned := range assignment.Members {
			if assigned.MemberID == q.MemberID {
				selected = i
			}
		}
		if selected < 0 || assignment.Members[selected].LaunchID != q.MemberLaunchID ||
			assignment.Members[selected].MemberSelector != q.MemberSelector ||
			assignment.Members[selected].AdjacentCLIPath != q.CLIPath ||
			assignment.Members[selected].AdjacentCLISHA256 != q.CLISHA256 ||
			ready.Members[selected].MemberID != q.MemberID ||
			ready.Members[selected].BArmReceiptSHA256 == "" ||
			!soulCooperativeCLIInSealedR(installed.RuntimeV3, q.CLIPath, q.CLISHA256) {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		if !now.Before(live.bridgeLiveExpires) || !now.Before(state.lastExpiry) ||
			!now.Before(live.memberReadyExpires) {
			return errSoulCooperativeAuthority
		}
		for _, id := range [2]string{"m_lead", "m_spec"} {
			active := live.childGrants[id]
			if active == nil || active.childPID <= 1 {
				return errSoulCooperativeAuthority
			}
			launcher, e1 := observeStage2aRoleProcess(active.launcherPID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, e2 := observeStage2aChildProcess(active.childPID, active.launcherPID,
				installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if e1 != nil || e2 != nil || !sameSoulKernelProcess(active.launcher, launcher) ||
				!sameSoulKernelProcess(active.child, child) {
				return errSoulCooperativeAuthority
			}
		}
		peer, err := observeStage2aQualificationProcess(q.Peer.PID, q.CLIPath, nil, true)
		parent, parentErr := observeStage2aChildProcess(state.childPID, state.launcherPID,
			installed.Policy.Runner, *installed.Policy.LaunchInputs)
		if err != nil || parentErr != nil ||
			peer.Kernel.PID != q.Peer.PID || peer.Kernel.ParentPID != state.childPID ||
			peer.Kernel.StartSeconds != q.Peer.StartSeconds ||
			peer.Kernel.StartMicros != q.Peer.StartMicros ||
			peer.Kernel.RealUID != uint32(q.Peer.UID) ||
			peer.Kernel.EffectiveUID != uint32(q.Peer.UID) ||
			peer.Kernel.SavedUID != uint32(q.Peer.UID) ||
			peer.Kernel.RealGID != uint32(installed.Policy.Runner.GID) ||
			peer.Kernel.PrimaryGroupGID != uint32(installed.Policy.Runner.GID) ||
			peer.Kernel.SavedGID != uint32(installed.Policy.Runner.GID) ||
			!sameSoulKernelProcess(state.child, parent) ||
			parent.StartSeconds != q.Peer.ParentStartSeconds ||
			parent.StartMicros != q.Peer.ParentStartMicros ||
			ready.Members[selected].ChildProcess != stage2aMemberProcessIdentity(parent,
				assignment.Members[selected].CommandSHA256) {
			return errSoulCooperativeAuthority
		}
		until := minStage2aTime(now.Add(5*time.Second), live.bridgeLiveExpires)
		until = minStage2aTime(until, state.lastExpiry)
		until = minStage2aTime(until, live.memberReadyExpires)
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeRelayPeerPayloadV3{Contract: "machine/v3",
			Kind: "soul-cooperative-relay-peer", SchemaVersion: 3,
			ProfileInForce: "managed-cooperative", HostID: installed.Policy.HostID,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			HQEpoch: epoch, ReservationSHA256: live.digest,
			AssignmentEnvelopeSHA256:       live.memberSHA,
			MemberBAuthorityEnvelopeSHA256: stage2aReservationSHA256(live.memberBAuthorityEnvelope),
			BridgeObservedSHA256:           q.BridgeObservedSHA256, ReadySHA256: q.ReadySHA256,
			BLeaseSHA256: q.BLeaseSHA256, BLeaseSequence: q.BLeaseSequence,
			MemberLeaseSHA256:   q.MemberLeaseSHA256,
			MemberLeaseSequence: q.MemberLeaseSequence,
			MemberID:            q.MemberID, MemberLaunchID: q.MemberLaunchID,
			MemberSelector: q.MemberSelector,
			BridgeProcess:  stage2aLiveRoleIdentity(live.bridgeNativeProcess),
			AdapterProcess: stage2aMemberProcessIdentity(parent,
				assignment.Members[selected].CommandSHA256),
			RelaySocket: q.RelaySocket, RelaySocketBirthtimeNS: q.RelaySocketBirthtimeNS,
			CLIPath: q.CLIPath, CLISHA256: q.CLISHA256, Peer: q.Peer,
			ChallengeNonceBase64URL: q.ChallengeNonceBase64URL,
			IssuedAt:                now.Format(time.RFC3339Nano), ExpiresAt: until.Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(payload, 3,
			SoulCooperativeRelayPeerPurposeV3, pub, s.sign)
		if err != nil || len(envelope) == 0 || len(envelope) > 8192 ||
			!time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		peerAgain, e1 := observeStage2aQualificationProcess(q.Peer.PID, q.CLIPath, nil, true)
		parentAgain, e2 := observeStage2aChildProcess(state.childPID, state.launcherPID,
			installed.Policy.Runner, *installed.Policy.LaunchInputs)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(peer.Kernel, peerAgain.Kernel) ||
			!sameSoulKernelProcess(parent, parentAgain) ||
			!cooperativeBSocketBirthtimeMatches(soulCooperativeBEndpointV3{
				Directory: installed.RelayDirectory.Path, SocketPath: q.RelaySocket.Path,
				SocketMode: q.RelaySocket.Socket.Mode, OwnerUID: int(q.RelaySocket.Socket.UID),
				GroupGID: int(q.RelaySocket.Socket.GID)}, q.RelaySocketBirthtimeNS) {
			return errSoulCooperativeAuthority
		}
		if live.peerNonces == nil {
			live.peerNonces = make(map[string]bool, 8)
		}
		live.peerNonces[q.ChallengeNonceBase64URL] = true
		if live.peerWarrants == nil {
			live.peerWarrants = make(map[string][]byte, 8)
		}
		live.peerWarrants[stage2aReservationSHA256(envelope)] = append([]byte(nil), envelope...)
		reply = SoulCooperativeRelayPeerReplyV3{
			PeerEnvelopeBase64URL:        base64.RawURLEncoding.EncodeToString(envelope),
			PeerSHA256:                   stage2aReservationSHA256(envelope),
			MemberLeaseEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(state.lastLeaseEnvelope),
			MemberLeaseSHA256:            state.lastLeaseSHA}
		return nil
	})
	if err != nil || !ran || reply.PeerSHA256 == "" {
		return SoulCooperativeRelayPeerReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
