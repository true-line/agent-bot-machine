//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func cooperativeBSocketBirthtimeMatches(e soulCooperativeBEndpointV3, expected string) bool {
	if expected == "" || !cooperativeBParentReady(e) {
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
		socket.Btim.Sec > 0 && socket.Btim.Nsec >= 0 && socket.Btim.Nsec < 1_000_000_000 &&
		socket.Btim.Sec <= (1<<63-1)/1_000_000_000 &&
		strconv.FormatInt(socket.Btim.Sec*1_000_000_000+socket.Btim.Nsec, 10) == expected
}

func cooperativeObservedBStillLive(live *soulCooperativeLiveV3,
	installed soulCooperativeInstalledV3) bool {
	if live == nil || live.bridgeNativePID <= 1 || len(live.bridgeObservedEnvelope) == 0 ||
		live.bridgeNativeProcess.PID != live.bridgeNativePID {
		return false
	}
	p := installed.Policy
	launcher, err := cooperativeBRoleProcess(live.bridgePID, p)
	if err != nil || !sameSoulKernelProcess(launcher, live.bridgeProcess) {
		return false
	}
	child, err := observeSoulProcess(live.bridgeNativePID, SoulBridgeBinary,
		[]string{SoulBridgeBinary, "--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"})
	if err != nil || child.Kernel.ParentPID != launcher.PID ||
		child.Kernel.ProcessGroupID != child.Kernel.PID ||
		!sameSoulKernelProcess(child.Kernel, live.bridgeNativeProcess) {
		return false
	}
	parents := soulCooperativeBParentsV3{Broker: installed.BrokerDirectory,
		Member: installed.MemberDirectory, Relay: installed.RelayDirectory}
	_, endpoints, _, err := soulCooperativeBLaunchIntentV3(p, p.ReviewedStartID, parents)
	return err == nil && cooperativeBSocketMatchesClaim(endpoints.Relay, live.bridgeRelayClaim) &&
		cooperativeBSocketBirthtimeMatches(endpoints.Relay, live.bridgeRelayBirthtimeNS)
}

type soulCooperativeBLivePayloadV3 struct {
	Contract                       string                  `json:"contract"`
	Kind                           string                  `json:"kind"`
	SchemaVersion                  int                     `json:"schema_version"`
	ProfileInForce                 string                  `json:"profile_in_force"`
	HostID                         string                  `json:"host_id"`
	InstallationID                 string                  `json:"installation_id"`
	StartID                        string                  `json:"start_id"`
	LaunchID                       string                  `json:"launch_id"`
	PlanID                         string                  `json:"plan_id"`
	PlanDigest                     string                  `json:"plan_digest"`
	HQEpoch                        string                  `json:"hq_epoch"`
	ReservationSHA256              string                  `json:"reservation_sha256"`
	BridgeAssignmentSHA256         string                  `json:"bridge_assignment_sha256"`
	AssignmentEnvelopeSHA256       string                  `json:"assignment_envelope_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                  `json:"member_b_authority_envelope_sha256"`
	BridgeObservedSHA256           string                  `json:"bridge_observed_sha256"`
	ReadySHA256                    string                  `json:"ready_sha256"`
	BridgeProcess                  Stage2aLiveRoleIdentity `json:"bridge_process"`
	RelaySocket                    Stage2aRelayClaim       `json:"relay_socket"`
	ChallengeNonceBase64URL        string                  `json:"challenge_nonce_base64url"`
	Sequence                       uint64                  `json:"sequence"`
	IssuedAt                       string                  `json:"issued_at"`
	ExpiresAt                      string                  `json:"expires_at"`
}

// CooperativeBLive signs a short B lease only after aggregate Ready. H must
// authenticate the B broker peer before forwarding its fresh challenge.
func (s *Stage2aService) CooperativeBLive(hqUID int, epoch string,
	q SoulCooperativeBLiveRequestV3,
	paired func(string, func() error) error) (SoulCooperativeBLiveReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeBLiveReplyV3
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeBLiveRequestV3(rawQ); err != nil ||
		paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || len(live.memberReadyEnvelope) == 0 ||
		len(live.childObservationEnvelope) == 0 || len(live.childGrants) != 2 ||
		q.ReadySHA256 != stage2aReservationSHA256(live.memberReadyEnvelope) ||
		q.BridgeObservedSHA256 != stage2aReservationSHA256(live.bridgeObservedEnvelope) ||
		q.BridgePID != live.bridgeNativePID ||
		q.BridgeStartSeconds != live.bridgeNativeProcess.StartSeconds ||
		q.BridgeStartMicros != live.bridgeNativeProcess.StartMicros ||
		q.AfterSequence != live.bridgeLiveSequence ||
		q.ChallengeNonceBase64URL == live.bridgeLiveNonce ||
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
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		paths, err := cooperativeLaunchPaths(q.InstallationID)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		pid, err := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
		if err != nil || pid != live.dispatcherPID {
			return errSoulCooperativeAuthority
		}
		dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
		runner, e2 := observeSoulKernelProcess(live.runnerPID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
			!sameSoulKernelProcess(live.runner, runner) ||
			!cooperativeProcessPair(installed.Policy, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		readyRaw, err := verifyStage2aStoredARecordV3(live.memberReadyEnvelope,
			stage2aCooperativeReadyPurpose, 3, pub)
		var ready soulCooperativeReadyPayloadV3
		observedRaw, observedErr := verifyStage2aStoredARecordV3(live.bridgeObservedEnvelope,
			soulCooperativeBObservedPurposeV3, 3, pub)
		var observed soulCooperativeBObservedPayloadV3
		if err != nil || observedErr != nil ||
			stage2aDecodeExact(readyRaw, &ready) != nil ||
			stage2aDecodeExact(observedRaw, &observed) != nil ||
			ready.ProfileInForce != "managed-cooperative" ||
			ready.ReservationSHA256 != live.digest || ready.BridgeObservedSHA256 != q.BridgeObservedSHA256 ||
			ready.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(live.memberBAuthorityEnvelope) ||
			observed.ReservationSHA256 != live.digest ||
			observed.Bridge != stage2aLiveRoleIdentity(live.bridgeNativeProcess) ||
			observed.RelaySocket != live.bridgeRelayClaim {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		readyUntil, e3 := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
		observedUntil, e4 := time.Parse(time.RFC3339Nano, observed.ExpiresAt)
		approvedUntil, e5 := time.Parse(time.RFC3339Nano, installed.Policy.ApprovedUntil)
		prior, e6 := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
		wantPrior := live.memberReadyExpires
		if live.bridgeLiveSequence > 0 {
			wantPrior = live.bridgeLiveExpires
		}
		if e3 != nil || e4 != nil || e5 != nil || e6 != nil || !prior.Equal(wantPrior) ||
			!now.Before(prior) || !now.Before(readyUntil) || !now.Before(observedUntil) ||
			!now.Before(approvedUntil) {
			return errSoulCooperativeAuthority
		}
		for i, id := range [2]string{"m_lead", "m_spec"} {
			state := live.childGrants[id]
			if state == nil || state.childPID <= 1 || state.hObservationSHA == "" ||
				ready.Members[i].MemberID != id ||
				ready.Members[i].HObservationSHA256 != state.hObservationSHA ||
				ready.Members[i].GrantSHA256 != state.grantSHA {
				return errSoulCooperativeAuthority
			}
			launcher, e1 := observeStage2aRoleProcess(state.launcherPID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, e2 := observeStage2aChildProcess(state.childPID, state.launcherPID,
				installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if e1 != nil || e2 != nil || !sameSoulKernelProcess(state.launcher, launcher) ||
				!sameSoulKernelProcess(state.child, child) ||
				ready.Members[i].LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
				ready.Members[i].ChildProcess != stage2aMemberProcessIdentity(child,
					installed.Policy.LaunchInputs.ComponentDigests["adapter"]) {
				return errSoulCooperativeAuthority
			}
		}
		store := installed.claimStore()
		dir, err := store.open()
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer dir.Close()
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
				store.uid, store.gid) != nil {
			return errSoulCooperativeAuthority
		}
		until := minStage2aTime(now.Add(5*time.Second), readyUntil)
		until = minStage2aTime(until, observedUntil)
		until = minStage2aTime(until, approvedUntil)
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeBLivePayloadV3{Contract: "machine/v3",
			Kind: "soul-cooperative-b-live-lease", SchemaVersion: 3,
			ProfileInForce: "managed-cooperative", HostID: installed.Policy.HostID,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: epoch,
			ReservationSHA256: live.digest, BridgeAssignmentSHA256: live.bridgeSHA,
			AssignmentEnvelopeSHA256:       live.memberSHA,
			MemberBAuthorityEnvelopeSHA256: stage2aReservationSHA256(live.memberBAuthorityEnvelope),
			BridgeObservedSHA256:           q.BridgeObservedSHA256, ReadySHA256: q.ReadySHA256,
			BridgeProcess:           stage2aLiveRoleIdentity(live.bridgeNativeProcess),
			RelaySocket:             live.bridgeRelayClaim,
			ChallengeNonceBase64URL: q.ChallengeNonceBase64URL,
			Sequence:                q.AfterSequence + 1,
			IssuedAt:                now.Format(time.RFC3339Nano), ExpiresAt: until.Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(payload, 3, SoulCooperativeBLivePurposeV3,
			pub, s.sign)
		if err != nil || len(envelope) == 0 || len(envelope) > 8192 ||
			!time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		live.bridgeLiveSequence = payload.Sequence
		live.bridgeLiveExpires = until
		live.bridgeLiveNonce = q.ChallengeNonceBase64URL
		live.bridgeLiveEnvelope = bytes.Clone(envelope)
		live.bridgeLiveSHA = stage2aReservationSHA256(envelope)
		reply = SoulCooperativeBLiveReplyV3{
			ReadyEnvelopeBase64URL:          base64.RawURLEncoding.EncodeToString(live.memberReadyEnvelope),
			ReadySHA256:                     q.ReadySHA256,
			BridgeObservedEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(live.bridgeObservedEnvelope),
			BridgeObservedSHA256:            q.BridgeObservedSHA256,
			LeaseEnvelopeBase64URL:          base64.RawURLEncoding.EncodeToString(envelope),
			LeaseSHA256:                     stage2aReservationSHA256(envelope), LeaseSequence: payload.Sequence}
		return nil
	})
	if err != nil || !ran || reply.LeaseSHA256 == "" {
		return SoulCooperativeBLiveReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
