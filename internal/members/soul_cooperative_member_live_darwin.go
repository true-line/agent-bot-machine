//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// CooperativeMemberLive answers only the exact R wrapper that H observed on
// its existing admission socket. Each fresh wrapper nonce receives at most
// one five-second A lease; ACP input remains gated by the wrapper verifier.
func (s *Stage2aService) CooperativeMemberLive(hqUID int, epoch string,
	q SoulCooperativeMemberLiveRequestV3,
	paired func(string, func() error) error) (SoulCooperativeMemberLiveReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeMemberLiveReplyV3
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeMemberLiveRequestV3(rawQ); err != nil ||
		paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || len(live.memberReadyEnvelope) == 0 ||
		len(live.childObservationEnvelope) == 0 || len(live.childGrants) != 2 ||
		q.ReadySHA256 != stage2aReservationSHA256(live.memberReadyEnvelope) ||
		q.AssignmentEnvelopeSHA256 != live.memberSHA ||
		q.MemberBAuthoritySHA256 != stage2aReservationSHA256(live.memberBAuthorityEnvelope) ||
		q.PeerUID != live.installed.Policy.Runner.UID ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	state := live.childGrants[q.MemberID]
	if state == nil || state.childPID <= 1 || state.memberID != q.MemberID ||
		state.memberLaunchID != q.MemberLaunchID || state.memberSelector != q.MemberSelector ||
		state.grantSHA != q.GrantSHA256 || state.launcherPID != q.LauncherPID ||
		state.childPID != q.ChildPID ||
		state.launcher.StartSeconds != q.LauncherStartSeconds ||
		state.launcher.StartMicros != q.LauncherStartMicros ||
		state.child.StartSeconds != q.ChildStartSeconds ||
		state.child.StartMicros != q.ChildStartMicros ||
		state.lastSequence != q.AfterSequence || state.lastNonce == q.ChallengeNonceBase64URL {
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
		grantRaw, grantErr := verifyStage2aStoredARecordV3(state.grantEnvelope,
			stage2aCooperativeChildGrantPurpose, 1, pub)
		var grant stage2aCooperativeChildGrant
		if err != nil || grantErr != nil ||
			stage2aDecodeExact(readyRaw, &ready) != nil ||
			stage2aDecodeExact(grantRaw, &grant) != nil ||
			ready.ProfileInForce != "managed-cooperative" ||
			ready.ReservationSHA256 != live.digest ||
			ready.AssignmentEnvelopeSHA256 != live.memberSHA ||
			grant.ReservationSHA256 != live.digest || grant.MemberID != q.MemberID ||
			grant.MemberLaunchID != q.MemberLaunchID ||
			grant.MemberSelector != q.MemberSelector || grant.PID != q.LauncherPID {
			return errSoulCooperativeAuthority
		}
		selected := -1
		for i, member := range ready.Members {
			if member.MemberID == q.MemberID {
				selected = i
			}
		}
		if selected < 0 || ready.Members[selected].MemberLaunchID != q.MemberLaunchID ||
			ready.Members[selected].MemberSelector != q.MemberSelector ||
			ready.Members[selected].GrantSHA256 != q.GrantSHA256 ||
			ready.Members[selected].HObservationSHA256 != state.hObservationSHA {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		readyUntil, e3 := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
		grantUntil, e4 := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
		approvedUntil, e5 := time.Parse(time.RFC3339Nano, installed.Policy.ApprovedUntil)
		prior, e6 := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
		wantPrior := grantUntil
		if state.lastSequence > 0 {
			wantPrior = state.lastExpiry
		}
		if e3 != nil || e4 != nil || e5 != nil || e6 != nil || !prior.Equal(wantPrior) ||
			!now.Before(prior) || !now.Before(readyUntil) ||
			!now.Before(grantUntil) || !now.Before(approvedUntil) {
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
		if checkStage2aGrantedRoleProcess(q.PeerPID, installed.Policy.Runner.UID,
			installed.Policy.Runner.GID, "child", state.launcher) != nil {
			return errSoulCooperativeAuthority
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
		until = minStage2aTime(until, grantUntil)
		until = minStage2aTime(until, approvedUntil)
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		payload := stage2aCooperativeLeasePayload{Contract: "machine/v3",
			Kind: "soul-cooperative-member-live-lease", SchemaVersion: 3,
			ProfileInForce: "managed-cooperative", ReservationSHA256: live.digest,
			AssignmentEnvelopeSHA256: live.memberSHA,
			ReadyEnvelopeSHA256:      q.ReadySHA256, MemberID: q.MemberID,
			MemberLaunchID: q.MemberLaunchID, MemberSelector: q.MemberSelector,
			GrantSHA256:     q.GrantSHA256,
			LauncherProcess: stage2aMemberLauncherIdentity(state.launcher),
			ChildProcess: stage2aMemberProcessIdentity(state.child,
				installed.Policy.LaunchInputs.ComponentDigests["adapter"]),
			ChallengeNonceBase64URL: q.ChallengeNonceBase64URL,
			Sequence:                q.AfterSequence + 1,
			IssuedAt:                now.Format(time.RFC3339Nano), ExpiresAt: until.Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(payload, 3, stage2aCooperativeLeasePurpose,
			pub, s.sign)
		if err != nil || len(envelope) == 0 || len(envelope) > 8192 ||
			!time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		state.lastSequence = payload.Sequence
		state.lastExpiry = until
		state.lastNonce = q.ChallengeNonceBase64URL
		state.lastLeaseEnvelope = bytes.Clone(envelope)
		state.lastLeaseSHA = stage2aReservationSHA256(envelope)
		reply = SoulCooperativeMemberLiveReplyV3{
			ReadyEnvelopeBase64URL:          base64.RawURLEncoding.EncodeToString(live.memberReadyEnvelope),
			ReadySHA256:                     q.ReadySHA256,
			BridgeObservedEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(live.bridgeObservedEnvelope),
			BridgeObservedSHA256:            stage2aReservationSHA256(live.bridgeObservedEnvelope),
			LeaseEnvelopeBase64URL:          base64.RawURLEncoding.EncodeToString(envelope),
			LeaseSHA256:                     stage2aReservationSHA256(envelope), LeaseSequence: payload.Sequence}
		return nil
	})
	if err != nil || !ran || reply.LeaseSHA256 == "" {
		return SoulCooperativeMemberLiveReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
