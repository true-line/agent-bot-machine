//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

func cooperativeHProcessMatchesV3(h soulCooperativeHProcessV3, a soulKernelProcessSnapshot) bool {
	return h.PID == a.PID && h.UID == int(a.EffectiveUID) &&
		h.GID == int(a.PrimaryGroupGID) && h.StartSeconds == a.StartSeconds &&
		h.StartMicros == a.StartMicros
}

// CooperativeChildObserve signs the two-child aggregate only after A samples
// both exact granted wrappers and stock children twice. H's committed rows
// are checked against those samples, then retained for separate Ready proof.
func (s *Stage2aService) CooperativeChildObserve(hqUID int, epoch string,
	q SoulCooperativeChildObserveRequestV3,
	paired func(string, func() error) error) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch ||
		len(q.Members) != 2 || q.Members[0].MemberID != "m_lead" ||
		q.Members[1].MemberID != "m_spec" {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || len(live.childObservationEnvelope) != 0 ||
		len(live.childGrants) != 2 || len(live.provisionalHQMap) == 0 ||
		len(live.memberBAuthorityEnvelope) == 0 ||
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
		mapQ := Stage2aMemberProvisionalMapRequest{
			Stage2aStopRequest:            q.Stage2aStopRequest,
			ProvisionalHQMappingBase64URL: base64.RawURLEncoding.EncodeToString(live.provisionalHQMap),
			ProvisionalHQMappingSHA256:    live.provisionalHQMapSHA256}
		_, mapping, err := decodeSoulCooperativeProvisionalMap(mapQ)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		assignmentRaw, err := verifyStage2aStoredARecordV3(live.memberEnvelope,
			stage2aMemberSetAssignmentPurpose, 1, pub)
		var assignment soulCooperativeMemberSetAssignmentV3
		reservationRaw, _, reservationErr := verifySoulCooperativePurposeV3(live.envelope,
			pub, soulCooperativeReservationPurposeV3)
		var reservation soulCooperativeReservationPayloadV3
		if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
			reservationErr != nil || stage2aDecodeExact(reservationRaw, &reservation) != nil ||
			assignment.ProfileInForce != "managed-cooperative" ||
			assignment.ReservationSHA256 != q.ReservationSHA256 ||
			mapping.AssignmentEnvelopeSHA256 != live.memberSHA {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		mapExpires, e1 := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
		assignmentExpires, e2 := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
		reservationExpires, e3 := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
		if e1 != nil || e2 != nil || e3 != nil || !now.Before(mapExpires) ||
			!now.Before(assignmentExpires) || !now.Before(reservationExpires) {
			return errSoulCooperativeAuthority
		}
		var observed [2]stage2aObservedMemberChild
		var hDigests [2]string
		for i, input := range q.Members {
			state := live.childGrants[input.MemberID]
			_, h, err := decodeSoulCooperativeHChildReceipt(input)
			assigned := assignment.Members[i]
			if state == nil || err != nil || state.childPID != 0 ||
				input.MemberID != assigned.MemberID || input.MemberID != mapping.Members[i].MemberID ||
				input.MemberLaunchID != assigned.LaunchID ||
				input.MemberSelector != assigned.MemberSelector ||
				input.MemberSelector != mapping.Members[i].MemberSelector ||
				input.MemberLaunchID != state.memberLaunchID ||
				input.MemberSelector != state.memberSelector ||
				input.GrantSHA256 != state.grantSHA ||
				input.ChildLauncherPID != state.launcherPID ||
				h.ReservationSHA256 != q.ReservationSHA256 ||
				h.AssignmentEnvelopeSHA256 != live.memberSHA ||
				h.InstallationID != q.InstallationID || h.StartID != q.StartID ||
				h.LaunchID != q.LaunchID || h.HQEpoch != epoch ||
				h.LauncherProcess.UID != installed.Policy.Runner.UID ||
				h.LauncherProcess.GID != installed.Policy.Runner.GID ||
				h.ChildProcess.UID != installed.Policy.Runner.UID ||
				h.ChildProcess.GID != installed.Policy.Runner.GID {
				return errSoulCooperativeAuthority
			}
			launcher, err := observeStage2aRoleProcess(input.ChildLauncherPID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			if err != nil || !sameSoulKernelProcess(launcher, state.launcher) ||
				!cooperativeHProcessMatchesV3(h.LauncherProcess, launcher) {
				return errSoulCooperativeAuthority
			}
			child, err := observeStage2aChildProcess(input.ChildPID,
				input.ChildLauncherPID, installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if err != nil || !cooperativeHProcessMatchesV3(h.ChildProcess, child) ||
				assigned.CommandSHA256 != installed.Policy.LaunchInputs.ComponentDigests["adapter"] {
				return errSoulCooperativeAuthority
			}
			observed[i] = stage2aObservedMemberChild{MemberID: input.MemberID,
				CommandPath: assigned.CommandPath, CommandSHA256: assigned.CommandSHA256,
				Launcher: launcher, Child: child}
			hDigests[i] = input.HObservationSHA256
		}
		for i := range observed {
			launcher, err := observeStage2aRoleProcess(observed[i].Launcher.PID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, e2 := observeStage2aChildProcess(observed[i].Child.PID,
				observed[i].Launcher.PID, installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if err != nil || e2 != nil || !sameSoulKernelProcess(observed[i].Launcher, launcher) ||
				!sameSoulKernelProcess(observed[i].Child, child) {
				return errSoulCooperativeAuthority
			}
		}
		until := minStage2aTime(now.Add(15*time.Second), mapExpires)
		until = minStage2aTime(until, assignmentExpires)
		until = minStage2aTime(until, reservationExpires)
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		payload := stage2aMemberChildObservationPayload{Contract: "machine/v3",
			Kind: "stage2a-member-set-child-observation", SchemaVersion: 1,
			ProfileInForce: "managed-cooperative", HostID: installed.Policy.HostID,
			InstallationID: q.InstallationID, SoulID: installed.Policy.Runner.SoulID,
			StartID: q.StartID, HQEpoch: epoch, ReservationSHA256: q.ReservationSHA256,
			AssignmentEnvelopeSHA256:   live.memberSHA,
			ProvisionalHQMappingSHA256: live.provisionalHQMapSHA256,
			ProvisionalHQMapping:       bytes.Clone(live.provisionalHQMap),
			ObservedAt:                 now.Format(time.RFC3339Nano), IssuedAt: now.Format(time.RFC3339Nano),
			ExpiresAt: until.Format(time.RFC3339Nano)}
		for i, member := range observed {
			payload.Members[i].MemberID = member.MemberID
			payload.Members[i].LaunchID = assignment.Members[i].LaunchID
			payload.Members[i].MemberSelector = assignment.Members[i].MemberSelector
			payload.Members[i].RuntimeID = mapping.Members[i].RuntimeID
			payload.Members[i].GrantSHA256 = q.Members[i].GrantSHA256
			payload.Members[i].LauncherProcess = stage2aMemberLauncherIdentity(member.Launcher)
			payload.Members[i].ChildProcess = stage2aMemberProcessIdentity(member.Child,
				member.CommandSHA256)
		}
		envelope, err := signStage2aEnvelope(payload, 1, Stage2aMemberChildObservationPurpose,
			pub, s.sign)
		if err != nil || len(envelope) == 0 || len(envelope) > 16<<10 ||
			!time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		for i := range observed {
			launcher, err := observeStage2aRoleProcess(observed[i].Launcher.PID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, e2 := observeStage2aChildProcess(observed[i].Child.PID,
				observed[i].Launcher.PID, installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if err != nil || e2 != nil || !sameSoulKernelProcess(observed[i].Launcher, launcher) ||
				!sameSoulKernelProcess(observed[i].Child, child) {
				return errSoulCooperativeAuthority
			}
		}
		live.childObservationEnvelope = envelope
		for i, input := range q.Members {
			state := live.childGrants[input.MemberID]
			state.childPID = input.ChildPID
			state.child = observed[i].Child
			state.hObservationSHA = hDigests[i]
		}
		reply = Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: stage2aReservationSHA256(envelope)}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aHelloReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
