//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"time"
)

func (s *Stage2aService) CooperativeMemberPolicy(hqUID int, epoch string,
	q SoulCooperativeMemberPolicyRequestV3, paired func(string, func() error) error,
) (SoulCooperativeMemberPolicyReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeMemberPolicyReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.bridgeBindVerified || len(live.bridgeObservedEnvelope) == 0 ||
		stage2aReservationSHA256(live.bridgeObservedEnvelope) != q.BridgeObservedSHA256 ||
		live.memberSHA == "" || stage2aReservationSHA256(live.memberEnvelope) != live.memberSHA ||
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
		observedRaw, err := verifyStage2aStoredARecordV3(live.bridgeObservedEnvelope,
			soulCooperativeBObservedPurposeV3, 3, pub)
		var observed soulCooperativeBObservedPayloadV3
		if err != nil || stage2aDecodeExact(observedRaw, &observed) != nil ||
			observed.ReservationSHA256 != q.ReservationSHA256 ||
			observed.BridgeAssignmentSHA256 != live.bridgeSHA ||
			observed.GrantNonce != live.bridgeGrantNonce ||
			observed.Launcher != stage2aLiveRoleIdentity(launcher) {
			return errSoulCooperativeAuthority
		}
		reservationRaw, _, reservationErr := verifySoulCooperativePurposeV3(live.envelope, pub,
			soulCooperativeReservationPurposeV3)
		var reservation soulCooperativeReservationPayloadV3
		bridgeRaw, _, bridgeErr := verifySoulCooperativePurposeV3(live.bridgeEnvelope, pub,
			soulCooperativeBridgeAssignmentPurposeV3)
		var bridge soulCooperativeBridgeAssignmentPayloadV3
		memberRaw, memberErr := verifyStage2aStoredARecordV3(live.memberEnvelope,
			stage2aMemberSetAssignmentPurpose, 1, pub)
		var member soulCooperativeMemberSetAssignmentV3
		if reservationErr != nil || bridgeErr != nil || memberErr != nil ||
			stage2aDecodeExact(reservationRaw, &reservation) != nil ||
			stage2aDecodeExact(bridgeRaw, &bridge) != nil ||
			stage2aDecodeExact(memberRaw, &member) != nil ||
			reservation.Assignment.PlanID != q.PlanID || reservation.Assignment.PlanDigest != q.PlanDigest ||
			bridge.PlanID != q.PlanID || bridge.PlanDigest != q.PlanDigest ||
			member.PlanID != q.PlanID || member.PlanDigest != q.PlanDigest ||
			member.ProfileInForce != "managed-cooperative" ||
			member.ReservationSHA256 != q.ReservationSHA256 ||
			member.BAuthority.Purpose != soulCooperativeBridgeAssignmentPurposeV3 ||
			member.BAuthority.EnvelopeSHA256 != live.bridgeSHA ||
			member.Bridge.UID != p.Bridge.UID || member.Bridge.GID != p.Bridge.GID ||
			member.RunnerUID != p.Runner.UID ||
			!reflect.DeepEqual(member.Bridge.Endpoints, bridge.Endpoints) ||
			!cooperativeBSocketMatchesClaim(bridge.Endpoints.Relay, observed.RelaySocket) {
			return errSoulCooperativeAuthority
		}
		child, err := observeSoulProcess(observed.Bridge.PID, SoulBridgeBinary,
			[]string{SoulBridgeBinary, "--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"})
		if err != nil || child.Kernel.ParentPID != launcher.PID ||
			child.Kernel.ProcessGroupID != child.Kernel.PID ||
			observed.Bridge != stage2aLiveRoleIdentity(child.Kernel) {
			return errSoulCooperativeAuthority
		}
		if len(p.MemberBridgeQualifications) != 2 ||
			member.Members[0].MemberID != p.MemberBridgeQualifications[0].MemberID ||
			member.Members[1].MemberID != p.MemberBridgeQualifications[1].MemberID ||
			member.Members[0].MemberID >= member.Members[1].MemberID ||
			member.Members[0].MemberSelector == member.Members[1].MemberSelector ||
			member.Members[0].LaunchID == member.Members[1].LaunchID {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		reservationExpires, e1 := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
		memberExpires, e2 := time.Parse(time.RFC3339Nano, member.ExpiresAt)
		until := minStage2aTime(reservationExpires, memberExpires)
		if e1 != nil || e2 != nil || !now.Before(until) {
			return errSoulCooperativeAuthority
		}
		if len(live.memberBAuthorityEnvelope) != 0 {
			store := installed.claimStore()
			dir, err := store.open()
			if err != nil {
				return errSoulCooperativeAuthority
			}
			defer dir.Close()
			lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
			if err != nil {
				return errSoulCooperativeAuthority
			}
			defer lock.Close()
			name := ".cooperative-member-policy-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
			if store.checkDirectory(dir) != nil ||
				cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
				stage2aCheckFinalizationFile(dir, name, store.uid, store.gid,
					live.memberBAuthorityEnvelope) != nil {
				return errSoulCooperativeAuthority
			}
			reply = SoulCooperativeMemberPolicyReplyV3{
				MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(live.memberEnvelope),
				MemberSetAssignmentSHA256:            live.memberSHA,
				MemberBAuthorityEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(live.memberBAuthorityEnvelope),
				MemberBAuthoritySHA256:               stage2aReservationSHA256(live.memberBAuthorityEnvelope),
				BridgeObservedSHA256:                 q.BridgeObservedSHA256}
			return nil
		}
		bridgeJSON, err := marshalStage2aReservationJCS(member.Bridge)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		payload := stage2aBMemberAuthorityPayload{Contract: "machine/v3", Kind: "stage2a-b-member-authority",
			SchemaVersion: 1, ProfileInForce: "managed-cooperative", HostID: p.HostID,
			InstallationID: q.InstallationID, SoulID: p.Runner.SoulID, StartID: q.StartID,
			HQEpoch: epoch, PlanID: q.PlanID, PlanDigest: q.PlanDigest,
			ReservationSHA256:                 q.ReservationSHA256,
			MemberSetAssignmentEnvelopeSHA256: live.memberSHA,
			OwnerPlanMemberSetSHA256:          p.OwnerPlanMemberSetSHA256,
			BAuthority:                        member.BAuthority, HQUID: p.HQUID, RunnerUID: p.Runner.UID,
			Bridge: bridgeJSON, IssuedAt: now.Format(time.RFC3339Nano),
			ExpiresAt: until.Format(time.RFC3339Nano)}
		for i, assigned := range member.Members {
			payload.Members[i] = stage2aBMemberAuthorityMember{MemberID: assigned.MemberID,
				LaunchID: assigned.LaunchID, MemberSelector: assigned.MemberSelector,
				AdjacentCLIPath:   assigned.AdjacentCLIPath,
				AdjacentCLISHA256: assigned.AdjacentCLISHA256,
				Qualification:     p.MemberBridgeQualifications[i].Qualification}
		}
		envelope, err := signStage2aEnvelope(payload, 1, stage2aBMemberAuthorityPurpose, pub, s.sign)
		if err != nil || len(envelope) > 16<<10 || !time.Now().Before(until) {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
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
		name := ".cooperative-member-policy-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil ||
			!time.Now().Before(until) {
			return errSoulCooperativeAuthority
		}
		if err := commitStage2aReservation(dir, name, envelope); err != nil {
			return errSoulCooperativeAuthority
		}
		live.memberBAuthorityEnvelope = bytes.Clone(envelope)
		reply = SoulCooperativeMemberPolicyReplyV3{
			MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(live.memberEnvelope),
			MemberSetAssignmentSHA256:            live.memberSHA,
			MemberBAuthorityEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(envelope),
			MemberBAuthoritySHA256:               stage2aReservationSHA256(envelope),
			BridgeObservedSHA256:                 q.BridgeObservedSHA256}
		return nil
	})
	if err != nil || !ran || reply.MemberBAuthoritySHA256 == "" {
		return SoulCooperativeMemberPolicyReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
