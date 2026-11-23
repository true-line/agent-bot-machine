//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"
)

// The R wrapper accepts aggregate Ready only for the two exact A-observed
// children and the B policy selected by its one-use grant. Ready alone never
// releases ACP: the wrapper must also obtain a fresh post-Ready member lease.
func verifyStage2aProtectedMemberReady(readyReply, observationReply Stage2aHelloReply,
	in Stage2aRoleInvocation, grantSHA256 string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, now time.Time) (stage2aMemberReadyPayload, error) {
	var ready stage2aMemberReadyPayload
	invalid := errors.New("invalid protected two-member Ready")
	exec := in.ChildExec
	if exec == nil || exec.MemberID == "" || !stage2aPrefixedDigest.MatchString(readyReply.SHA256) ||
		!stage2aPrefixedDigest.MatchString(observationReply.SHA256) ||
		in.Binding.ProfileInForce != "managed-protected" {
		return ready, invalid
	}
	observation, err := verifyStage2aMemberChildObservation(observationReply,
		in, grantSHA256, launcher, child, pub, now)
	if err != nil {
		return ready, invalid
	}
	envelope, err := decodeStage2aRoleBase64(readyReply.EnvelopeBase64URL, 16<<10)
	if err != nil || stage2aReservationSHA256(envelope) != readyReply.SHA256 {
		return ready, invalid
	}
	raw, err := verifyStage2aStoredARecordV3(envelope, Stage2aMemberReadyPurpose, 1, pub)
	if err != nil || stage2aDecodeExact(raw, &ready) != nil {
		return ready, invalid
	}
	canonical, err := marshalStage2aReservationJCS(ready)
	if err != nil || !bytes.Equal(raw, canonical) || ready.Contract != "machine/v3" ||
		ready.Kind != "stage2a-member-set-ready" || ready.SchemaVersion != 1 ||
		ready.ProfileInForce != "managed-protected" || ready.HostID != in.Binding.HostID ||
		ready.InstallationID != in.Start.InstallationID || ready.SoulID != in.Start.SoulID ||
		ready.StartID != in.Start.StartID || ready.HQEpoch != in.Start.HQEpoch ||
		ready.ReservationSHA256 != exec.ReservationSHA256 ||
		ready.ChildObservationEnvelopeSHA256 != observationReply.SHA256 ||
		ready.ProvisionalHQMappingSHA256 != observation.ProvisionalHQMappingSHA256 ||
		ready.BridgeProcess.PID != exec.Bridge.PID ||
		ready.BridgeProcess.UID != int(exec.Bridge.UID) || ready.BridgeProcess.GID != int(exec.Bridge.GID) ||
		ready.BridgeProcess.StartSeconds != exec.Bridge.StartSeconds ||
		ready.BridgeProcess.StartMicros != exec.Bridge.StartMicros ||
		ready.BridgeProcess.ExecutableSHA256 != in.Launch.ComponentDigests["bridge"] {
		return ready, invalid
	}
	assignmentEnvelope, err := decodeStage2aRoleBase64(exec.MemberSetAssignmentEnvelopeBase64URL, 16<<10)
	if err != nil || ready.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(assignmentEnvelope) {
		return ready, invalid
	}
	assignmentRaw, err := verifyStage2aStoredARecordV3(assignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, pub)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.Contract != "machine/v3" || assignment.Kind != "stage2a-member-set-assignment" ||
		assignment.SchemaVersion != 1 || assignment.ProfileInForce != "managed-protected" ||
		assignment.HostID != ready.HostID || assignment.InstallationID != ready.InstallationID ||
		assignment.SoulID != ready.SoulID || assignment.StartID != ready.StartID ||
		assignment.HQEpoch != ready.HQEpoch ||
		assignment.ReservationSHA256 != ready.ReservationSHA256 ||
		assignment.BAuthority.EnvelopeSHA256 != ready.BAuthoritySHA256 {
		return ready, invalid
	}
	bEnvelope, err := decodeStage2aRoleBase64(exec.MemberBAuthorityEnvelopeBase64URL, 16<<10)
	if err != nil || ready.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(bEnvelope) {
		return ready, invalid
	}
	bRaw, err := verifyStage2aStoredARecordV3(bEnvelope, stage2aBMemberAuthorityPurpose, 1, pub)
	var b stage2aBMemberAuthorityPayload
	if err != nil || stage2aDecodeExact(bRaw, &b) != nil ||
		b.Contract != "machine/v3" || b.Kind != "stage2a-b-member-authority" ||
		b.SchemaVersion != 1 || b.ProfileInForce != "managed-protected" ||
		b.HostID != ready.HostID || b.InstallationID != ready.InstallationID ||
		b.SoulID != ready.SoulID || b.StartID != ready.StartID || b.HQEpoch != ready.HQEpoch ||
		b.ReservationSHA256 != ready.ReservationSHA256 ||
		b.MemberSetAssignmentEnvelopeSHA256 != ready.AssignmentEnvelopeSHA256 ||
		b.BAuthority.EnvelopeSHA256 != ready.BAuthoritySHA256 ||
		b.PlanID != assignment.PlanID || b.PlanDigest != assignment.PlanDigest ||
		b.OwnerPlanMemberSetSHA256 != assignment.OwnerPlanMemberSetSHA256 ||
		b.HQUID != in.Start.HQUID || b.RunnerUID != in.Runner.UID {
		return ready, invalid
	}
	bridgeRaw, bridgeErr := marshalStage2aReservationJCS(assignment.Bridge)
	if bridgeErr != nil || !bytes.Equal(b.Bridge, bridgeRaw) {
		return ready, invalid
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, ready.IssuedAt)
	observed, observedErr := time.Parse(time.RFC3339Nano, ready.ObservedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	observationExpires, observationExpiryErr := time.Parse(time.RFC3339Nano, observation.ExpiresAt)
	assignmentExpires, assignmentExpiryErr := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	bExpires, bExpiryErr := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	grantExpires, grantExpiryErr := time.Parse(time.RFC3339Nano, exec.GrantExpiresAt)
	if issueErr != nil || observedErr != nil || expiryErr != nil || observationExpiryErr != nil ||
		assignmentExpiryErr != nil || bExpiryErr != nil || grantExpiryErr != nil ||
		observed.After(issued) || issued.After(now) || !now.Before(expires) ||
		!expires.After(issued) || expires.Sub(issued) > stage2aLiveLease ||
		expires.After(observationExpires) || expires.After(assignmentExpires) ||
		expires.After(bExpires) || expires.After(grantExpires) {
		return ready, invalid
	}
	selected := 0
	for i, member := range ready.Members {
		observedMember := observation.Members[i]
		assigned := assignment.Members[i]
		bMember := b.Members[i]
		arm := member.BridgeArm
		armRaw, armErr := marshalStage2aReservationJCS(arm)
		if armErr != nil || member.MemberID != assigned.MemberID ||
			member.MemberID != observedMember.MemberID || member.LaunchID != assigned.LaunchID ||
			bMember.MemberID != assigned.MemberID || bMember.LaunchID != assigned.LaunchID ||
			bMember.MemberSelector != assigned.MemberSelector ||
			bMember.AdjacentCLIPath != assigned.AdjacentCLIPath ||
			bMember.AdjacentCLISHA256 != assigned.AdjacentCLISHA256 ||
			member.MemberSelector != assigned.MemberSelector || member.RuntimeID != observedMember.RuntimeID ||
			member.BridgeArmReceiptSHA256 != stage2aReservationSHA256(armRaw) ||
			arm.MemberID != member.MemberID || arm.MemberSelector != member.MemberSelector ||
			arm.RuntimeID != member.RuntimeID ||
			arm.ChildObservationEnvelopeSHA256 != observationReply.SHA256 ||
			arm.AdapterPID != observedMember.ChildProcess.PID ||
			arm.AdapterUID != observedMember.ChildProcess.UID ||
			arm.AdapterGID != observedMember.ChildProcess.GID ||
			arm.AdapterStartSeconds != observedMember.ChildProcess.StartSeconds ||
			arm.AdapterStartMicros != observedMember.ChildProcess.StartMicros ||
			arm.BridgeUID != int(exec.Bridge.UID) || arm.State != "armed" ||
			arm.RelayPeerRule != "a-attested-live-direct-child-of-adapter-v1" ||
			arm.RelayPeerState != "unobserved" ||
			arm.ProviderIngress != "withheld-pending-per-peer-attestation" {
			return ready, invalid
		}
		if member.MemberID == exec.MemberID {
			selected++
			if member.LaunchID != exec.MemberLaunchID || member.MemberSelector != exec.MemberSelector ||
				observedMember.GrantSHA256 != grantSHA256 ||
				observedMember.LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
				observedMember.ChildProcess != stage2aMemberProcessIdentity(child, exec.ExecutableSHA256) {
				return ready, invalid
			}
		}
	}
	if selected != 1 {
		return ready, invalid
	}
	return ready, nil
}
