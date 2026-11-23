//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"
)

// HQ's committed two-member finalization must be authenticated by A before
// its first post-Ready lease. This field is deliberately required even while
// the matching HQ/A route is being integrated: old leases cannot release ACP.
type stage2aProtectedMemberRuntimeLease struct {
	stage2aMemberRuntimeLeasePayload
	HQFinalizationSHA256 string `json:"hq_finalization_sha256"`
}

func verifyStage2aProtectedMemberRuntimeLease(reply Stage2aLiveReply,
	ready stage2aMemberReadyPayload, readySHA256, observationSHA256,
	hqFinalizationSHA256, grantSHA256, challenge string,
	in Stage2aRoleInvocation, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, after uint64, previousSHA256 *string,
	priorExpires, now time.Time) (stage2aProtectedMemberRuntimeLease, error) {
	var lease stage2aProtectedMemberRuntimeLease
	invalid := errors.New("invalid protected two-member runtime lease")
	exec := in.ChildExec
	if exec == nil || exec.MemberID == "" || !validStage2aLiveChallenge(challenge) ||
		!stage2aPrefixedDigest.MatchString(readySHA256) ||
		!stage2aPrefixedDigest.MatchString(observationSHA256) ||
		!stage2aPrefixedDigest.MatchString(hqFinalizationSHA256) ||
		!stage2aPrefixedDigest.MatchString(grantSHA256) ||
		!stage2aPrefixedDigest.MatchString(reply.LeaseSHA256) ||
		after >= (1<<53)-1 || !now.Before(priorExpires) ||
		(after == 0 && previousSHA256 != nil) ||
		(after > 0 && (previousSHA256 == nil ||
			!stage2aPrefixedDigest.MatchString(*previousSHA256))) {
		return lease, invalid
	}
	envelope, err := decodeStage2aRoleBase64(reply.LeaseEnvelopeBase64URL, 8192)
	if err != nil || stage2aReservationSHA256(envelope) != reply.LeaseSHA256 {
		return lease, invalid
	}
	raw, err := verifyStage2aStoredARecordV3(envelope,
		Stage2aMemberRuntimeLeasePurpose, 1, pub)
	if err != nil || stage2aDecodeExact(raw, &lease) != nil {
		return lease, invalid
	}
	canonical, err := marshalStage2aReservationJCS(lease)
	if err != nil || !bytes.Equal(raw, canonical) ||
		lease.Contract != "machine/v3" || lease.Kind != "stage2a-member-runtime-lease" ||
		lease.SchemaVersion != 1 || lease.ProfileInForce != "managed-protected" ||
		lease.HostID != in.Binding.HostID || lease.InstallationID != in.Start.InstallationID ||
		lease.SoulID != in.Start.SoulID || lease.StartID != in.Start.StartID ||
		lease.HQEpoch != in.Start.HQEpoch ||
		lease.ReservationSHA256 != exec.ReservationSHA256 ||
		lease.AssignmentEnvelopeSHA256 != ready.AssignmentEnvelopeSHA256 ||
		lease.ChildObservationEnvelopeSHA256 != observationSHA256 ||
		lease.ReadyEnvelopeSHA256 != readySHA256 ||
		lease.BAuthorityEnvelopeSHA256 != ready.MemberBAuthorityEnvelopeSHA256 ||
		lease.HQFinalizationSHA256 != hqFinalizationSHA256 ||
		lease.BindReceiptSHA256 != exec.BindReceiptSHA256 ||
		!stage2aPrefixedDigest.MatchString(lease.InstalledAuthoritySHA256) ||
		lease.MemberID != exec.MemberID || lease.MemberSelector != exec.MemberSelector ||
		lease.MemberLaunchID != exec.MemberLaunchID || lease.GrantSHA256 != grantSHA256 ||
		lease.RunnerProcess != exec.Runner || lease.BridgeProcess != exec.Bridge ||
		lease.LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
		lease.ChildProcess != stage2aMemberProcessIdentity(child, exec.ExecutableSHA256) ||
		lease.ChallengeNonceBase64URL != challenge ||
		lease.Sequence != after+1 || lease.Sequence != reply.LeaseSequence ||
		!sameStage2aOptionalDigest(lease.PreviousLeaseEnvelopeSHA256, previousSHA256) ||
		lease.QProcess.PID < 2 || lease.OwnerDriverProcess.PID < 2 ||
		lease.QProcess.PID == lease.OwnerDriverProcess.PID ||
		lease.QProcess.UID == 0 || lease.OwnerDriverProcess.UID == 0 ||
		lease.QProcess.UID == uint32(in.Runner.UID) ||
		lease.OwnerDriverProcess.UID == uint32(in.Runner.UID) {
		return lease, invalid
	}
	selected := 0
	for _, member := range ready.Members {
		if member.MemberID == exec.MemberID {
			selected++
			if member.LaunchID != lease.MemberLaunchID ||
				member.MemberSelector != lease.MemberSelector ||
				member.RuntimeID != lease.RuntimeID ||
				member.BridgeArmReceiptSHA256 != lease.BridgeArmReceiptSHA256 {
				return lease, invalid
			}
		}
	}
	if selected != 1 {
		return lease, invalid
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, lease.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, lease.ApprovedUntil)
	readyExpires, readyExpiryErr := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	if issueErr != nil || expiryErr != nil || approvalErr != nil || readyExpiryErr != nil ||
		issued.After(now) || !now.Before(expires) || !expires.After(issued) ||
		expires.Sub(issued) > stage2aLiveLease || expires.After(approvedUntil) ||
		(after == 0 && !now.Before(readyExpires)) {
		return lease, invalid
	}
	return lease, nil
}

func sameStage2aOptionalDigest(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
