//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"
)

// A member lease keeps one already observed stock child inert and supervised.
// It is never an aggregate Ready receipt or permission to forward ACP stdin.
func verifyStage2aMemberLiveLease(reply Stage2aLiveReply, challenge string,
	in Stage2aRoleInvocation, observationSHA256, grantSHA256 string,
	launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	after uint64, observationExpiry, now time.Time) (stage2aMemberLiveLeasePayload, error) {
	var lease stage2aMemberLiveLeasePayload
	invalid := errors.New("invalid Machine two-member live lease")
	exec := in.ChildExec
	if exec == nil || !validStage2aLiveChallenge(challenge) ||
		!stage2aPrefixedDigest.MatchString(observationSHA256) ||
		!stage2aPrefixedDigest.MatchString(grantSHA256) ||
		!stage2aPrefixedDigest.MatchString(reply.LeaseSHA256) ||
		after >= (1<<53)-1 {
		return lease, invalid
	}
	envelope, err := decodeStage2aRoleBase64(reply.LeaseEnvelopeBase64URL, 8192)
	if err != nil || stage2aReservationSHA256(envelope) != reply.LeaseSHA256 {
		return lease, invalid
	}
	raw, err := verifyStage2aStoredARecordV3(envelope, Stage2aMemberLiveLeasePurpose, 1, pub)
	if err != nil || stage2aDecodeExact(raw, &lease) != nil {
		return lease, invalid
	}
	canonical, err := marshalStage2aReservationJCS(lease)
	if err != nil || !bytes.Equal(raw, canonical) || lease.Contract != "machine/v3" ||
		lease.Kind != "stage2a-member-live-lease" || lease.SchemaVersion != 1 ||
		lease.ProfileInForce != "managed-protected" || lease.HostID != in.Binding.HostID ||
		lease.InstallationID != in.Start.InstallationID || lease.SoulID != in.Start.SoulID ||
		lease.StartID != in.Start.StartID || lease.HQEpoch != in.Start.HQEpoch ||
		lease.ReservationSHA256 != exec.ReservationSHA256 ||
		lease.ChildObservationEnvelopeSHA256 != observationSHA256 ||
		lease.MemberID != exec.MemberID || lease.MemberSelector != exec.MemberSelector ||
		lease.MemberLaunchID != exec.MemberLaunchID || lease.GrantSHA256 != grantSHA256 ||
		lease.LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
		lease.ChildProcess != stage2aMemberProcessIdentity(child, exec.ExecutableSHA256) ||
		lease.ChallengeNonceBase64URL != challenge ||
		lease.Sequence != after+1 || lease.Sequence != reply.LeaseSequence {
		return lease, invalid
	}
	assignmentEnvelope, err := decodeStage2aRoleBase64(exec.MemberSetAssignmentEnvelopeBase64URL, 16<<10)
	if err != nil || lease.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(assignmentEnvelope) {
		return lease, invalid
	}
	assignmentRaw, err := verifyStage2aStoredARecordV3(assignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, pub)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.ReservationSHA256 != lease.ReservationSHA256 ||
		assignment.HostID != lease.HostID || assignment.InstallationID != lease.InstallationID ||
		assignment.SoulID != lease.SoulID || assignment.StartID != lease.StartID ||
		assignment.HQEpoch != lease.HQEpoch {
		return lease, invalid
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, lease.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	assignmentExpires, assignmentExpiryErr := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	grantExpires, grantExpiryErr := time.Parse(time.RFC3339Nano, exec.GrantExpiresAt)
	if issueErr != nil || expiryErr != nil || assignmentExpiryErr != nil || grantExpiryErr != nil ||
		observationExpiry.IsZero() || !now.Before(observationExpiry) ||
		issued.After(now) || !now.Before(expires) || !expires.After(issued) ||
		expires.Sub(issued) > stage2aLiveLease ||
		expires.After(observationExpiry) ||
		expires.After(assignmentExpires) || expires.After(grantExpires) {
		return lease, invalid
	}
	return lease, nil
}
