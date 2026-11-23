//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestMemberLiveLeaseRejectsWrongMemberAndRepeatedSequence(t *testing.T) {
	key, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reservation := "sha256:" + strings.Repeat("a", 64)
	observation := "sha256:" + strings.Repeat("b", 64)
	grant := "sha256:" + strings.Repeat("c", 64)
	commandSHA := "sha256:" + strings.Repeat("d", 64)
	start := SoulStartAssignment{InstallationID: "inst_0123456789abcdef",
		SoulID:  "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b",
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("e", 64)}
	assignment := stage2aMemberSetAssignmentPayload{Contract: "machine/v3",
		Kind: "stage2a-member-set-assignment", SchemaVersion: 1,
		HostID: "host-1", InstallationID: start.InstallationID,
		SoulID: start.SoulID, StartID: start.StartID, HQEpoch: start.HQEpoch,
		ReservationSHA256: reservation, ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	assignmentEnvelope, err := signStage2aEnvelope(assignment, 1, stage2aMemberSetAssignmentPurpose,
		key, func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil })
	if err != nil {
		t.Fatal(err)
	}
	childExec := &Stage2aChildExec{MemberID: "m_lead", MemberLaunchID: "ln_" + strings.Repeat("1", 24),
		MemberSelector: "mb_" + strings.Repeat("2", 64), ReservationSHA256: reservation,
		MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(assignmentEnvelope),
		ExecutableSHA256:                     commandSHA,
		GrantExpiresAt:                       now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	in := Stage2aRoleInvocation{Start: start,
		Binding: Stage2aMeasurementBinding{HostID: "host-1"}, ChildExec: childExec}
	launcher := soulKernelProcessSnapshot{PID: 401, EffectiveUID: 320, PrimaryGroupGID: 320,
		StartSeconds: 1000, StartMicros: 1}
	child := soulKernelProcessSnapshot{PID: 402, ParentPID: 401, ProcessGroupID: 402,
		EffectiveUID: 320, PrimaryGroupGID: 320, StartSeconds: 1001, StartMicros: 2}
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	lease := stage2aMemberLiveLeasePayload{Contract: "machine/v3", Kind: "stage2a-member-live-lease",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: "host-1",
		InstallationID: start.InstallationID, SoulID: start.SoulID,
		StartID: start.StartID, HQEpoch: start.HQEpoch,
		ReservationSHA256:              reservation,
		AssignmentEnvelopeSHA256:       stage2aReservationSHA256(assignmentEnvelope),
		ChildObservationEnvelopeSHA256: observation,
		MemberID:                       childExec.MemberID, MemberLaunchID: childExec.MemberLaunchID,
		MemberSelector: childExec.MemberSelector, GrantSHA256: grant,
		LauncherProcess:         stage2aMemberLauncherIdentity(launcher),
		ChildProcess:            stage2aMemberProcessIdentity(child, commandSHA),
		ChallengeNonceBase64URL: challenge, Sequence: 1,
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Second).Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(lease, 1, Stage2aMemberLiveLeasePurpose,
		key, func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil })
	if err != nil {
		t.Fatal(err)
	}
	reply := Stage2aLiveReply{LeaseEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		LeaseSHA256: stage2aReservationSHA256(envelope), LeaseSequence: 1}
	check := func(in Stage2aRoleInvocation, after uint64, obsExpiry time.Time, pub ed25519.PublicKey) error {
		_, err := verifyStage2aMemberLiveLease(reply, challenge, in, observation, grant,
			launcher, child, pub, after, obsExpiry, now.Add(time.Second))
		return err
	}
	if err := check(in, 0, now.Add(5*time.Second), key); err != nil {
		t.Fatal(err)
	}
	if err := check(in, 1, now.Add(5*time.Second), key); err == nil {
		t.Fatal("repeated sequence accepted")
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || check(in, 0, now.Add(5*time.Second), otherKey) == nil {
		t.Fatal("another Machine key accepted")
	}
	in.ChildExec.MemberID = "m_spec"
	if err := check(in, 0, now.Add(5*time.Second), key); err == nil {
		t.Fatal("sibling member accepted")
	}
	in.ChildExec.MemberID = "m_lead"
	if err := check(in, 0, now.Add(2*time.Second), key); err == nil {
		t.Fatal("lease outliving child observation accepted")
	}
}
