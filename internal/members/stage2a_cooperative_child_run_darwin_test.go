//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCooperativeChildSignedSelectionAndAggregateGate(t *testing.T) {
	key, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil }
	now := time.Now().UTC()
	until := now.Add(15 * time.Second).Format(time.RFC3339Nano)
	reservation := soulCooperativeBReservationViewV3{
		Contract: "machine/v3", Kind: "soul-cooperative-reservation",
		SchemaVersion: 3, HostID: "host-1", AdapterTransport: "brokered-b",
		ExpiresAt: until}
	reservation.Assignment.InstallationID = "inst_0123456789abcdef"
	reservation.Assignment.StartID = "st_0123456789abcdef01234567"
	reservation.Assignment.HQEpoch = strings.Repeat("e", 64)
	reservation.Assignment.PlanID = "plan-1"
	reservation.Assignment.PlanDigest = strings.Repeat("a", 64)
	reservation.Assignment.LaunchID = "ln_" + strings.Repeat("1", 24)
	reservation.Assignment.RunnerUID = 320
	reservation.Endpoints.Relay = soulCooperativeBEndpointV3{
		SocketPath: "/private/var/run/agent-bot/relay.sock", ExpectedPeerUID: 320}
	rRaw, err := marshalStage2aReservationJCS(reservation)
	if err != nil {
		t.Fatal(err)
	}
	rEnvelope, rSHA, err := signSoulCooperativeEnvelopeV3(rRaw, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	bridge := soulCooperativeBridgeAssignmentPayloadV3{
		Contract: "machine/v3", Kind: "soul-cooperative-bridge-assignment",
		SchemaVersion: 3, HostID: reservation.HostID,
		InstallationID: reservation.Assignment.InstallationID,
		StartID:        reservation.Assignment.StartID, HQEpoch: reservation.Assignment.HQEpoch,
		PlanID: reservation.Assignment.PlanID, PlanDigest: reservation.Assignment.PlanDigest,
		LaunchID: reservation.Assignment.LaunchID, ReservationSHA256: rSHA,
		ExpiresAt: until}
	bridge.Endpoints.Relay = reservation.Endpoints.Relay
	bEnvelope, err := signStage2aEnvelope(bridge, 3,
		soulCooperativeBridgeAssignmentPurposeV3, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	assignment := soulCooperativeMemberSetAssignmentV3{
		Contract: "machine/v3", Kind: "stage2a-member-set-assignment",
		SchemaVersion: 1, ProfileInForce: "managed-cooperative",
		HostID: reservation.HostID, InstallationID: reservation.Assignment.InstallationID,
		StartID: reservation.Assignment.StartID, HQEpoch: reservation.Assignment.HQEpoch,
		PlanID: reservation.Assignment.PlanID, PlanDigest: reservation.Assignment.PlanDigest,
		ReservationSHA256: rSHA, ExpiresAt: until}
	assignment.BAuthority.Purpose = soulCooperativeBridgeAssignmentPurposeV3
	assignment.BAuthority.EnvelopeSHA256 = stage2aReservationSHA256(bEnvelope)
	assignment.Bridge.Endpoints = bridge.Endpoints
	assignment.Members[0] = stage2aAssignedMember{MemberID: "m_lead",
		LaunchID:      "ln_" + strings.Repeat("2", 24),
		CommandPath:   "/private/var/runtime/bin/claude-agent-acp",
		CommandSHA256: "sha256:" + strings.Repeat("c", 64)}
	assignment.Members[1] = stage2aAssignedMember{MemberID: "m_spec",
		LaunchID:      "ln_" + strings.Repeat("3", 24),
		CommandPath:   assignment.Members[0].CommandPath,
		CommandSHA256: assignment.Members[0].CommandSHA256}
	for i := range assignment.Members {
		m := &assignment.Members[i]
		m.MemberSelector = stage2aMemberSelector(rSHA, m.MemberID, m.LaunchID)
		m.AdjacentCLIPath = "/private/var/runtime/bin/claude"
		m.AdjacentCLISHA256 = "sha256:" + strings.Repeat("9", 64)
	}
	aEnvelope, err := signStage2aEnvelope(assignment, 1,
		stage2aMemberSetAssignmentPurpose, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	bridgeJSON, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	authority := stage2aBMemberAuthorityPayload{Contract: "machine/v3",
		Kind: "stage2a-b-member-authority", SchemaVersion: 1,
		ProfileInForce: "managed-cooperative", HostID: assignment.HostID,
		InstallationID: assignment.InstallationID, SoulID: assignment.SoulID,
		StartID: assignment.StartID, HQEpoch: assignment.HQEpoch,
		PlanID: assignment.PlanID, PlanDigest: assignment.PlanDigest,
		ReservationSHA256:                 rSHA,
		MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(aEnvelope),
		OwnerPlanMemberSetSHA256:          assignment.OwnerPlanMemberSetSHA256,
		HQUID:                             reservation.Assignment.HQUID, RunnerUID: reservation.Assignment.RunnerUID,
		Bridge: bridgeJSON, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: until}
	authority.BAuthority = assignment.BAuthority
	for i, member := range assignment.Members {
		authority.Members[i] = stage2aBMemberAuthorityMember{
			MemberID: member.MemberID, LaunchID: member.LaunchID,
			MemberSelector:    member.MemberSelector,
			AdjacentCLIPath:   member.AdjacentCLIPath,
			AdjacentCLISHA256: member.AdjacentCLISHA256}
	}
	authorityEnvelope, err := signStage2aEnvelope(authority, 1,
		stage2aBMemberAuthorityPurpose, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyStage2aCooperativeBAuthority(authorityEnvelope,
		reservation, bridge, assignment, rSHA, stage2aReservationSHA256(bEnvelope),
		stage2aReservationSHA256(aEnvelope), key, now); err != nil {
		t.Fatalf("signed B member authority refused: %v", err)
	}
	selected := assignment.Members[0]
	_, _, _, _, _, _, _, _, err = verifyStage2aCooperativeChildSelection(
		rEnvelope, bEnvelope, aEnvelope, selected.MemberID, selected.LaunchID,
		selected.MemberSelector, key, now)
	if err != nil {
		t.Fatalf("signed cooperative selection refused: %v", err)
	}
	if _, _, _, _, _, _, _, _, err := verifyStage2aCooperativeChildSelection(
		rEnvelope, bEnvelope, aEnvelope, selected.MemberID, selected.LaunchID,
		assignment.Members[1].MemberSelector, key, now); err == nil {
		t.Fatal("sibling selector accepted")
	}
	if _, _, _, _, _, _, _, _, err := verifyStage2aCooperativeChildSelection(
		rEnvelope, bEnvelope, aEnvelope, selected.MemberID, selected.LaunchID,
		selected.MemberSelector, key, now.Add(16*time.Second)); err == nil {
		t.Fatal("expired assignment accepted")
	}
	in := stage2aCooperativeChildInvocation{
		ReservationEnvelopeBase64URL:      base64.RawURLEncoding.EncodeToString(rEnvelope),
		BridgeEnvelopeBase64URL:           base64.RawURLEncoding.EncodeToString(bEnvelope),
		AssignmentEnvelopeBase64URL:       base64.RawURLEncoding.EncodeToString(aEnvelope),
		MemberBAuthorityEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(authorityEnvelope),
		MemberID:                          selected.MemberID, MemberLaunchID: selected.LaunchID,
		MemberSelector: selected.MemberSelector, ExecutableSHA256: selected.CommandSHA256}
	grantSHA := "sha256:" + strings.Repeat("d", 64)
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	grant := stage2aCooperativeChildGrant{ReservationSHA256: rSHA,
		AssignmentEnvelopeSHA256: stage2aReservationSHA256(aEnvelope),
		MemberBAuthoritySHA256:   stage2aReservationSHA256(authorityEnvelope),
		InstallationID:           assignment.InstallationID, StartID: assignment.StartID,
		HQEpoch: assignment.HQEpoch, MemberID: selected.MemberID,
		MemberLaunchID: selected.LaunchID, MemberSelector: selected.MemberSelector,
		ExpiresAt: until}
	launcher := soulKernelProcessSnapshot{PID: 401, EffectiveUID: 320,
		PrimaryGroupGID: 320, StartSeconds: 1000, StartMicros: 1}
	child := soulKernelProcessSnapshot{PID: 402, ParentPID: 401, ProcessGroupID: 402,
		EffectiveUID: 320, PrimaryGroupGID: 320, StartSeconds: 1001, StartMicros: 2}
	ready := stage2aCooperativeReadyPayload{Contract: "machine/v3",
		Kind: "soul-cooperative-member-ready", SchemaVersion: 3,
		ProfileInForce: "managed-cooperative", HostID: reservation.HostID,
		InstallationID: assignment.InstallationID, StartID: assignment.StartID,
		HQEpoch: assignment.HQEpoch, ReservationSHA256: rSHA,
		AssignmentEnvelopeSHA256: grant.AssignmentEnvelopeSHA256,
		IssuedAt:                 now.Format(time.RFC3339Nano), ExpiresAt: until}
	for i, member := range assignment.Members {
		memberLauncher := launcher
		memberChild := child
		if i == 1 {
			memberLauncher.PID, memberChild.PID, memberChild.ParentPID = 501, 502, 501
			memberChild.ProcessGroupID = 502
		}
		ready.Members[i] = stage2aCooperativeReadyMember{
			MemberID: member.MemberID, MemberLaunchID: member.LaunchID,
			MemberSelector:     member.MemberSelector,
			GrantSHA256:        "sha256:" + strings.Repeat(string(rune('d'+i)), 64),
			LauncherProcess:    stage2aMemberLauncherIdentity(memberLauncher),
			ChildProcess:       stage2aMemberProcessIdentity(memberChild, selected.CommandSHA256),
			HObservationSHA256: "sha256:" + strings.Repeat(string(rune('e'+i)), 64),
			BArmReceiptSHA256:  "sha256:" + strings.Repeat(string(rune('a'+i)), 64)}
	}
	ready.Members[0].GrantSHA256 = grantSHA
	readyEnvelope, err := signStage2aEnvelope(ready, 3,
		stage2aCooperativeReadyPurpose, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	lease := stage2aCooperativeLeasePayload{Contract: "machine/v3",
		Kind: "soul-cooperative-member-live-lease", SchemaVersion: 3,
		ProfileInForce: "managed-cooperative", ReservationSHA256: rSHA,
		AssignmentEnvelopeSHA256: grant.AssignmentEnvelopeSHA256,
		ReadyEnvelopeSHA256:      stage2aReservationSHA256(readyEnvelope),
		MemberID:                 selected.MemberID, MemberLaunchID: selected.LaunchID,
		MemberSelector: selected.MemberSelector, GrantSHA256: grantSHA,
		LauncherProcess:         stage2aMemberLauncherIdentity(launcher),
		ChildProcess:            stage2aMemberProcessIdentity(child, selected.CommandSHA256),
		ChallengeNonceBase64URL: challenge,
		Sequence:                1, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Second).Format(time.RFC3339Nano)}
	leaseEnvelope, err := signStage2aEnvelope(lease, 3,
		stage2aCooperativeLeasePurpose, key, sign)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyStage2aCooperativeReadyLease(readyEnvelope,
		leaseEnvelope, in, grant, grantSHA, launcher, child, key, challenge, 0, now.Add(time.Second)); err != nil {
		t.Fatalf("signed aggregate gate refused: %v", err)
	}
	if _, _, err := verifyStage2aCooperativeReadyLease(readyEnvelope,
		leaseEnvelope, in, grant, grantSHA, launcher, child, key, challenge, 1, now.Add(time.Second)); err == nil {
		t.Fatal("replayed lease accepted")
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyStage2aCooperativeReadyLease(readyEnvelope,
		leaseEnvelope, in, grant, grantSHA, launcher, child, otherKey, challenge, 0, now.Add(time.Second)); err == nil {
		t.Fatal("different A key accepted")
	}
	if _, _, err := verifyStage2aCooperativeReadyLease(readyEnvelope,
		leaseEnvelope, in, grant, grantSHA, launcher, child, key,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), 0, now.Add(time.Second)); err == nil {
		t.Fatal("lease for another challenge accepted")
	}
}

func TestCooperativeLeasedReaderWithholdsExpiredACP(t *testing.T) {
	var until atomic.Int64
	until.Store(time.Now().Add(500 * time.Millisecond).UnixMilli())
	input := stage2aCooperativeLeasedReader{input: bytes.NewBufferString("ACP"), expires: &until}
	buffer := make([]byte, 3)
	if n, err := input.Read(buffer); n != 0 || err != io.EOF {
		t.Fatal("ACP passed without a fresh signed lease")
	}
	until.Store(time.Now().Add(3 * time.Second).UnixMilli())
	if n, err := input.Read(buffer); n != 3 || err != nil || string(buffer) != "ACP" {
		t.Fatal("freshly leased ACP was not forwarded")
	}
}
