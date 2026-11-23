//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemberChildGrantUsesSameAKeyAndExactAssignedMember(t *testing.T) {
	key, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reservation := "sha256:" + strings.Repeat("a", 64)
	command := "/private/var/stage2a/runtime/bin/claude-acp"
	commandSHA := "sha256:" + strings.Repeat("b", 64)
	cliSHA := "sha256:" + strings.Repeat("c", 64)
	cli := "/private/var/stage2a/runtime/bin/claude"
	roles := []stage2aHelloMember{{MemberID: "m_lead", Role: "lead", AdapterID: "claude-code", AdapterVersion: "0.109.0"},
		{MemberID: "m_spec", Role: "specialist", AdapterID: "claude-code", AdapterVersion: "0.109.0"}}
	ownerDigest, err := stage2aOwnerMemberSetDigest(roles, command, commandSHA, cli, cliSHA)
	if err != nil {
		t.Fatal(err)
	}
	start := SoulStartAssignment{InstallationID: "inst_0123456789abcdef",
		SoulID: "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b", StartID: "st_0123456789abcdef01234567",
		HQEpoch: strings.Repeat("d", 64), PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("e", 64), ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano),
		HQUID: 501, RunnerUID: 320, RunnerGID: 320, BridgeAccount: "_abm-bridge", BridgeUID: 321, BridgeGID: 321,
		Broker: SoulStartEndpoint{SocketPath: "/private/var/broker.sock", PeerUIDs: []int{320}},
		Member: SoulStartEndpoint{SocketPath: "/private/var/member.sock", PeerUIDs: []int{320}},
		Relay:  SoulStartEndpoint{SocketPath: "/private/var/relay.sock", PeerUIDs: []int{321}}}
	projection := Stage2aHostProjection{Adapters: map[string]any{"claude-code": map[string]any{"command": []any{command}}},
		Installation: map[string]any{"id": start.InstallationID}}
	projectionRaw, err := marshalStage2aReservationJCS(projection)
	if err != nil {
		t.Fatal(err)
	}
	assignment := stage2aMemberSetAssignmentPayload{Contract: "machine/v3", Kind: "stage2a-member-set-assignment",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: "host-1",
		InstallationID: start.InstallationID, SoulID: start.SoulID, StartID: start.StartID,
		HQEpoch: start.HQEpoch, PlanID: start.PlanID, PlanDigest: start.PlanDigest,
		ReservationSHA256: reservation, OwnerPlanMemberSetSHA256: ownerDigest,
		SoulArtifactSHA256:    "sha256:" + strings.Repeat("f", 64),
		DefinitionMeasurement: "sha256:" + strings.Repeat("1", 64),
		HostProjectionSHA256:  stage2aReservationSHA256(projectionRaw),
		RunnerUID:             320, RunnerGID: 320,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	assignment.BAuthority.Purpose, assignment.BAuthority.EnvelopeSHA256 = stage2aReservationPurposeV3, reservation
	assignment.Bridge.Account, assignment.Bridge.UID, assignment.Bridge.GID = start.BridgeAccount, start.BridgeUID, start.BridgeGID
	assignment.Bridge.Endpoints.Broker, assignment.Bridge.Endpoints.Member, assignment.Bridge.Endpoints.Relay = start.Broker, start.Member, start.Relay
	for i, role := range roles {
		launchID := "ln_" + strings.Repeat(string(rune('1'+i)), 24)
		assignment.Members[i] = stage2aAssignedMember{MemberID: role.MemberID, Role: role.Role,
			AdapterID: role.AdapterID, AdapterVersion: role.AdapterVersion,
			CommandPath: command, CommandSHA256: commandSHA,
			AdjacentCLIPath: cli, AdjacentCLISHA256: cliSHA,
			LaunchID: launchID, MemberSelector: stage2aMemberSelector(reservation, role.MemberID, launchID)}
	}
	envelope, err := signStage2aEnvelope(assignment, 1, stage2aMemberSetAssignmentPurpose, key,
		func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil })
	if err != nil {
		t.Fatal(err)
	}
	bridgeRaw, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	bAuthority := stage2aBMemberAuthorityPayload{Contract: "machine/v3", Kind: "stage2a-b-member-authority",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: assignment.HostID,
		InstallationID: start.InstallationID, SoulID: start.SoulID, StartID: start.StartID,
		HQEpoch: start.HQEpoch, PlanID: start.PlanID, PlanDigest: start.PlanDigest,
		ReservationSHA256: reservation, MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(envelope),
		OwnerPlanMemberSetSHA256: ownerDigest, BAuthority: assignment.BAuthority,
		HQUID: start.HQUID, RunnerUID: start.RunnerUID, Bridge: json.RawMessage(bridgeRaw),
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(15 * time.Second).Format(time.RFC3339Nano)}
	for i, member := range assignment.Members {
		bAuthority.Members[i] = stage2aBMemberAuthorityMember{MemberID: member.MemberID,
			LaunchID: member.LaunchID, MemberSelector: member.MemberSelector,
			AdjacentCLIPath: member.AdjacentCLIPath, AdjacentCLISHA256: member.AdjacentCLISHA256}
	}
	bEnvelope, err := signStage2aEnvelope(bAuthority, 1, stage2aBMemberAuthorityPurpose, key,
		func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil })
	if err != nil {
		t.Fatal(err)
	}
	child := &Stage2aChildExec{MemberID: roles[0].MemberID,
		MemberLaunchID:                       assignment.Members[0].LaunchID,
		MemberSelector:                       assignment.Members[0].MemberSelector,
		MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		MemberBAuthorityEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(bEnvelope),
		ProvisionalHQMapSHA256:               "sha256:" + strings.Repeat("2", 64),
		Executable:                           command, ExecutableSHA256: commandSHA}
	in := Stage2aRoleInvocation{Start: start, ChildExec: child,
		Runner: SoulRunner{UID: 320, GID: 320}, Bridge: SoulBridge{Account: start.BridgeAccount, UID: 321, GID: 321},
		Binding: Stage2aMeasurementBinding{HostID: assignment.HostID,
			SoulArtifactSHA256:    assignment.SoulArtifactSHA256,
			DefinitionMeasurement: assignment.DefinitionMeasurement,
			Snapshots:             Stage2aBindingSnapshots{LaunchInputs: Stage2aSnapshotIdentity{RootPath: "/private/var/stage2a"}}},
		Launch: Stage2aLaunchInputRecords{HostProjection: projection,
			ComponentDigests: map[string]string{"adapter": commandSHA},
			Files:            []Stage2aDefinitionRecord{{Path: "runtime/bin/claude", Kind: "regular", SHA256: strings.TrimPrefix(cliSHA, "sha256:")}}}}
	grant := Stage2aRoleGrant{ReservationSHA256: reservation, MemberID: child.MemberID,
		MemberLaunchID: child.MemberLaunchID, MemberSelector: child.MemberSelector,
		MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(envelope)}
	if !stage2aVerifyMemberChildGrant(grant, in, key, now.Add(time.Second)) {
		t.Fatal("exact A-signed member child grant refused")
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || stage2aVerifyMemberChildGrant(grant, in, otherKey, now.Add(time.Second)) {
		t.Fatal("another Machine key accepted")
	}
	changed := grant
	changed.MemberSelector = assignment.Members[1].MemberSelector
	if stage2aVerifyMemberChildGrant(changed, in, key, now.Add(time.Second)) {
		t.Fatal("sibling selector accepted")
	}
	changed = grant
	changed.MemberLaunchID = assignment.Members[1].LaunchID
	if stage2aVerifyMemberChildGrant(changed, in, key, now.Add(time.Second)) {
		t.Fatal("sibling launch ID accepted")
	}
	if stage2aVerifyMemberChildGrant(grant, in, key, now.Add(21*time.Second)) {
		t.Fatal("expired member assignment accepted")
	}
	in.Launch.Files[0].SHA256 = strings.Repeat("0", 64)
	if stage2aVerifyMemberChildGrant(grant, in, key, now.Add(time.Second)) {
		t.Fatal("changed adjacent CLI measurement accepted")
	}
}
