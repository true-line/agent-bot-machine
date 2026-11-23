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

func TestMemberChildObservationRequiresSameAKeyMemberGrantAndWithheldMap(t *testing.T) {
	key, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := SoulStartAssignment{InstallationID: "inst_0123456789abcdef",
		SoulID:  "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b",
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("d", 64)}
	reservation := "sha256:" + strings.Repeat("a", 64)
	grant := "sha256:" + strings.Repeat("b", 64)
	commandSHA := "sha256:" + strings.Repeat("c", 64)
	assignment := stage2aMemberSetAssignmentPayload{Contract: "machine/v3",
		Kind: "stage2a-member-set-assignment", SchemaVersion: 1, ProfileInForce: "managed-protected",
		HostID: "host-1", InstallationID: start.InstallationID,
		SoulID: start.SoulID, StartID: start.StartID, HQEpoch: start.HQEpoch,
		ReservationSHA256: reservation, ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	assignment.BAuthority.Purpose = stage2aReservationPurposeV3
	assignment.BAuthority.EnvelopeSHA256 = reservation
	for i, id := range []string{"m_lead", "m_spec"} {
		assignment.Members[i].MemberID = id
		assignment.Members[i].LaunchID = "ln_" + strings.Repeat(string(rune('1'+i)), 24)
		assignment.Members[i].MemberSelector = stage2aMemberSelector(reservation, id, assignment.Members[i].LaunchID)
		assignment.Members[i].CommandSHA256 = commandSHA
	}
	sign := func(payload any, purpose string) []byte {
		t.Helper()
		out, err := signStage2aEnvelope(payload, 1, purpose, key,
			func(message []byte) ([]byte, error) { return ed25519.Sign(secret, message), nil })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	assignmentEnvelope := sign(assignment, stage2aMemberSetAssignmentPurpose)
	mapValue := map[string]any{"contract": "hq/v1", "kind": "stage2a-provisional-member-map",
		"schema_version": 1, "profile_in_force": "managed-protected", "host_id": assignment.HostID,
		"installation_id": start.InstallationID, "soul_id": start.SoulID,
		"start_id": start.StartID, "hq_epoch": start.HQEpoch,
		"assignment_envelope_sha256": stage2aReservationSHA256(assignmentEnvelope),
		"runtime_state":              "provisional", "acp_authority": "withheld",
		"issued_at":  now.Format(time.RFC3339Nano),
		"expires_at": now.Add(20 * time.Second).Format(time.RFC3339Nano),
		"members": []any{
			map[string]any{"member_id": "m_lead", "member_selector": assignment.Members[0].MemberSelector,
				"runtime_id": "runtime_lead", "channel_binding": strings.Repeat("A", 24)},
			map[string]any{"member_id": "m_spec", "member_selector": assignment.Members[1].MemberSelector,
				"runtime_id": "runtime_spec", "channel_binding": strings.Repeat("B", 24)},
		}}
	mapRaw, err := marshalStage2aReservationJCS(mapValue)
	if err != nil {
		t.Fatal(err)
	}
	launcher := soulKernelProcessSnapshot{PID: 401, EffectiveUID: 320, PrimaryGroupGID: 320,
		StartSeconds: 1000, StartMicros: 1}
	child := soulKernelProcessSnapshot{PID: 402, ParentPID: 401, ProcessGroupID: 402,
		EffectiveUID: 320, PrimaryGroupGID: 320, StartSeconds: 1001, StartMicros: 2}
	observation := stage2aMemberChildObservationPayload{Contract: "machine/v3",
		Kind: "stage2a-member-set-child-observation", SchemaVersion: 1,
		ProfileInForce: "managed-protected", HostID: assignment.HostID,
		InstallationID: start.InstallationID, SoulID: start.SoulID,
		StartID: start.StartID, HQEpoch: start.HQEpoch,
		ReservationSHA256:          reservation,
		AssignmentEnvelopeSHA256:   stage2aReservationSHA256(assignmentEnvelope),
		ProvisionalHQMappingSHA256: stage2aReservationSHA256(mapRaw),
		ProvisionalHQMapping:       mapRaw,
		ObservedAt:                 now.Format(time.RFC3339Nano), IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Second).Format(time.RFC3339Nano)}
	for i := range observation.Members {
		observedLauncher := launcher
		observedChild := child
		observedLauncher.PID += i * 10
		observedChild.PID += i * 10
		observedChild.ParentPID = observedLauncher.PID
		observedChild.ProcessGroupID = observedChild.PID
		observation.Members[i].MemberID = assignment.Members[i].MemberID
		observation.Members[i].LaunchID = assignment.Members[i].LaunchID
		observation.Members[i].MemberSelector = assignment.Members[i].MemberSelector
		observation.Members[i].RuntimeID = []string{"runtime_lead", "runtime_spec"}[i]
		observation.Members[i].GrantSHA256 = []string{grant, "sha256:" + strings.Repeat("e", 64)}[i]
		observation.Members[i].LauncherProcess = stage2aMemberLauncherIdentity(observedLauncher)
		observation.Members[i].ChildProcess = stage2aMemberProcessIdentity(observedChild, commandSHA)
	}
	envelope := sign(observation, Stage2aMemberChildObservationPurpose)
	reply := Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}
	in := Stage2aRoleInvocation{Start: start, Runner: SoulRunner{UID: 320, GID: 320},
		Binding: Stage2aMeasurementBinding{HostID: assignment.HostID, ProfileInForce: "managed-protected"},
		Launch:  Stage2aLaunchInputRecords{ComponentDigests: map[string]string{"bridge": commandSHA}},
		ChildExec: &Stage2aChildExec{MemberID: "m_lead",
			MemberLaunchID:                       assignment.Members[0].LaunchID,
			MemberSelector:                       assignment.Members[0].MemberSelector,
			MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(assignmentEnvelope),
			ProvisionalHQMapSHA256:               stage2aReservationSHA256(mapRaw),
			ReservationSHA256:                    reservation, ExecutableSHA256: commandSHA,
			GrantExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}}
	in.ChildExec.Bridge = Stage2aLiveRoleIdentity{PID: 500, UID: 321, GID: 321,
		StartSeconds: 999, StartMicros: 3}
	if _, err := verifyStage2aMemberChildObservation(reply, in, grant, launcher, child, key, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b := stage2aBMemberAuthorityPayload{Contract: "machine/v3", Kind: "stage2a-b-member-authority",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: assignment.HostID,
		InstallationID: start.InstallationID, SoulID: start.SoulID, StartID: start.StartID,
		HQEpoch: start.HQEpoch, ReservationSHA256: reservation,
		MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(assignmentEnvelope),
		BAuthority:                        assignment.BAuthority, ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	bEnvelope := sign(b, stage2aBMemberAuthorityPurpose)
	in.ChildExec.MemberBAuthorityEnvelopeBase64URL = base64.RawURLEncoding.EncodeToString(bEnvelope)
	ready := stage2aMemberReadyPayload{Contract: "machine/v3", Kind: "stage2a-member-set-ready",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: assignment.HostID,
		InstallationID: start.InstallationID, SoulID: start.SoulID, StartID: start.StartID,
		HQEpoch: start.HQEpoch, ReservationSHA256: reservation,
		AssignmentEnvelopeSHA256:       stage2aReservationSHA256(assignmentEnvelope),
		ChildObservationEnvelopeSHA256: reply.SHA256, BAuthoritySHA256: reservation,
		MemberBAuthorityEnvelopeSHA256: stage2aReservationSHA256(bEnvelope),
		ProvisionalHQMappingSHA256:     observation.ProvisionalHQMappingSHA256,
		ObservedAt:                     now.Format(time.RFC3339Nano), IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Second).Format(time.RFC3339Nano)}
	ready.BridgeProcess.PID, ready.BridgeProcess.UID, ready.BridgeProcess.GID = 500, 321, 321
	ready.BridgeProcess.StartSeconds, ready.BridgeProcess.StartMicros = 999, 3
	ready.BridgeProcess.ExecutableSHA256 = commandSHA
	for i := range ready.Members {
		member := &ready.Members[i]
		observed := observation.Members[i]
		member.MemberID, member.LaunchID = observed.MemberID, observed.LaunchID
		member.MemberSelector, member.RuntimeID = observed.MemberSelector, observed.RuntimeID
		member.BridgeArm = stage2aMemberBridgeArm{MemberID: observed.MemberID,
			MemberSelector: observed.MemberSelector, RuntimeID: observed.RuntimeID,
			ChildObservationEnvelopeSHA256: reply.SHA256, BridgeUID: 321,
			AdapterPID: observed.ChildProcess.PID, AdapterUID: 320, AdapterGID: 320,
			AdapterStartSeconds: observed.ChildProcess.StartSeconds,
			AdapterStartMicros:  observed.ChildProcess.StartMicros, State: "armed",
			RelayPeerState: "unobserved", ProviderIngress: "withheld-pending-per-peer-attestation"}
		armRaw, err := marshalStage2aReservationJCS(member.BridgeArm)
		if err != nil {
			t.Fatal(err)
		}
		member.BridgeArmReceiptSHA256 = stage2aReservationSHA256(armRaw)
	}
	readyEnvelope := sign(ready, Stage2aMemberReadyPurpose)
	readyReply := Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(readyEnvelope),
		SHA256: stage2aReservationSHA256(readyEnvelope)}
	if _, err := verifyStage2aProtectedMemberReady(readyReply, reply, in, grant,
		launcher, child, key, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wrongReady := readyReply
	wrongReady.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := verifyStage2aProtectedMemberReady(wrongReady, reply, in, grant,
		launcher, child, key, now.Add(time.Second)); err == nil {
		t.Fatal("different aggregate Ready digest accepted")
	}
	in.ChildExec.Runner = Stage2aLiveRoleIdentity{PID: 499, UID: 320, GID: 320,
		StartSeconds: 998, StartMicros: 4}
	in.ChildExec.BindReceiptSHA256 = "sha256:" + strings.Repeat("8", 64)
	hqFinalization := "sha256:" + strings.Repeat("9", 64)
	challenge := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	lease := stage2aProtectedMemberRuntimeLease{
		stage2aMemberRuntimeLeasePayload: stage2aMemberRuntimeLeasePayload{
			Contract: "machine/v3", Kind: "stage2a-member-runtime-lease", SchemaVersion: 1,
			ProfileInForce: "managed-protected", HostID: assignment.HostID,
			InstallationID: start.InstallationID, SoulID: start.SoulID,
			StartID: start.StartID, HQEpoch: start.HQEpoch, ReservationSHA256: reservation,
			InstalledAuthoritySHA256:       "sha256:" + strings.Repeat("7", 64),
			AssignmentEnvelopeSHA256:       ready.AssignmentEnvelopeSHA256,
			ChildObservationEnvelopeSHA256: reply.SHA256,
			ReadyEnvelopeSHA256:            readyReply.SHA256,
			BAuthorityEnvelopeSHA256:       ready.MemberBAuthorityEnvelopeSHA256,
			BindReceiptSHA256:              in.ChildExec.BindReceiptSHA256,
			MemberID:                       "m_lead", MemberSelector: assignment.Members[0].MemberSelector,
			MemberLaunchID: assignment.Members[0].LaunchID, RuntimeID: "runtime_lead",
			GrantSHA256: grant, BridgeArmReceiptSHA256: ready.Members[0].BridgeArmReceiptSHA256,
			RunnerProcess: in.ChildExec.Runner, BridgeProcess: in.ChildExec.Bridge,
			QProcess:                Stage2aLiveRoleIdentity{PID: 600, UID: 322, GID: 322},
			OwnerDriverProcess:      Stage2aLiveRoleIdentity{PID: 601, UID: 323, GID: 323},
			LauncherProcess:         stage2aMemberLauncherIdentity(launcher),
			ChildProcess:            stage2aMemberProcessIdentity(child, commandSHA),
			ChallengeNonceBase64URL: challenge, Sequence: 1,
			ApprovedUntil: now.Add(time.Hour).Format(time.RFC3339Nano),
			IssuedAt:      now.Format(time.RFC3339Nano), ExpiresAt: now.Add(3 * time.Second).Format(time.RFC3339Nano)},
		HQFinalizationSHA256: hqFinalization}
	leaseEnvelope := sign(lease, Stage2aMemberRuntimeLeasePurpose)
	leaseReply := Stage2aLiveReply{LeaseEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(leaseEnvelope),
		LeaseSHA256: stage2aReservationSHA256(leaseEnvelope), LeaseSequence: 1}
	if _, err := verifyStage2aProtectedMemberRuntimeLease(leaseReply, ready, readyReply.SHA256,
		reply.SHA256, hqFinalization, grant, challenge, in, launcher, child, key,
		0, nil, now.Add(4*time.Second), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aProtectedMemberRuntimeLease(leaseReply, ready, readyReply.SHA256,
		reply.SHA256, "sha256:"+strings.Repeat("0", 64), grant, challenge,
		in, launcher, child, key, 0, nil, now.Add(4*time.Second), now.Add(time.Second)); err == nil {
		t.Fatal("lease for a different HQ finalization accepted")
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aMemberChildObservation(reply, in, grant, launcher, child, otherKey, now.Add(time.Second)); err == nil {
		t.Fatal("another A key accepted")
	}
	if _, err := verifyStage2aMemberChildObservation(reply, in,
		"sha256:"+strings.Repeat("f", 64), launcher, child, key, now.Add(time.Second)); err == nil {
		t.Fatal("wrong member grant accepted")
	}
	in.ChildExec.ProvisionalHQMapSHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := verifyStage2aMemberChildObservation(reply, in, grant, launcher, child, key, now.Add(time.Second)); err == nil {
		t.Fatal("different H provisional map accepted")
	}
}
