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
		Kind: "stage2a-member-set-assignment", SchemaVersion: 1,
		HostID: "host-1", InstallationID: start.InstallationID,
		SoulID: start.SoulID, StartID: start.StartID, HQEpoch: start.HQEpoch,
		ReservationSHA256: reservation, ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
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
		Binding: Stage2aMeasurementBinding{HostID: assignment.HostID},
		ChildExec: &Stage2aChildExec{MemberID: "m_lead",
			MemberLaunchID:                       assignment.Members[0].LaunchID,
			MemberSelector:                       assignment.Members[0].MemberSelector,
			MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(assignmentEnvelope),
			ProvisionalHQMapSHA256:               stage2aReservationSHA256(mapRaw),
			ReservationSHA256:                    reservation, ExecutableSHA256: commandSHA,
			GrantExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}}
	if _, err := verifyStage2aMemberChildObservation(reply, in, grant, launcher, child, key, now.Add(time.Second)); err != nil {
		t.Fatal(err)
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
