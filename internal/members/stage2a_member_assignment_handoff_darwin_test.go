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

func TestProtectedRunnerFD3UsesOneAKeyAndExactMemberAssignment(t *testing.T) {
	key, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reservation := "sha256:" + strings.Repeat("a", 64)
	info := strings.Repeat("b", 64)
	manifest := strings.Repeat("c", 64)
	ownerSet := "sha256:" + strings.Repeat("d", 64)
	projection := Stage2aHostProjection{Adapters: map[string]any{"claude-code": map[string]any{"command": []any{"/private/var/acp"}}},
		Installation: map[string]any{"id": "inst_0123456789abcdef"}}
	projectionRaw, err := marshalStage2aReservationJCS(projection)
	if err != nil {
		t.Fatal(err)
	}
	start := SoulStartAssignment{
		InstallationID: "inst_0123456789abcdef", SoulID: "agent_0b3f1e2a-7c4d-4e8f-9a1b-2c3d4e5f6a7b",
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("e", 64),
		PlanID: "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("f", 64),
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano),
		RunnerUID: 320, RunnerGID: 320, BridgeAccount: "_abm-bridge", BridgeUID: 321, BridgeGID: 321,
		Broker: SoulStartEndpoint{SocketPath: "/private/var/broker.sock", PeerUIDs: []int{320}},
		Member: SoulStartEndpoint{SocketPath: "/private/var/member.sock", PeerUIDs: []int{320}},
		Relay:  SoulStartEndpoint{SocketPath: "/private/var/relay.sock", PeerUIDs: []int{321}},
	}
	in := Stage2aRoleInvocation{Start: start,
		Binding: Stage2aMeasurementBinding{HostID: "host-1", SoulArtifactSHA256: "sha256:" + strings.Repeat("1", 64),
			DefinitionMeasurement: "sha256:" + strings.Repeat("2", 64)},
		Launch: Stage2aLaunchInputRecords{HostProjection: projection,
			EffectiveConfig:  map[string]any{"adapter_id": "claude-code"},
			ComponentDigests: map[string]string{"adapter": "sha256:" + strings.Repeat("3", 64)}},
		RunnerExec: &Stage2aRunnerExec{ReservationSHA256: reservation,
			Definition: []Stage2aDefinitionRecord{
				{Path: "Contents/SoulInfo.json", Kind: "regular", SHA256: info},
				{Path: "Contents/opt/stock-claude.json", Kind: "regular", SHA256: manifest},
			}},
	}
	assignment := stage2aMemberSetAssignmentPayload{
		Contract: "machine/v3", Kind: "stage2a-member-set-assignment", SchemaVersion: 1,
		ProfileInForce: "managed-protected", HostID: in.Binding.HostID,
		InstallationID: start.InstallationID, SoulID: start.SoulID, StartID: start.StartID,
		HQEpoch: start.HQEpoch, PlanID: start.PlanID, PlanDigest: start.PlanDigest,
		OwnerPlanMemberSetSHA256: ownerSet, ReservationSHA256: reservation,
		SoulArtifactSHA256: in.Binding.SoulArtifactSHA256, FrozenSoulInfoSHA256: "sha256:" + info,
		AdapterManifestRelpath:      "Contents/opt/stock-claude.json",
		FrozenAdapterManifestSHA256: "sha256:" + manifest,
		HostProjectionSHA256:        stage2aReservationSHA256(projectionRaw),
		DefinitionMeasurement:       in.Binding.DefinitionMeasurement,
		RunnerUID:                   start.RunnerUID, RunnerGID: start.RunnerGID,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano),
	}
	assignment.BAuthority.Purpose = stage2aReservationPurposeV3
	assignment.BAuthority.EnvelopeSHA256 = reservation
	assignment.Bridge.Account, assignment.Bridge.UID, assignment.Bridge.GID = start.BridgeAccount, start.BridgeUID, start.BridgeGID
	assignment.Bridge.Endpoints.Broker, assignment.Bridge.Endpoints.Member, assignment.Bridge.Endpoints.Relay = start.Broker, start.Member, start.Relay
	for i, memberID := range []string{"m_lead", "m_spec"} {
		role := "lead"
		if i == 1 {
			role = "specialist"
		}
		launchID := "ln_" + strings.Repeat(string(rune('1'+i)), 24)
		assignment.Members[i] = stage2aAssignedMember{MemberID: memberID, Role: role,
			AdapterID: "claude-code", AdapterVersion: "0.109.0", CommandPath: "/private/var/acp",
			CommandSHA256:   "sha256:" + strings.Repeat("3", 64),
			AdjacentCLIPath: "/private/var/claude", AdjacentCLISHA256: "sha256:" + strings.Repeat("4", 64),
			LaunchID: launchID, MemberSelector: stage2aMemberSelector(reservation, memberID, launchID)}
	}
	sign := func(a stage2aMemberSetAssignmentPayload, signingKey ed25519.PrivateKey, public ed25519.PublicKey) string {
		t.Helper()
		raw, err := signStage2aEnvelope(a, 1, stage2aMemberSetAssignmentPurpose, public,
			func(message []byte) ([]byte, error) { return ed25519.Sign(signingKey, message), nil })
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	encoded := sign(assignment, secret, key)
	if !stage2aRunnerMemberSetStillLive(encoded, now.Add(time.Second)) ||
		stage2aRunnerMemberSetStillLive(encoded, now.Add(21*time.Second)) {
		t.Fatal("R did not enforce assignment expiry immediately before FD3")
	}
	if _, err := verifyStage2aRunnerMemberSetAssignment(encoded, in, key, now.Add(time.Second)); err != nil {
		t.Fatalf("same-key assignment refused: %v", err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aRunnerMemberSetAssignment(encoded, in, otherKey, now.Add(time.Second)); err == nil {
		t.Fatal("assignment accepted under another Machine pin")
	}
	for name, edit := range map[string]func(*stage2aMemberSetAssignmentPayload){
		"reservation": func(a *stage2aMemberSetAssignmentPayload) { a.ReservationSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"B socket":    func(a *stage2aMemberSetAssignmentPayload) { a.Bridge.Endpoints.Relay.SocketPath += "-other" },
		"selector":    func(a *stage2aMemberSetAssignmentPayload) { a.Members[1].MemberSelector += "-other" },
		"command":     func(a *stage2aMemberSetAssignmentPayload) { a.Members[1].CommandPath += "-other" },
		"profile":     func(a *stage2aMemberSetAssignmentPayload) { a.ProfileInForce = "managed-cooperative" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := assignment
			edit(&changed)
			if _, err := verifyStage2aRunnerMemberSetAssignment(sign(changed, secret, key), in, key, now.Add(time.Second)); err == nil {
				t.Fatal("signed but mismatched assignment accepted")
			}
		})
	}
	if _, err := verifyStage2aRunnerMemberSetAssignment(encoded, in, key, now.Add(21*time.Second)); err == nil {
		t.Fatal("expired assignment accepted")
	}
	planRaw, err := json.Marshal(Plan{Purpose: SoulProtectedLaunchInstallPurpose,
		SoulProtectedLaunch: &SoulProtectedLaunchInstall{OwnerPlanMemberSetSHA256: ownerSet}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	r := &stage2aLiveReservation{memberSetAssignmentEnvelope: raw,
		memberSetAssignmentExpires: now.Add(20 * time.Second)}
	p := stage2aInstalledPolicy{Plan: planRaw}
	if got, err := stage2aRunnerMemberSetFromA(r, p, in, key, now.Add(time.Second)); err != nil || got != encoded {
		t.Fatalf("A refused retained assignment: %v", err)
	}
	r.memberSetAssignmentEnvelope = nil
	if _, err := stage2aRunnerMemberSetFromA(r, p, in, key, now.Add(time.Second)); err == nil {
		t.Fatal("reviewed two-member plan accepted missing assignment")
	}
	r.memberSetAssignmentEnvelope = raw
	p.Plan, err = json.Marshal(Plan{Purpose: SoulProtectedLaunchInstallPurpose,
		SoulProtectedLaunch: &SoulProtectedLaunchInstall{OwnerPlanMemberSetSHA256: "sha256:" + strings.Repeat("0", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage2aRunnerMemberSetFromA(r, p, in, key, now.Add(time.Second)); err == nil {
		t.Fatal("assignment accepted under a different owner-reviewed member set")
	}
	p.Plan, err = json.Marshal(Plan{Purpose: SoulProtectedLaunchInstallPurpose,
		SoulProtectedLaunch: &SoulProtectedLaunchInstall{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage2aRunnerMemberSetFromA(r, p, in, key, now.Add(time.Second)); err == nil {
		t.Fatal("legacy plan accepted a two-member assignment")
	}
	r.memberSetAssignmentEnvelope = nil
	if got, err := stage2aRunnerMemberSetFromA(r, p, in, key, now.Add(time.Second)); err != nil || got != "" {
		t.Fatalf("legacy one-member plan refused: %v", err)
	}
}

func TestProtectedRunnerFD3V1AndV2HaveClosedFields(t *testing.T) {
	assignment := base64.RawURLEncoding.EncodeToString([]byte("signed-assignment"))
	for _, tc := range []struct {
		name, member, schema string
		fields               int
	}{
		{"legacy", "", "agent-bot-souls/protected-start/v1", 6},
		{"member set", assignment, "agent-bot-souls/protected-start/v2", 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := marshalStage2aSoulsProtectedStart("reservation", "sha256:"+strings.Repeat("a", 64),
				Stage2aLaunchInputRecords{}, "/private/var/runner", tc.member)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != tc.fields ||
				string(fields["schema"]) != `"`+tc.schema+`"` ||
				string(fields["machine_pin_path"]) != `"`+SoulAuthorityPin+`"` {
				t.Fatalf("FD3 shape changed: %s", raw)
			}
			_, memberPresent := fields["member_set_assignment_envelope_base64url"]
			if memberPresent != (tc.member != "") {
				t.Fatal("FD3 assignment field presence differs from schema")
			}
			if _, extra := fields["admission_challenge_base64url"]; extra {
				t.Fatal("protected FD3 gained a cooperative-only challenge")
			}
		})
	}
}
