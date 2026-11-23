//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

// The same installed A pin authenticates both the reservation and this
// assignment. The runner receives neither a new key nor a caller-selected
// member command through its role grant.
func verifyStage2aRunnerMemberSetAssignment(encoded string, in Stage2aRoleInvocation,
	key ed25519.PublicKey, now time.Time) (stage2aMemberSetAssignmentPayload, error) {
	var empty stage2aMemberSetAssignmentPayload
	invalid := errors.New("protected member assignment differs from Machine's signed start")
	if in.RunnerExec == nil || len(key) != ed25519.PublicKeySize {
		return empty, invalid
	}
	raw, err := decodeStage2aRoleBase64(encoded, 16<<10)
	var envelope stage2aSignedReservation
	if err != nil || stage2aDecodeExact(raw, &envelope) != nil || envelope.SchemaVersion != 1 ||
		envelope.Purpose != stage2aMemberSetAssignmentPurpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(key) {
		return empty, invalid
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return empty, invalid
	}
	payload, err := decodeStage2aRoleBase64(envelope.PayloadBase64URL, 12<<10)
	if err != nil || stage2aReservationSHA256(payload) != envelope.PayloadSHA256 {
		return empty, invalid
	}
	signature, err := decodeStage2aRoleBase64(envelope.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(key,
		append([]byte(stage2aMemberSetAssignmentPurpose+"\x00"), payload...), signature) {
		return empty, invalid
	}
	var assignment stage2aMemberSetAssignmentPayload
	if stage2aDecodeExact(payload, &assignment) != nil {
		return empty, invalid
	}
	canonical, err = marshalStage2aReservationJCS(assignment)
	if err != nil || !bytes.Equal(payload, canonical) ||
		!stage2aRunnerMemberSetMatches(assignment, in, now) {
		return empty, invalid
	}
	return assignment, nil
}

func stage2aRunnerMemberSetMatches(a stage2aMemberSetAssignmentPayload,
	in Stage2aRoleInvocation, now time.Time) bool {
	run := in.RunnerExec
	if run == nil || now.IsZero() {
		return false
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, a.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	startExpires, startErr := time.Parse(time.RFC3339Nano, in.Start.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || startErr != nil ||
		issued.After(now) || !now.Before(expires) || expires.After(startExpires) ||
		!expires.After(issued) || expires.Sub(issued) > 20*time.Second ||
		a.Contract != "machine/v3" || a.Kind != "stage2a-member-set-assignment" ||
		a.SchemaVersion != 1 || a.ProfileInForce != "managed-protected" ||
		!stage2aPrefixedDigest.MatchString(a.OwnerPlanMemberSetSHA256) ||
		a.HostID != in.Binding.HostID || a.InstallationID != in.Start.InstallationID ||
		a.SoulID != in.Start.SoulID || a.StartID != in.Start.StartID ||
		a.HQEpoch != in.Start.HQEpoch || a.PlanID != in.Start.PlanID ||
		a.PlanDigest != in.Start.PlanDigest || a.ReservationSHA256 != run.ReservationSHA256 ||
		a.BAuthority.Purpose != stage2aReservationPurposeV3 ||
		a.BAuthority.EnvelopeSHA256 != run.ReservationSHA256 ||
		a.SoulArtifactSHA256 != in.Binding.SoulArtifactSHA256 ||
		a.DefinitionMeasurement != in.Binding.DefinitionMeasurement ||
		a.RunnerUID != in.Start.RunnerUID || a.RunnerGID != in.Start.RunnerGID ||
		a.Bridge.Account != in.Start.BridgeAccount || a.Bridge.UID != in.Start.BridgeUID ||
		a.Bridge.GID != in.Start.BridgeGID ||
		!reflect.DeepEqual(a.Bridge.Endpoints.Broker, in.Start.Broker) ||
		!reflect.DeepEqual(a.Bridge.Endpoints.Member, in.Start.Member) ||
		!reflect.DeepEqual(a.Bridge.Endpoints.Relay, in.Start.Relay) ||
		a.AdapterManifestRelpath != "Contents/opt/stock-claude.json" ||
		a.FrozenSoulInfoSHA256 != stage2aRunnerDefinitionFileSHA(run.Definition, "Contents/SoulInfo.json") ||
		a.FrozenAdapterManifestSHA256 != stage2aRunnerDefinitionFileSHA(run.Definition, a.AdapterManifestRelpath) {
		return false
	}
	projection, err := marshalStage2aReservationJCS(in.Launch.HostProjection)
	if err != nil || a.HostProjectionSHA256 != stage2aReservationSHA256(projection) {
		return false
	}
	adapterID, _ := in.Launch.EffectiveConfig["adapter_id"].(string)
	adapter, _ := in.Launch.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if adapterID == "" || len(command) != 1 {
		return false
	}
	commandPath, _ := command[0].(string)
	if commandPath == "" || !stage2aPrefixedDigest.MatchString(in.Launch.ComponentDigests["adapter"]) {
		return false
	}
	lead, specialist := false, false
	for i, member := range a.Members {
		if member.MemberID == "" || member.AdapterID != adapterID || member.AdapterVersion == "" ||
			member.CommandPath != commandPath || member.CommandSHA256 != in.Launch.ComponentDigests["adapter"] ||
			member.AdjacentCLIPath == "" || !stage2aPrefixedDigest.MatchString(member.AdjacentCLISHA256) ||
			!soulLaunchID.MatchString(member.LaunchID) ||
			member.MemberSelector != stage2aMemberSelector(a.ReservationSHA256, member.MemberID, member.LaunchID) ||
			(i > 0 && (a.Members[i-1].MemberID >= member.MemberID ||
				a.Members[i-1].AdapterVersion != member.AdapterVersion ||
				a.Members[i-1].AdjacentCLIPath != member.AdjacentCLIPath ||
				a.Members[i-1].AdjacentCLISHA256 != member.AdjacentCLISHA256 ||
				a.Members[i-1].LaunchID == member.LaunchID ||
				a.Members[i-1].MemberSelector == member.MemberSelector)) {
			return false
		}
		lead = lead || member.Role == "lead"
		specialist = specialist || member.Role == "specialist"
	}
	return lead && specialist
}

func stage2aRunnerDefinitionFileSHA(records []Stage2aDefinitionRecord, name string) string {
	for _, row := range records {
		if row.Path == name && row.Kind == "regular" && soulDigest.MatchString(row.SHA256) {
			return "sha256:" + row.SHA256
		}
	}
	return ""
}

// Role-grant verification authenticated these immutable bytes earlier. A
// potentially slow snapshot recheck must not deliver them after expiry.
func stage2aRunnerMemberSetStillLive(encoded string, now time.Time) bool {
	if encoded == "" {
		return true
	}
	raw, err := decodeStage2aRoleBase64(encoded, 16<<10)
	var envelope stage2aSignedReservation
	if err != nil || stage2aDecodeExact(raw, &envelope) != nil {
		return false
	}
	payload, err := decodeStage2aRoleBase64(envelope.PayloadBase64URL, 12<<10)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(payload, &assignment) != nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	return err == nil && now.Before(expires)
}

func stage2aRunnerMemberSetFromA(r *stage2aLiveReservation, p stage2aInstalledPolicy,
	in Stage2aRoleInvocation, key ed25519.PublicKey, now time.Time) (string, error) {
	invalid := errors.New("protected member assignment unavailable for runner grant")
	var plan Plan
	if r == nil || in.RunnerExec == nil || stage2aStrictJSON(p.Plan) != nil || json.Unmarshal(p.Plan, &plan) != nil ||
		plan.Purpose != SoulProtectedLaunchInstallPurpose || plan.SoulProtectedLaunch == nil {
		return "", invalid
	}
	want := plan.SoulProtectedLaunch.OwnerPlanMemberSetSHA256
	if want == "" {
		if len(r.memberSetAssignmentEnvelope) != 0 {
			return "", invalid
		}
		return "", nil // Legacy protected-start/v1 remains byte-for-byte available.
	}
	if !stage2aPrefixedDigest.MatchString(want) || len(r.memberSetAssignmentEnvelope) == 0 ||
		!now.Before(r.memberSetAssignmentExpires) {
		return "", invalid
	}
	encoded := base64.RawURLEncoding.EncodeToString(r.memberSetAssignmentEnvelope)
	assignment, err := verifyStage2aRunnerMemberSetAssignment(encoded, in, key, now)
	if err != nil || assignment.OwnerPlanMemberSetSHA256 != want {
		return "", invalid
	}
	return encoded, nil
}
