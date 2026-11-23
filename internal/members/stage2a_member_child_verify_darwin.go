//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// The fixed child wrapper verifies the selected member against A's own
// signed assignment before creating its separate state root or starting ACP.
func stage2aVerifyMemberChildGrant(grant Stage2aRoleGrant, in Stage2aRoleInvocation,
	key ed25519.PublicKey, now time.Time) bool {
	child := in.ChildExec
	if child == nil {
		return false
	}
	if grant.MemberID == "" && grant.MemberLaunchID == "" && grant.MemberSelector == "" &&
		grant.MemberSetAssignmentEnvelopeSHA256 == "" {
		return child.MemberID == "" && child.MemberLaunchID == "" &&
			child.MemberSelector == "" && child.MemberSetAssignmentEnvelopeBase64URL == "" &&
			child.ProvisionalHQMapSHA256 == ""
	}
	if !stage2aBindingID.MatchString(grant.MemberID) ||
		!soulLaunchID.MatchString(grant.MemberLaunchID) ||
		!stage2aMemberSelectorPattern.MatchString(grant.MemberSelector) ||
		!stage2aPrefixedDigest.MatchString(grant.MemberSetAssignmentEnvelopeSHA256) ||
		!stage2aPrefixedDigest.MatchString(child.ProvisionalHQMapSHA256) ||
		child.MemberID != grant.MemberID || child.MemberLaunchID != grant.MemberLaunchID ||
		child.MemberSelector != grant.MemberSelector || child.HelloFinalizationSHA256 != "" ||
		len(key) != ed25519.PublicKeySize {
		return false
	}
	envelope, err := decodeStage2aRoleBase64(child.MemberSetAssignmentEnvelopeBase64URL, 16<<10)
	if err != nil || stage2aReservationSHA256(envelope) != grant.MemberSetAssignmentEnvelopeSHA256 {
		return false
	}
	raw, err := verifyStage2aStoredARecordV3(envelope, stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(raw, &assignment) != nil ||
		assignment.Contract != "machine/v3" || assignment.Kind != "stage2a-member-set-assignment" ||
		assignment.SchemaVersion != 1 || assignment.ProfileInForce != "managed-protected" ||
		assignment.HostID != in.Binding.HostID || assignment.InstallationID != in.Start.InstallationID ||
		assignment.SoulID != in.Start.SoulID || assignment.StartID != in.Start.StartID ||
		assignment.HQEpoch != in.Start.HQEpoch || assignment.PlanID != in.Start.PlanID ||
		assignment.PlanDigest != in.Start.PlanDigest || assignment.ReservationSHA256 != grant.ReservationSHA256 ||
		assignment.BAuthority.Purpose != stage2aReservationPurposeV3 ||
		assignment.BAuthority.EnvelopeSHA256 != grant.ReservationSHA256 ||
		assignment.DefinitionMeasurement != in.Binding.DefinitionMeasurement ||
		assignment.RunnerUID != in.Runner.UID || assignment.RunnerGID != in.Runner.GID ||
		assignment.Bridge.Account != in.Bridge.Account || assignment.Bridge.UID != in.Bridge.UID ||
		assignment.Bridge.GID != in.Bridge.GID ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Broker, in.Start.Broker) ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Member, in.Start.Member) ||
		!reflect.DeepEqual(assignment.Bridge.Endpoints.Relay, in.Start.Relay) {
		return false
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, assignment.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	startExpires, startErr := time.Parse(time.RFC3339Nano, in.Start.ExpiresAt)
	if issuedErr != nil || expiryErr != nil || startErr != nil || issued.After(now) ||
		!now.Before(expires) || expires.After(startExpires) ||
		expires.Sub(issued) > 20*time.Second || !expires.After(issued) ||
		assignment.Members[0].MemberID >= assignment.Members[1].MemberID ||
		assignment.Members[0].LaunchID == assignment.Members[1].LaunchID ||
		assignment.Members[0].MemberSelector == assignment.Members[1].MemberSelector {
		return false
	}
	selected := false
	for _, member := range assignment.Members {
		if member.MemberSelector != stage2aMemberSelector(grant.ReservationSHA256,
			member.MemberID, member.LaunchID) ||
			member.CommandPath != child.Executable || member.CommandSHA256 != child.ExecutableSHA256 ||
			member.AdjacentCLIPath != filepath.Join(filepath.Dir(child.Executable), "claude") ||
			!stage2aPrefixedDigest.MatchString(member.AdjacentCLISHA256) {
			return false
		}
		selected = selected || member.MemberID == grant.MemberID &&
			member.LaunchID == grant.MemberLaunchID && member.MemberSelector == grant.MemberSelector
	}
	if !selected || grant.MemberSelector != stage2aMemberSelector(grant.ReservationSHA256,
		grant.MemberID, grant.MemberLaunchID) ||
		child.ExecutableSHA256 != in.Launch.ComponentDigests["adapter"] ||
		assignment.SoulArtifactSHA256 != in.Binding.SoulArtifactSHA256 ||
		!strings.HasPrefix(child.Executable, in.Binding.Snapshots.LaunchInputs.RootPath+"/") {
		return false
	}
	roles := []stage2aHelloMember{
		{MemberID: assignment.Members[0].MemberID, Role: assignment.Members[0].Role,
			AdapterID: assignment.Members[0].AdapterID, AdapterVersion: assignment.Members[0].AdapterVersion},
		{MemberID: assignment.Members[1].MemberID, Role: assignment.Members[1].Role,
			AdapterID: assignment.Members[1].AdapterID, AdapterVersion: assignment.Members[1].AdapterVersion},
	}
	ownerDigest, err := stage2aOwnerMemberSetDigest(roles, child.Executable,
		child.ExecutableSHA256, assignment.Members[0].AdjacentCLIPath,
		assignment.Members[0].AdjacentCLISHA256)
	projectionRaw, projectionErr := marshalStage2aReservationJCS(in.Launch.HostProjection)
	if err != nil || projectionErr != nil || ownerDigest != assignment.OwnerPlanMemberSetSHA256 ||
		stage2aReservationSHA256(projectionRaw) != assignment.HostProjectionSHA256 {
		return false
	}
	matchedCLI := 0
	for _, file := range in.Launch.Files {
		if file.Path == "runtime/bin/claude" &&
			"sha256:"+file.SHA256 == assignment.Members[0].AdjacentCLISHA256 {
			matchedCLI++
		}
	}
	return matchedCLI == 1 &&
		base64.RawURLEncoding.EncodeToString(envelope) == child.MemberSetAssignmentEnvelopeBase64URL
}
