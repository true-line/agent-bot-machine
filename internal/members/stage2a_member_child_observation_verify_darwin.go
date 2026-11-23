//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

// The fixed R-UID wrapper accepts H's relayed observation only when the
// installed A key signed both granted members, the exact withheld H map, and
// this wrapper's live kernel parent/child pair. The observation is not Ready.
func verifyStage2aMemberChildObservation(reply Stage2aHelloReply,
	in Stage2aRoleInvocation, grantSHA256 string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, now time.Time) (stage2aMemberChildObservationPayload, error) {
	var observation stage2aMemberChildObservationPayload
	invalid := errors.New("invalid Machine two-member child observation")
	exec := in.ChildExec
	if exec == nil || !stage2aPrefixedDigest.MatchString(reply.SHA256) ||
		!stage2aPrefixedDigest.MatchString(grantSHA256) {
		return observation, invalid
	}
	envelope, err := decodeStage2aRoleBase64(reply.EnvelopeBase64URL, 16<<10)
	if err != nil || stage2aReservationSHA256(envelope) != reply.SHA256 {
		return observation, invalid
	}
	raw, err := verifyStage2aStoredARecordV3(envelope, Stage2aMemberChildObservationPurpose, 1, pub)
	if err != nil || stage2aDecodeExact(raw, &observation) != nil {
		return observation, invalid
	}
	canonical, err := marshalStage2aReservationJCS(observation)
	if err != nil || !bytes.Equal(raw, canonical) ||
		observation.Contract != "machine/v3" ||
		observation.Kind != "stage2a-member-set-child-observation" ||
		observation.SchemaVersion != 1 || observation.ProfileInForce != "managed-protected" ||
		observation.HostID != in.Binding.HostID ||
		observation.InstallationID != in.Start.InstallationID ||
		observation.SoulID != in.Start.SoulID || observation.StartID != in.Start.StartID ||
		observation.HQEpoch != in.Start.HQEpoch ||
		observation.ReservationSHA256 != exec.ReservationSHA256 ||
		observation.ProvisionalHQMappingSHA256 != exec.ProvisionalHQMapSHA256 ||
		stage2aReservationSHA256(observation.ProvisionalHQMapping) != exec.ProvisionalHQMapSHA256 {
		return observation, invalid
	}
	assignmentEnvelope, err := decodeStage2aRoleBase64(exec.MemberSetAssignmentEnvelopeBase64URL, 16<<10)
	if err != nil || observation.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(assignmentEnvelope) {
		return observation, invalid
	}
	assignmentRaw, err := verifyStage2aStoredARecordV3(assignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, pub)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.ReservationSHA256 != exec.ReservationSHA256 ||
		assignment.InstallationID != in.Start.InstallationID ||
		assignment.StartID != in.Start.StartID || assignment.HQEpoch != in.Start.HQEpoch ||
		assignment.HostID != in.Binding.HostID || assignment.SoulID != in.Start.SoulID {
		return observation, invalid
	}
	mapRequest := Stage2aMemberProvisionalMapRequest{
		ProvisionalHQMappingBase64URL: base64.RawURLEncoding.EncodeToString(observation.ProvisionalHQMapping),
		ProvisionalHQMappingSHA256:    observation.ProvisionalHQMappingSHA256,
	}
	mapRaw, mapping, err := stage2aDecodeProvisionalMap(mapRequest)
	if err != nil || !bytes.Equal(mapRaw, observation.ProvisionalHQMapping) ||
		mapping.AssignmentEnvelopeSHA256 != observation.AssignmentEnvelopeSHA256 ||
		mapping.HostID != observation.HostID || mapping.InstallationID != observation.InstallationID ||
		mapping.SoulID != observation.SoulID || mapping.StartID != observation.StartID ||
		mapping.HQEpoch != observation.HQEpoch {
		return observation, invalid
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, observation.IssuedAt)
	observed, observedErr := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, observation.ExpiresAt)
	mapExpires, mapExpiryErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	assignmentExpires, assignmentExpiryErr := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	grantExpires, grantExpiryErr := time.Parse(time.RFC3339Nano, exec.GrantExpiresAt)
	if issueErr != nil || observedErr != nil || expiryErr != nil || mapExpiryErr != nil ||
		assignmentExpiryErr != nil || grantExpiryErr != nil || issued.After(now) ||
		observed.After(issued) || !now.Before(expires) || expires.Sub(issued) > 15*time.Second ||
		expires.After(mapExpires) || expires.After(assignmentExpires) || expires.After(grantExpires) {
		return observation, invalid
	}
	selected := 0
	for i, member := range observation.Members {
		assigned := assignment.Members[i]
		mapped := mapping.Members[i]
		if member.MemberID != assigned.MemberID || member.MemberID != mapped.MemberID ||
			member.LaunchID != assigned.LaunchID ||
			member.MemberSelector != assigned.MemberSelector ||
			member.MemberSelector != mapped.MemberSelector ||
			member.RuntimeID != mapped.RuntimeID ||
			!stage2aPrefixedDigest.MatchString(member.GrantSHA256) ||
			member.LauncherProcess.UID != in.Runner.UID ||
			member.LauncherProcess.GID != in.Runner.GID ||
			member.ChildProcess.UID != in.Runner.UID ||
			member.ChildProcess.GID != in.Runner.GID ||
			member.ChildProcess.ParentPID != member.LauncherProcess.PID ||
			member.ChildProcess.ProcessGroupID != member.ChildProcess.PID ||
			member.ChildProcess.ExecutableSHA256 != assigned.CommandSHA256 ||
			member.ChildProcess.PID == observation.Members[1-i].ChildProcess.PID ||
			member.LauncherProcess.PID == observation.Members[1-i].LauncherProcess.PID {
			return observation, invalid
		}
		if member.MemberID == exec.MemberID {
			selected++
			if member.LaunchID != exec.MemberLaunchID || member.MemberSelector != exec.MemberSelector ||
				member.GrantSHA256 != grantSHA256 ||
				member.LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
				member.ChildProcess != stage2aMemberProcessIdentity(child, exec.ExecutableSHA256) {
				return observation, invalid
			}
		}
	}
	if selected != 1 {
		return observation, invalid
	}
	return observation, nil
}
