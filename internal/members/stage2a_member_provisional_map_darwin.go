//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// MemberProvisionalMap accepts only H's exact withheld two-member map after
// A's signed assignment and provisional Hello. It gives H no signed readiness
// receipt; A will bind these exact bytes in a later child observation.
func (s *Stage2aService) MemberProvisionalMap(hqUID int, epoch string,
	q Stage2aMemberProvisionalMapRequest) (Stage2aMemberProvisionalMapReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aMemberProvisionalMapReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	mapRaw, mapping, err := stage2aDecodeProvisionalMap(q)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.memberSetAssignmentEnvelope) == 0 || len(p.MemberBridgeQualifications) != 2 ||
		r.hello == nil || r.hello.aborted || r.hello.finalized ||
		len(r.hello.startEnvelope) == 0 || len(r.hello.members) != 2 ||
		r.childLauncherPID != 0 || r.childPID != 0 || r.twoMemberChildren != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	if !now.Before(r.memberSetAssignmentExpires) {
		return reply, errStage2aReservationExpired
	}
	key := s.key.Public().(ed25519.PublicKey)
	assignmentRaw, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || json.Unmarshal(assignmentRaw, &assignment) != nil ||
		assignment.Contract != "machine/v3" || assignment.Kind != "stage2a-member-set-assignment" ||
		assignment.SchemaVersion != 1 || assignment.ReservationSHA256 != r.digest ||
		assignment.InstallationID != r.request.InstallationID ||
		assignment.StartID != r.request.StartID || assignment.HQEpoch != r.request.HQEpoch ||
		assignment.HostID != p.Binding.HostID || assignment.SoulID != p.Binding.SoulID ||
		assignment.PlanID != r.payload.Assignment.PlanID || assignment.PlanDigest != r.request.PlanDigest {
		return reply, errStage2aReservationAuthority
	}
	if mapping.HostID != assignment.HostID || mapping.InstallationID != assignment.InstallationID ||
		mapping.SoulID != assignment.SoulID || mapping.StartID != assignment.StartID ||
		mapping.HQEpoch != assignment.HQEpoch || mapping.ProfileInForce != assignment.ProfileInForce ||
		mapping.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) {
		return reply, errStage2aReservationAuthority
	}
	for i, member := range mapping.Members {
		if member.MemberID != assignment.Members[i].MemberID ||
			member.MemberSelector != assignment.Members[i].MemberSelector ||
			member.MemberID != r.hello.members[i] ||
			member.MemberSelector != stage2aMemberSelector(r.digest, member.MemberID, assignment.Members[i].LaunchID) {
			return reply, errStage2aReservationAuthority
		}
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, mapping.IssuedAt)
	until, expiryErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	if issueErr != nil || expiryErr != nil || issued.After(now.Add(time.Second)) ||
		now.Sub(issued) > 5*time.Second || !now.Before(until) ||
		until.After(r.memberSetAssignmentExpires) || until.After(expires) ||
		len(r.provisionalHQMap) != 0 && !bytes.Equal(r.provisionalHQMap, mapRaw) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.provisionalHQMap = bytes.Clone(mapRaw)
	r.provisionalHQMapSHA256 = q.ProvisionalHQMappingSHA256
	return Stage2aMemberProvisionalMapReply{Accepted: true, SHA256: q.ProvisionalHQMappingSHA256}, nil
}
