//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"time"
)

// CooperativeProvisionalMap retains H's exact withheld two-member intent.
// This grants no ACP authority; A later joins it to two independent kernel
// observations and signs a separate aggregate child observation.
func (s *Stage2aService) CooperativeProvisionalMap(hqUID int, epoch string,
	q Stage2aMemberProvisionalMapRequest,
	paired func(string, func() error) error) (Stage2aMemberProvisionalMapReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aMemberProvisionalMapReply
	mapRaw, mapping, err := decodeSoulCooperativeProvisionalMap(q)
	if err != nil || q.HQEpoch != epoch || paired == nil || len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || !live.bridgeBindVerified ||
		len(live.bridgeObservedEnvelope) == 0 || len(live.memberBAuthorityEnvelope) == 0 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch ||
		len(live.provisionalHQMap) != 0 && !bytes.Equal(live.provisionalHQMap, mapRaw) {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err = paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		assignmentRaw, err := verifyStage2aStoredARecordV3(live.memberEnvelope,
			stage2aMemberSetAssignmentPurpose, 1, pub)
		var assignment soulCooperativeMemberSetAssignmentV3
		if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
			assignment.ProfileInForce != "managed-cooperative" ||
			assignment.ReservationSHA256 != live.digest ||
			assignment.InstallationID != q.InstallationID ||
			assignment.StartID != q.StartID || assignment.HQEpoch != epoch ||
			assignment.PlanID != q.PlanID || assignment.PlanDigest != q.PlanDigest ||
			mapping.HostID != assignment.HostID ||
			mapping.InstallationID != assignment.InstallationID ||
			mapping.SoulID != assignment.SoulID || mapping.StartID != assignment.StartID ||
			mapping.HQEpoch != epoch || mapping.AssignmentEnvelopeSHA256 != live.memberSHA {
			return errSoulCooperativeAuthority
		}
		for i, member := range mapping.Members {
			if member.MemberID != assignment.Members[i].MemberID ||
				member.MemberSelector != assignment.Members[i].MemberSelector ||
				member.MemberSelector != stage2aMemberSelector(live.digest,
					member.MemberID, assignment.Members[i].LaunchID) {
				return errSoulCooperativeAuthority
			}
		}
		now := time.Now().UTC()
		issued, e1 := time.Parse(time.RFC3339Nano, mapping.IssuedAt)
		expires, e2 := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
		assignmentExpires, e3 := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
		if e1 != nil || e2 != nil || e3 != nil || issued.After(now.Add(time.Second)) ||
			now.Sub(issued) > 5*time.Second || !now.Before(expires) ||
			expires.After(assignmentExpires) || len(live.childGrants) != 0 {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, err := store.open()
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer dir.Close()
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
				store.uid, store.gid) != nil {
			return errSoulCooperativeAuthority
		}
		live.provisionalHQMap = bytes.Clone(mapRaw)
		live.provisionalHQMapSHA256 = q.ProvisionalHQMappingSHA256
		reply = Stage2aMemberProvisionalMapReply{Accepted: true, SHA256: q.ProvisionalHQMappingSHA256}
		return nil
	})
	if err != nil || !ran || !reply.Accepted {
		return Stage2aMemberProvisionalMapReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
