//go:build darwin

package members

import (
	"crypto/ed25519"
	"time"
)

type stage2aMemberLiveLeasePayload struct {
	Contract                       string                               `json:"contract"`
	Kind                           string                               `json:"kind"`
	SchemaVersion                  int                                  `json:"schema_version"`
	ProfileInForce                 string                               `json:"profile_in_force"`
	HostID                         string                               `json:"host_id"`
	InstallationID                 string                               `json:"installation_id"`
	SoulID                         string                               `json:"soul_id"`
	StartID                        string                               `json:"start_id"`
	HQEpoch                        string                               `json:"hq_epoch"`
	ReservationSHA256              string                               `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256       string                               `json:"assignment_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string                               `json:"child_observation_envelope_sha256"`
	MemberID                       string                               `json:"member_id"`
	MemberSelector                 string                               `json:"member_selector"`
	MemberLaunchID                 string                               `json:"member_launch_id"`
	GrantSHA256                    string                               `json:"grant_sha256"`
	LauncherProcess                stage2aMemberObservedLauncherProcess `json:"launcher_process"`
	ChildProcess                   stage2aMemberObservedProcess         `json:"child_process"`
	ChallengeNonceBase64URL        string                               `json:"challenge_nonce_base64url"`
	Sequence                       uint64                               `json:"sequence"`
	IssuedAt                       string                               `json:"issued_at"`
	ExpiresAt                      string                               `json:"expires_at"`
}

// MemberLive extends one inert wrapper only while both previously observed
// children and the same H/R/B/Q start remain live. It never releases ACP
// input or authorizes provider ingress; a missed five-second lease cuts off.
func (s *Stage2aService) MemberLive(hqUID int, epoch string,
	q Stage2aMemberLiveRequest) (Stage2aLiveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aLiveReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize || q.PeerPID != q.LauncherPID ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) ||
		q.AfterSequence >= (1<<53)-1 {
		return reply, errStage2aReservationAuthority
	}
	r, p, reservationExpires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.memberChildObservationEnvelope) == 0 || r.twoMemberChildren == nil ||
		len(r.memberChildGrants) != 2 || len(r.provisionalHQMap) == 0 ||
		r.protectedQ.recheckMemberQ() != nil ||
		r.hello == nil || r.hello.aborted || r.hello.finalized ||
		q.PeerUID != p.Runner.UID ||
		q.ChildObservationEnvelopeSHA256 != stage2aReservationSHA256(r.memberChildObservationEnvelope) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	grant := r.memberChildGrants[q.MemberID]
	if grant.MemberID != q.MemberID || grant.MemberSelector != q.MemberSelector ||
		grant.MemberLaunchID != q.MemberLaunchID || grant.GrantSHA256 != q.GrantSHA256 ||
		grant.Launcher.PID != q.LauncherPID || grant.ChildPID != q.ChildPID ||
		grant.Child.PID != q.ChildPID || grant.LiveSequence != q.AfterSequence ||
		grant.LastNonce == q.ChallengeNonceBase64URL ||
		q.MemberSelector != stage2aMemberSelector(r.digest, q.MemberID, q.MemberLaunchID) ||
		checkStage2aGrantedRoleProcess(q.PeerPID, p.Runner.UID, p.Runner.GID,
			"child", grant.Launcher) != nil {
		return reply, errStage2aReservationAuthority
	}
	selected := -1
	for i, member := range r.twoMemberChildren.Members {
		if member.MemberID == q.MemberID {
			selected = i
		}
	}
	if selected < 0 || !sameSoulKernelProcess(r.twoMemberChildren.Members[selected].Launcher, grant.Launcher) ||
		!sameSoulKernelProcess(r.twoMemberChildren.Members[selected].Child, grant.Child) ||
		checkStage2aChildProcess(q.ChildPID, q.LauncherPID, p.Runner, p.LaunchInputs, grant.Child) != nil {
		return reply, errStage2aReservationAuthority
	}
	var mapping Stage2aProvisionalMemberMap
	if stage2aDecodeExact(r.provisionalHQMap, &mapping) != nil ||
		mapping.ACPAuthority != "withheld" || mapping.RuntimeState != "provisional" ||
		mapping.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	mapExpires, mapErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	prior, priorErr := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
	wantPrior := r.memberChildObservationExpires
	if grant.LiveSequence != 0 {
		wantPrior = grant.LiveExpiresAt
	}
	if mapErr != nil || priorErr != nil || !prior.Equal(wantPrior) ||
		!now.Before(wantPrior) || !now.Before(mapExpires) ||
		!now.Before(r.memberSetAssignmentExpires) || !now.Before(grant.ExpiresAt) ||
		!now.Before(r.memberChildObservationExpires) ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	until := minStage2aTime(now.Add(stage2aLiveLease), approvedUntil)
	until = minStage2aTime(until, reservationExpires)
	until = minStage2aTime(until, r.memberSetAssignmentExpires)
	until = minStage2aTime(until, mapExpires)
	until = minStage2aTime(until, r.memberChildObservationExpires)
	until = minStage2aTime(until, grant.ExpiresAt)
	if approvalErr != nil || !until.After(now) {
		return reply, errStage2aReservationAuthority
	}
	payload := stage2aMemberLiveLeasePayload{Contract: "machine/v3", Kind: "stage2a-member-live-lease",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: p.Binding.HostID,
		InstallationID: q.InstallationID, SoulID: p.Binding.SoulID,
		StartID: q.StartID, HQEpoch: epoch, ReservationSHA256: r.digest,
		AssignmentEnvelopeSHA256:       stage2aReservationSHA256(r.memberSetAssignmentEnvelope),
		ChildObservationEnvelopeSHA256: q.ChildObservationEnvelopeSHA256,
		MemberID:                       q.MemberID, MemberSelector: q.MemberSelector, MemberLaunchID: q.MemberLaunchID,
		GrantSHA256:             q.GrantSHA256,
		LauncherProcess:         stage2aMemberLauncherIdentity(grant.Launcher),
		ChildProcess:            stage2aMemberProcessIdentity(grant.Child, r.twoMemberChildren.Members[selected].CommandSHA256),
		ChallengeNonceBase64URL: q.ChallengeNonceBase64URL,
		Sequence:                q.AfterSequence + 1,
		IssuedAt:                now.UTC().Format(time.RFC3339Nano), ExpiresAt: until.UTC().Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aMemberLiveLeasePurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 || !time.Now().Before(until) ||
		r.protectedQ.recheckMemberQ() != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	grant.LiveSequence = payload.Sequence
	grant.LiveExpiresAt = until
	grant.LastNonce = q.ChallengeNonceBase64URL
	r.memberChildGrants[q.MemberID] = grant
	return Stage2aLiveReply{LeaseEnvelopeBase64URL: stage2aEncodeEnvelope(envelope),
		LeaseSHA256: stage2aReservationSHA256(envelope), LeaseSequence: payload.Sequence}, nil
}
