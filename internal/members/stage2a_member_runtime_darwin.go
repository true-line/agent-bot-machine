//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type stage2aMemberRuntimeLeasePayload struct {
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
	InstalledAuthoritySHA256       string                               `json:"installed_authority_sha256"`
	AssignmentEnvelopeSHA256       string                               `json:"assignment_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string                               `json:"child_observation_envelope_sha256"`
	ReadyEnvelopeSHA256            string                               `json:"ready_envelope_sha256"`
	BAuthorityEnvelopeSHA256       string                               `json:"member_b_authority_envelope_sha256"`
	BindReceiptSHA256              string                               `json:"bind_receipt_sha256"`
	MemberID                       string                               `json:"member_id"`
	MemberSelector                 string                               `json:"member_selector"`
	MemberLaunchID                 string                               `json:"member_launch_id"`
	RuntimeID                      string                               `json:"runtime_id"`
	GrantSHA256                    string                               `json:"grant_sha256"`
	BridgeArmReceiptSHA256         string                               `json:"bridge_arm_receipt_sha256"`
	RunnerProcess                  Stage2aLiveRoleIdentity              `json:"runner_process"`
	BridgeProcess                  Stage2aLiveRoleIdentity              `json:"bridge_process"`
	QProcess                       Stage2aLiveRoleIdentity              `json:"q_process"`
	OwnerDriverProcess             Stage2aLiveRoleIdentity              `json:"owner_driver_process"`
	LauncherProcess                stage2aMemberObservedLauncherProcess `json:"launcher_process"`
	ChildProcess                   stage2aMemberObservedProcess         `json:"child_process"`
	ChallengeNonceBase64URL        string                               `json:"challenge_nonce_base64url"`
	Sequence                       uint64                               `json:"sequence"`
	PreviousLeaseEnvelopeSHA256    *string                              `json:"previous_lease_envelope_sha256"`
	ApprovedUntil                  string                               `json:"approved_until"`
	IssuedAt                       string                               `json:"issued_at"`
	ExpiresAt                      string                               `json:"expires_at"`
}

// MemberRuntime is separate from the short admission lease. It only renews
// one previously Ready member while the retained Q/driver, R, B, and both
// stock children are still the exact kernel processes A admitted. A stop,
// missed renewal, changed process, or expired owner approval cuts it off.
func (s *Stage2aService) MemberRuntime(hqUID int, epoch string,
	q Stage2aMemberRuntimeRequest) (Stage2aLiveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aLiveReply
	if validateStage2aMemberLiveRequest(q.Stage2aMemberLiveRequest) != nil ||
		!stage2aPrefixedDigest.MatchString(q.ReadyEnvelopeSHA256) ||
		q.HQEpoch != epoch || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.hello == nil || r.hello.aborted || r.twoMemberChildren == nil ||
		len(r.memberReadyEnvelope) == 0 || len(r.memberChildObservationEnvelope) == 0 ||
		len(r.memberSetAssignmentEnvelope) == 0 || len(r.memberBAuthorityEnvelope) == 0 ||
		len(r.memberChildGrants) != 2 || r.protectedQ == nil ||
		q.ReadyEnvelopeSHA256 != stage2aReservationSHA256(r.memberReadyEnvelope) ||
		q.ChildObservationEnvelopeSHA256 != stage2aReservationSHA256(r.memberChildObservationEnvelope) {
		return reply, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	p, policyRaw, err := loadStage2aActiveExecutionPolicy(key, hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(policyRaw) != r.policyDigest ||
		p.Binding.ProfileInForce != "managed-protected" || q.PeerUID != p.Runner.UID ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.protectedQ.recheckMemberQ() != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	readyRaw, err := verifyStage2aStoredARecordV3(r.memberReadyEnvelope,
		Stage2aMemberReadyPurpose, 1, key)
	var ready stage2aMemberReadyPayload
	if err != nil || stage2aDecodeExact(readyRaw, &ready) != nil ||
		ready.Contract != "machine/v3" || ready.Kind != "stage2a-member-set-ready" ||
		ready.SchemaVersion != 1 || ready.ProfileInForce != p.Binding.ProfileInForce ||
		ready.HostID != p.Binding.HostID || ready.InstallationID != q.InstallationID ||
		ready.SoulID != p.Binding.SoulID || ready.StartID != q.StartID || ready.HQEpoch != epoch ||
		ready.ReservationSHA256 != r.digest ||
		ready.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) ||
		ready.ChildObservationEnvelopeSHA256 != q.ChildObservationEnvelopeSHA256 ||
		ready.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(r.memberBAuthorityEnvelope) ||
		ready.ProvisionalHQMappingSHA256 != r.provisionalHQMapSHA256 {
		return reply, errStage2aReservationAuthority
	}
	readyExpiry, readyErr := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if readyErr != nil || approvalErr != nil || !readyExpiry.Equal(r.memberReadyExpires) ||
		!time.Now().Before(approvedUntil) ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	selected := -1
	for i, member := range ready.Members {
		if member.MemberID == q.MemberID {
			selected = i
		}
	}
	grant := r.memberChildGrants[q.MemberID]
	if selected < 0 || grant.MemberID != q.MemberID ||
		grant.MemberSelector != q.MemberSelector || grant.MemberLaunchID != q.MemberLaunchID ||
		grant.GrantSHA256 != q.GrantSHA256 || grant.Launcher.PID != q.LauncherPID ||
		grant.Child.PID != q.ChildPID || grant.RuntimeSequence != q.AfterSequence ||
		grant.RuntimeLastNonce == q.ChallengeNonceBase64URL ||
		(q.AfterSequence == 0 && q.PreviousLeaseEnvelopeSHA256 != nil) ||
		(q.AfterSequence != 0 && (q.PreviousLeaseEnvelopeSHA256 == nil ||
			*q.PreviousLeaseEnvelopeSHA256 != grant.RuntimeEnvelopeSHA256)) ||
		ready.Members[selected].MemberSelector != q.MemberSelector ||
		ready.Members[selected].LaunchID != q.MemberLaunchID ||
		!stage2aPrefixedDigest.MatchString(ready.Members[selected].BridgeArmReceiptSHA256) ||
		checkStage2aGrantedRoleProcess(q.PeerPID, p.Runner.UID, p.Runner.GID,
			"child", grant.Launcher) != nil ||
		checkStage2aChildProcess(q.ChildPID, q.LauncherPID, p.Runner,
			p.LaunchInputs, grant.Child) != nil {
		return reply, errStage2aReservationAuthority
	}
	prior, priorErr := time.Parse(time.RFC3339Nano, q.PriorExpiresAt)
	now := time.Now()
	until, windowErr := stage2aPostReadyLeaseWindow(now, readyExpiry, approvedUntil,
		prior, grant.RuntimeExpiresAt, q.AfterSequence, grant.RuntimeSequence)
	if priorErr != nil || windowErr != nil {
		return reply, errStage2aReservationAuthority
	}
	payload := stage2aMemberRuntimeLeasePayload{Contract: "machine/v3",
		Kind: "stage2a-member-runtime-lease", SchemaVersion: 1,
		ProfileInForce: p.Binding.ProfileInForce, HostID: p.Binding.HostID,
		InstallationID: q.InstallationID, SoulID: p.Binding.SoulID,
		StartID: q.StartID, HQEpoch: epoch, ReservationSHA256: r.digest,
		InstalledAuthoritySHA256:       r.policyDigest,
		AssignmentEnvelopeSHA256:       ready.AssignmentEnvelopeSHA256,
		ChildObservationEnvelopeSHA256: ready.ChildObservationEnvelopeSHA256,
		ReadyEnvelopeSHA256:            q.ReadyEnvelopeSHA256,
		BAuthorityEnvelopeSHA256:       ready.MemberBAuthorityEnvelopeSHA256,
		BindReceiptSHA256:              r.bindReceiptSHA256,
		MemberID:                       q.MemberID, MemberSelector: q.MemberSelector,
		MemberLaunchID: q.MemberLaunchID, RuntimeID: ready.Members[selected].RuntimeID,
		GrantSHA256:            q.GrantSHA256,
		BridgeArmReceiptSHA256: ready.Members[selected].BridgeArmReceiptSHA256,
		RunnerProcess:          stage2aLiveRoleIdentity(r.runnerProcess),
		BridgeProcess:          stage2aLiveRoleIdentity(r.bridgeProcess),
		QProcess:               stage2aLiveRoleIdentity(r.protectedQ.session.peer.kernel),
		OwnerDriverProcess:     stage2aLiveRoleIdentity(r.protectedQ.driver.peer.kernel),
		LauncherProcess:        stage2aMemberLauncherIdentity(grant.Launcher),
		ChildProcess: stage2aMemberProcessIdentity(grant.Child,
			r.twoMemberChildren.Members[selected].CommandSHA256),
		ChallengeNonceBase64URL: q.ChallengeNonceBase64URL,
		Sequence:                q.AfterSequence + 1, ApprovedUntil: p.ApprovedUntil,
		PreviousLeaseEnvelopeSHA256: q.PreviousLeaseEnvelopeSHA256,
		IssuedAt:                    now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:                   until.UTC().Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aMemberRuntimeLeasePurpose, key, s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 ||
		!time.Now().Before(until) ||
		(grant.RuntimeSequence == 0 && !time.Now().Before(readyExpiry)) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.protectedQ.recheckMemberQ() != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	grant.RuntimeSequence, grant.RuntimeExpiresAt = payload.Sequence, until
	grant.RuntimeLastNonce = q.ChallengeNonceBase64URL
	grant.RuntimeEnvelopeSHA256 = stage2aReservationSHA256(envelope)
	r.memberChildGrants[q.MemberID] = grant
	return Stage2aLiveReply{LeaseEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		LeaseSHA256: stage2aReservationSHA256(envelope), LeaseSequence: payload.Sequence}, nil
}
