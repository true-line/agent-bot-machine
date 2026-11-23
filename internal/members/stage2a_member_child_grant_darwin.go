//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type stage2aMemberChildGrant struct {
	MemberID              string
	MemberSelector        string
	MemberLaunchID        string
	Launcher              soulKernelProcessSnapshot
	GrantSHA256           string
	ExpiresAt             time.Time
	ChildPID              int
	Child                 soulKernelProcessSnapshot
	Receipt               []byte
	LiveSequence          uint64
	LiveExpiresAt         time.Time
	LastNonce             string
	RuntimeSequence       uint64
	RuntimeExpiresAt      time.Time
	RuntimeLastNonce      string
	RuntimeEnvelopeSHA256 string
}

const stage2aMemberChildGrantLife = 20 * time.Second

// MemberChildGrant grants one inert ACP wrapper selected by the signed A
// assignment. Both wrappers must later be observed before A signs child
// observation; this grant alone cannot finalize H or arm B relay ingress.
func (s *Stage2aService) MemberChildGrant(hqUID int, epoch string,
	q Stage2aMemberChildGrantRequest) (Stage2aExecReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aExecReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize || q.PID <= 1 ||
		!stage2aBindingID.MatchString(q.MemberID) ||
		!stage2aMemberSelectorPattern.MatchString(q.MemberSelector) {
		return reply, errStage2aReservationAuthority
	}
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(q.Nonce)
	if nonceErr != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != q.Nonce {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.memberSetAssignmentEnvelope) == 0 || len(r.provisionalHQMap) == 0 ||
		len(r.memberBAuthorityEnvelope) == 0 ||
		r.provisionalHQMapSHA256 != stage2aReservationSHA256(r.provisionalHQMap) ||
		len(p.MemberBridgeQualifications) != 2 ||
		r.hello == nil || r.hello.aborted || r.hello.finalized ||
		len(r.hello.startEnvelope) == 0 || r.childLauncherPID != 0 || r.childPID != 0 ||
		len(r.memberChildGrants) >= 2 || r.memberChildGrants[q.MemberID].MemberID != "" ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	for _, existing := range r.memberChildGrants {
		if existing.Launcher.PID == q.PID || existing.MemberSelector == q.MemberSelector {
			return reply, errStage2aReservationAuthority
		}
	}
	key := s.key.Public().(ed25519.PublicKey)
	assignmentRaw, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.ReservationSHA256 != r.digest || assignment.InstallationID != r.request.InstallationID ||
		assignment.StartID != r.request.StartID || assignment.HQEpoch != r.request.HQEpoch ||
		assignment.PlanID != q.PlanID || assignment.PlanDigest != q.PlanDigest ||
		assignment.HostID != p.Binding.HostID || assignment.SoulID != p.Binding.SoulID ||
		assignment.RunnerUID != p.Runner.UID || assignment.RunnerGID != p.Runner.GID ||
		assignment.ProfileInForce != "managed-protected" {
		return reply, errStage2aReservationAuthority
	}
	var member stage2aAssignedMember
	for _, candidate := range assignment.Members {
		if candidate.MemberID == q.MemberID {
			member = candidate
		}
	}
	if member.MemberID == "" || member.MemberSelector != q.MemberSelector ||
		member.MemberSelector != stage2aMemberSelector(r.digest, member.MemberID, member.LaunchID) ||
		!soulLaunchID.MatchString(member.LaunchID) {
		return reply, errStage2aReservationAuthority
	}
	var mapping Stage2aProvisionalMemberMap
	if stage2aDecodeExact(r.provisionalHQMap, &mapping) != nil ||
		mapping.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) ||
		mapping.HostID != assignment.HostID || mapping.InstallationID != assignment.InstallationID ||
		mapping.StartID != assignment.StartID || mapping.HQEpoch != assignment.HQEpoch ||
		mapping.SoulID != assignment.SoulID || mapping.ACPAuthority != "withheld" ||
		mapping.RuntimeState != "provisional" || len(mapping.Members) != 2 {
		return reply, errStage2aReservationAuthority
	}
	selected := false
	for _, item := range mapping.Members {
		selected = selected || item.MemberID == q.MemberID && item.MemberSelector == q.MemberSelector
	}
	if !selected {
		return reply, errStage2aReservationAuthority
	}
	mapUntil, mapErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	if mapErr != nil || !time.Now().Before(mapUntil) || !time.Now().Before(r.memberSetAssignmentExpires) {
		return reply, errStage2aReservationExpired
	}
	launcher, err := observeStage2aRoleProcess(q.PID, p.Runner.UID, p.Runner.GID, "child")
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, r.request.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil || snapshots.check() != nil || p.verifyRunnerGroup() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+soulStartClaimName(q.InstallationID, q.StartID)+".json",
			store.uid, store.gid, r.finalizationEnvelope) != nil ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil ||
		stage2aCheckRunnerSnapshot(p.Binding.Snapshots.Definition, p.Definition) != nil ||
		stage2aCheckRuntimeSnapshot(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files) != nil ||
		stage2aRecheckExecutionCode(r, p) != nil ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return reply, errStage2aReservationAuthority
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return reply, errStage2aReservationAuthority
	}
	adapterID, _ := p.LaunchInputs.EffectiveConfig["adapter_id"].(string)
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 {
		return reply, errStage2aReservationAuthority
	}
	executable, _ := command[0].(string)
	if executable == "" || executable != member.CommandPath ||
		p.LaunchInputs.ComponentDigests["adapter"] != member.CommandSHA256 {
		return reply, errStage2aReservationAuthority
	}
	workdir, environment, err := stage2aMemberChildEnvironment(p.Runner,
		r.payload.Assignment.SoulStartAssignment, p.LaunchInputs, member.MemberSelector)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	until := minStage2aTime(now.Add(stage2aMemberChildGrantLife), approvedUntil)
	until = minStage2aTime(until, expires)
	until = minStage2aTime(until, r.memberSetAssignmentExpires)
	until = minStage2aTime(until, mapUntil)
	if approvalErr != nil || !until.After(now) ||
		checkStage2aGrantedRoleProcess(q.PID, p.Runner.UID, p.Runner.GID, "child", launcher) != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil {
		return reply, errStage2aReservationAuthority
	}
	child := &Stage2aChildExec{
		MemberID: member.MemberID, MemberLaunchID: member.LaunchID,
		MemberSelector:                       member.MemberSelector,
		MemberSetAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(r.memberSetAssignmentEnvelope),
		MemberBAuthorityEnvelopeBase64URL:    base64.RawURLEncoding.EncodeToString(r.memberBAuthorityEnvelope),
		ProvisionalHQMapSHA256:               r.provisionalHQMapSHA256,
		ReservationSHA256:                    r.digest,
		FinalizationSHA256:                   stage2aReservationSHA256(r.finalizationEnvelope),
		BindReceiptSHA256:                    r.bindReceiptSHA256,
		Runner:                               stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		Executable: executable, ExecutableSHA256: member.CommandSHA256,
		RuntimeV3: &r.runtimeRefV3, RelaySocket: r.payload.Assignment.Relay.SocketPath,
		SandboxPath: SoulChildSandbox, SandboxSHA256: "sha256:" + harnessSHA(soulChildProfile),
		GrantExpiresAt: until.UTC().Format(time.RFC3339Nano),
		Workdir:        workdir, Environment: environment,
	}
	invocation := Stage2aRoleInvocation{Request: r.request,
		Start:  r.payload.Assignment.SoulStartAssignment,
		Runner: p.Runner, Bridge: p.Bridge, Binding: r.payload.MeasurementBinding,
		Launch: p.LaunchInputs, ChildExec: child}
	invocationRaw, err := marshalStage2aReservationJCS(invocation)
	if err != nil || len(invocationRaw) > stage2aExecMaxFrame {
		return reply, errStage2aReservationAuthority
	}
	grant := Stage2aRoleGrant{ReservationSHA256: r.digest, Role: "child", Nonce: q.Nonce,
		PID: q.PID, LaunchID: invocation.Start.LaunchID, InstallationID: q.InstallationID,
		StartID: q.StartID, HQEpoch: epoch, ExpiresAt: child.GrantExpiresAt,
		InvocationSHA256: stage2aReservationSHA256(invocationRaw),
		MemberID:         member.MemberID, MemberLaunchID: member.LaunchID,
		MemberSelector:                    member.MemberSelector,
		MemberSetAssignmentEnvelopeSHA256: stage2aReservationSHA256(r.memberSetAssignmentEnvelope)}
	name := ".stage2a-exec-member-" + soulStartClaimName(q.InstallationID, q.StartID) + "-" + member.MemberSelector
	if requireUnspentStage2aReservation(dir, name) != nil ||
		spendStage2aAdminName(dir, name, store.uid, store.gid) != nil {
		return reply, errStage2aReservationAuthority
	}
	envelope, err := signStage2aEnvelope(grant, 1, Stage2aRoleExecPurpose, key, s.sign)
	if err != nil || !time.Now().Before(until) ||
		checkStage2aGrantedRoleProcess(q.PID, p.Runner.UID, p.Runner.GID, "child", launcher) != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil {
		return reply, errStage2aReservationAuthority
	}
	reply = Stage2aExecReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:              stage2aReservationSHA256(envelope),
		InvocationBase64URL: base64.RawURLEncoding.EncodeToString(invocationRaw)}
	if len(reply.EnvelopeBase64URL)+len(reply.InvocationBase64URL) > stage2aExecMaxFrame-1024 {
		return Stage2aExecReply{}, errStage2aReservationAuthority
	}
	if r.memberChildGrants == nil {
		r.memberChildGrants = make(map[string]stage2aMemberChildGrant, 2)
	}
	r.memberChildGrants[member.MemberID] = stage2aMemberChildGrant{
		MemberID: member.MemberID, MemberLaunchID: member.LaunchID,
		MemberSelector: member.MemberSelector, Launcher: launcher,
		GrantSHA256: reply.SHA256, ExpiresAt: until}
	return reply, nil
}
