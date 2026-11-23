//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"time"
)

const stage2aChildGrantLife = 5 * time.Second

// execChild grants one separate, fixed R-UID wrapper after the original R/B
// start has finalized. The 30-second start lease is deliberately not reused:
// the child has its own five-second, one-use grant and the active reservation
// remains occupied until Stop proves both role UIDs idle.
func (s *Stage2aService) execChild(hqUID int, epoch, digest, nonce string, pid int) (Stage2aExecReply, error) {
	var reply Stage2aExecReply
	r := s.active[digest]
	if r == nil || r.digest != stage2aReservationSHA256(r.envelope) ||
		r.request.HQEpoch != epoch || r.payload.Assignment.HQUID != hqUID ||
		len(r.finalizationEnvelope) == 0 || r.bindReceiptSHA256 == "" ||
		r.hello == nil || r.hello.aborted || !r.hello.finalized || len(r.hello.finalizationEnvelope) == 0 ||
		r.runnerPID <= 1 || r.bridgePID <= 1 || r.childLauncherPID != 0 || r.liveSequence == 0 {
		return reply, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest ||
		p.Binding.InstallationID != r.request.InstallationID ||
		p.Binding.LaunchInputMeasurement != r.payload.MeasurementBinding.LaunchInputMeasurement ||
		p.Binding.DefinitionMeasurement != r.payload.MeasurementBinding.DefinitionMeasurement ||
		p.verifyRunnerGroup() != nil ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	childProcess, err := observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
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
	finalName := ".stage2a-b-final-" + soulStartClaimName(r.request.InstallationID, r.request.StartID) + ".json"
	if store.checkDirectory(dir) != nil || snapshots.check() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(r.request.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(r.request.InstallationID, r.request.StartID), store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, finalName, store.uid, store.gid, r.finalizationEnvelope) != nil ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil ||
		stage2aCheckRunnerSnapshot(p.Binding.Snapshots.Definition, p.Definition) != nil ||
		stage2aCheckRuntimeSnapshot(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files) != nil ||
		(r.runModeV3 == "" && stage2aRecheckExecutionCode(r, p) != nil) {
		return reply, errStage2aReservationAuthority
	}
	if trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
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
	executable, _ := command[0].(string) // validated above, including frozen digest
	endpoints, err := DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, r.request.StartID)
	if err != nil || r.payload.Assignment.Relay.SocketPath != endpoints.Relay.SocketPath ||
		filepath.Dir(executable) == "" {
		return reply, errStage2aReservationAuthority
	}
	workdir, environment, err := stage2aChildEnvironment(p.Runner,
		r.payload.Assignment.SoulStartAssignment, p.LaunchInputs)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	approvedUntil, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	expires := minStage2aTime(now.Add(stage2aChildGrantLife), approvedUntil)
	if err != nil || !expires.After(now) || expires.Sub(now) > stage2aChildGrantLife ||
		(r.runModeV3 != "" && stage2aRecheckExecutionCode(r, p) != nil) ||
		checkStage2aGrantedRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child", childProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	child := &Stage2aChildExec{
		ReservationSHA256: digest, FinalizationSHA256: stage2aReservationSHA256(r.finalizationEnvelope),
		HelloFinalizationSHA256: stage2aReservationSHA256(r.hello.finalizationEnvelope),
		BindReceiptSHA256:       r.bindReceiptSHA256,
		Runner:                  stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		Executable: executable, ExecutableSHA256: p.LaunchInputs.ComponentDigests["adapter"],
		RelaySocket: endpoints.Relay.SocketPath, SandboxPath: SoulChildSandbox,
		SandboxSHA256:  "sha256:" + harnessSHA(soulChildProfile),
		GrantExpiresAt: expires.UTC().Format(time.RFC3339Nano),
		Workdir:        workdir, Environment: environment,
	}
	if r.runModeV3 != "" {
		child.RuntimeV3 = &r.runtimeRefV3
	}
	invocation := Stage2aRoleInvocation{
		Request: r.request, Start: r.payload.Assignment.SoulStartAssignment,
		Runner: p.Runner, Bridge: p.Bridge, Binding: r.payload.MeasurementBinding,
		Launch: p.LaunchInputs, ChildExec: child,
	}
	invocationRaw, err := marshalStage2aReservationJCS(invocation)
	if err != nil || len(invocationRaw) > stage2aExecMaxFrame {
		return reply, errStage2aReservationAuthority
	}
	grant := Stage2aRoleGrant{
		ReservationSHA256: digest, Role: "child", Nonce: nonce, PID: pid,
		LaunchID: invocation.Start.LaunchID, InstallationID: r.request.InstallationID,
		StartID: r.request.StartID, HQEpoch: epoch, ExpiresAt: child.GrantExpiresAt,
		InvocationSHA256: stage2aReservationSHA256(invocationRaw),
	}
	name := ".stage2a-exec-child-" + soulStartClaimName(r.request.InstallationID, r.request.StartID)
	if requireUnspentStage2aReservation(dir, name) != nil {
		return reply, errStage2aReservationAuthority
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return reply, err
	}
	envelope, err := signStage2aEnvelope(grant, 1, Stage2aRoleExecPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || !time.Now().Before(expires) {
		return reply, errStage2aReservationAuthority
	}
	reply = Stage2aExecReply{
		EnvelopeBase64URL:   base64.RawURLEncoding.EncodeToString(envelope),
		SHA256:              stage2aReservationSHA256(envelope),
		InvocationBase64URL: base64.RawURLEncoding.EncodeToString(invocationRaw),
	}
	if len(reply.EnvelopeBase64URL)+len(reply.InvocationBase64URL) > stage2aExecMaxFrame-1024 ||
		checkStage2aGrantedRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child", childProcess) != nil {
		return Stage2aExecReply{}, errStage2aReservationAuthority
	}
	r.childLauncherPID, r.childLauncherProcess, r.childGrantSHA256 = pid, childProcess, reply.SHA256
	r.childGrantExpiresAt = expires
	return reply, nil
}
