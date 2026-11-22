//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

// ChildReady is A's independent observation after the fixed R-UID launcher
// starts the measured stock process. The receipt is one-use and short-lived;
// a PID supplied by HQ cannot be accepted without its granted parent and
// exact kernel start, UID, argv and separate process group.
func (s *Stage2aService) ChildReady(hqUID int, epoch string, q Stage2aChildReadyRequest) (Stage2aChildReadyReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aChildReadyReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.childLauncherPID != q.ChildLauncherPID || r.childPID != 0 ||
		r.childGrantSHA256 != q.GrantSHA256 || !time.Now().Before(r.childGrantExpiresAt) ||
		len(r.finalizationEnvelope) == 0 || r.bindReceiptSHA256 == "" ||
		r.hello == nil || r.hello.aborted || !r.hello.finalized || len(r.hello.finalizationEnvelope) == 0 {
		return reply, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aInstalledPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		stage2aAdapterChildEnv(p.LaunchInputs, &p.BridgeQualification, p.Binding.Snapshots.LaunchInputs.RootPath) != nil {
		return reply, errStage2aReservationAuthority
	}
	childProcess, err := observeStage2aChildProcess(q.ChildPID, q.ChildLauncherPID, p.Runner, p.LaunchInputs)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	name := ".stage2a-child-ready-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if store.checkDirectory(dir) != nil || snapshots.check() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+soulStartClaimName(q.InstallationID, q.StartID)+".json",
			store.uid, store.gid, r.finalizationEnvelope) != nil ||
		requireUnspentStage2aReservation(dir, name) != nil ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil ||
		stage2aCheckRuntimeSnapshot(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files) != nil {
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
	workdir, environment, err := stage2aChildEnvironment(p.Runner,
		r.payload.Assignment.SoulStartAssignment, p.LaunchInputs)
	if err != nil || workdir == "" {
		return reply, errStage2aReservationAuthority
	}
	environmentRaw, err := marshalStage2aReservationJCS(environment)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	adapterID, _ := p.LaunchInputs.EffectiveConfig["adapter_id"].(string)
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	executable, _ := command[0].(string) // validated by stage2aAdapterChildEnv
	now := time.Now()
	approvedUntil, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	expires := minStage2aTime(now.Add(stage2aLiveLease), approvedUntil)
	if err != nil || !expires.After(now) || !time.Now().Before(r.childGrantExpiresAt) ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(q.ChildPID, q.ChildLauncherPID, p.Runner, p.LaunchInputs, childProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	payload := Stage2aChildStartPayload{
		Schema: "agent-bot-machine/stage2a-child-start/v1", Stage2aStopRequest: q.Stage2aStopRequest,
		FinalizationSHA256:      stage2aReservationSHA256(r.finalizationEnvelope),
		HelloFinalizationSHA256: stage2aReservationSHA256(r.hello.finalizationEnvelope),
		BindReceiptSHA256:       r.bindReceiptSHA256, GrantSHA256: q.GrantSHA256,
		Runner: stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		ChildLauncher: stage2aLiveRoleIdentity(r.childLauncherProcess),
		Child:         stage2aLiveRoleIdentity(childProcess),
		Executable:    executable, ExecutableSHA256: p.LaunchInputs.ComponentDigests["adapter"],
		SandboxPath: SoulChildSandbox, SandboxSHA256: "sha256:" + harnessSHA(soulChildProfile),
		RelaySocket:       r.payload.Assignment.Relay.SocketPath,
		EnvironmentSHA256: stage2aReservationSHA256(environmentRaw),
		StartedAtMS:       now.UnixMilli(), ExpiresAtMS: expires.UnixMilli(),
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aChildStartPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) > 8192 || !time.Now().Before(expires) ||
		checkStage2aChildProcess(q.ChildPID, q.ChildLauncherPID, p.Runner, p.LaunchInputs, childProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	if err := commitStage2aReservation(dir, name, envelope); err != nil {
		return reply, err
	}
	r.childPID, r.childProcess, r.childReceiptEnvelope = q.ChildPID, childProcess, envelope
	return Stage2aChildReadyReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope), ExpiresAtMS: expires.UnixMilli()}, nil
}

func observeStage2aChildProcess(pid, parentPID int, runner SoulRunner,
	input Stage2aLaunchInputRecords) (soulKernelProcessSnapshot, error) {
	adapterID, ok := input.EffectiveConfig["adapter_id"].(string)
	if !ok || !stage2aBindingID.MatchString(adapterID) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	adapter, ok := input.HostProjection.Adapters[adapterID].(map[string]any)
	if !ok {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	command, ok := adapter["command"].([]any)
	if !ok || len(command) != 1 {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	executable, ok := command[0].(string)
	if !ok || !stage2aAbsolutePath(executable) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(pid, executable, []string{executable})
	if err != nil || observed.Kernel.ParentPID != parentPID || observed.Kernel.ProcessGroupID != pid ||
		observed.Kernel.RealUID != uint32(runner.UID) || observed.Kernel.EffectiveUID != uint32(runner.UID) ||
		observed.Kernel.SavedUID != uint32(runner.UID) || observed.Kernel.RealGID != uint32(runner.GID) ||
		observed.Kernel.PrimaryGroupGID != uint32(runner.GID) || observed.Kernel.SavedGID != uint32(runner.GID) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	return observed.Kernel, nil
}

func checkStage2aChildProcess(pid, parentPID int, runner SoulRunner,
	input Stage2aLaunchInputRecords, expected soulKernelProcessSnapshot) error {
	observed, err := observeStage2aChildProcess(pid, parentPID, runner, input)
	if err != nil || !sameSoulKernelProcess(expected, observed) {
		return errStage2aReservationAuthority
	}
	return nil
}
