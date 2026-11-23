//go:build darwin

package members

// These observations are nonauthorizing until the owner-reviewed two-member
// plan, per-member launcher grants, B bindings and signed wire are installed.
// In particular, observing two same-UID processes does not prove isolation.
type stage2aMemberChildCandidate struct {
	MemberID        string
	LauncherPID     int
	ChildPID        int
	GrantedLauncher soulKernelProcessSnapshot
}

type stage2aObservedMemberChild struct {
	MemberID      string
	CommandPath   string
	CommandSHA256 string
	Launcher      soulKernelProcessSnapshot
	Child         soulKernelProcessSnapshot
}

type stage2aTwoMemberObservation struct {
	Members [2]stage2aObservedMemberChild
}

type stage2aObserveLauncher func(int) (soulKernelProcessSnapshot, error)
type stage2aObserveChild func(int, int) (soulKernelProcessSnapshot, error)

// This is an A-side observation seam for a future reviewed two-member start.
// It deliberately has no daemon verb, signature or launch authority yet.
func (r *stage2aLiveReservation) observeTwoMemberChildren(p stage2aInstalledPolicy,
	candidates []stage2aMemberChildCandidate) error {
	if r == nil || r.hello == nil || r.hello.aborted || r.hello.finalized ||
		r.twoMemberChildren != nil || r.childPID != 0 || r.childLauncherPID != 0 ||
		r.bindReceiptSHA256 == "" || len(r.finalizationEnvelope) == 0 ||
		p.Binding.ProfileInForce != "managed-protected" ||
		p.Binding.InstallationID != r.request.InstallationID ||
		p.Binding.SoulID != r.payload.Assignment.SoulID ||
		!stage2aHelloMatchesFrozenMembers(p, r.hello.roles) ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID,
			"runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID,
			"bridge", r.bridgeProcess) != nil ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return errStage2aReservationAuthority
	}
	adapterID, _ := p.LaunchInputs.EffectiveConfig["adapter_id"].(string)
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 {
		return errStage2aReservationAuthority
	}
	commandPath, _ := command[0].(string)
	observed, err := collectStage2aTwoMemberChildren(r.hello.roles, candidates,
		r.runnerProcess, r.bridgeProcess, p.Runner.UID, p.Runner.GID,
		commandPath, p.LaunchInputs.ComponentDigests["adapter"],
		func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		},
		func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		})
	if err != nil ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID,
			"runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID,
			"bridge", r.bridgeProcess) != nil ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return errStage2aReservationAuthority
	}
	r.twoMemberChildren = &observed
	return nil
}

// collectStage2aTwoMemberChildren samples both granted launcher/child pairs
// and then samples them again. The second pass refuses PID reuse, process
// replacement or credential drift while the other member was observed.
func collectStage2aTwoMemberChildren(roles []stage2aHelloMember,
	candidates []stage2aMemberChildCandidate, runner, bridge soulKernelProcessSnapshot,
	runnerUID, runnerGID int, commandPath, commandSHA256 string, launcher stage2aObserveLauncher,
	child stage2aObserveChild) (stage2aTwoMemberObservation, error) {
	var result stage2aTwoMemberObservation
	if len(roles) != 2 || len(candidates) != 2 || launcher == nil || child == nil ||
		runner.PID <= 1 || bridge.PID <= 1 || runner.PID == bridge.PID ||
		runnerUID <= 0 || runnerGID <= 0 || !stage2aAbsolutePath(commandPath) ||
		!stage2aPrefixedDigest.MatchString(commandSHA256) {
		return result, errStage2aReservationAuthority
	}
	seen := map[int]bool{runner.PID: true, bridge.PID: true}
	for i, candidate := range candidates {
		if roles[i].MemberID == "" || roles[i].MemberID != candidate.MemberID ||
			(i > 0 && roles[i-1].MemberID >= roles[i].MemberID) ||
			candidate.LauncherPID <= 1 || candidate.ChildPID <= 1 ||
			seen[candidate.LauncherPID] || seen[candidate.ChildPID] ||
			candidate.LauncherPID == candidate.ChildPID ||
			candidate.GrantedLauncher.PID != candidate.LauncherPID {
			return stage2aTwoMemberObservation{}, errStage2aReservationAuthority
		}
		seen[candidate.LauncherPID], seen[candidate.ChildPID] = true, true
		l, err := launcher(candidate.LauncherPID)
		if err != nil || !sameSoulKernelProcess(candidate.GrantedLauncher, l) ||
			!stage2aMemberRunnerIdentity(l, runnerUID, runnerGID) {
			return stage2aTwoMemberObservation{}, errStage2aReservationAuthority
		}
		c, err := child(candidate.ChildPID, candidate.LauncherPID)
		if err != nil || c.PID != candidate.ChildPID || c.ParentPID != l.PID ||
			c.ProcessGroupID != c.PID || !stage2aMemberRunnerIdentity(c, runnerUID, runnerGID) {
			return stage2aTwoMemberObservation{}, errStage2aReservationAuthority
		}
		result.Members[i] = stage2aObservedMemberChild{MemberID: candidate.MemberID,
			CommandPath: commandPath, CommandSHA256: commandSHA256, Launcher: l, Child: c}
	}
	if result.recheck(launcher, child) != nil {
		return stage2aTwoMemberObservation{}, errStage2aReservationAuthority
	}
	return result, nil
}

func stage2aMemberRunnerIdentity(p soulKernelProcessSnapshot, uid, gid int) bool {
	return p.PID > 1 && p.StartSeconds > 0 && p.StartMicros >= 0 && p.StartMicros < 1_000_000 &&
		p.RealUID == uint32(uid) && p.EffectiveUID == uint32(uid) && p.SavedUID == uint32(uid) &&
		p.RealGID == uint32(gid) && p.PrimaryGroupGID == uint32(gid) && p.SavedGID == uint32(gid)
}

func (o stage2aTwoMemberObservation) recheck(launcher stage2aObserveLauncher,
	child stage2aObserveChild) error {
	if launcher == nil || child == nil || o.Members[0].MemberID == "" ||
		o.Members[1].MemberID == "" || o.Members[0].MemberID >= o.Members[1].MemberID {
		return errStage2aReservationAuthority
	}
	for _, member := range o.Members {
		l, err := launcher(member.Launcher.PID)
		if err != nil || !sameSoulKernelProcess(member.Launcher, l) {
			return errStage2aReservationAuthority
		}
		c, err := child(member.Child.PID, member.Launcher.PID)
		if err != nil || !sameSoulKernelProcess(member.Child, c) {
			return errStage2aReservationAuthority
		}
	}
	return nil
}
