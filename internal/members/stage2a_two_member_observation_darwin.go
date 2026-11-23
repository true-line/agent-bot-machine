//go:build darwin

package members

import (
	"encoding/json"
	"slices"
)

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
	if len(r.hello.roles) != 2 || r.hello.roles[0].AdapterID != adapterID ||
		r.hello.roles[1].AdapterID != adapterID ||
		r.hello.roles[0].AdapterVersion != r.hello.roles[1].AdapterVersion {
		return errStage2aReservationAuthority
	}
	adapter, _ := p.LaunchInputs.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 {
		return errStage2aReservationAuthority
	}
	commandPath, _ := command[0].(string)
	if !stage2aOwnerReviewedTwoMemberSet(p, r.hello.roles, commandPath,
		p.LaunchInputs.ComponentDigests["adapter"]) {
		return errStage2aReservationAuthority
	}
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

// A derives the stable member projection from measured SoulInfo and the
// installed adapter command. Only the exact digest in the owner-approved plan
// selects this cohort; an R or H claim cannot select it at launch time.
func stage2aOwnerReviewedTwoMemberSet(p stage2aInstalledPolicy,
	roles []stage2aHelloMember, commandPath, commandSHA256 string) bool {
	if len(roles) != 2 || !stage2aHelloMatchesFrozenMembers(p, roles) ||
		stage2aStrictJSON(p.Plan) != nil {
		return false
	}
	var plan Plan
	if json.Unmarshal(p.Plan, &plan) != nil || plan.SoulProtectedLaunch == nil ||
		plan.Purpose != SoulProtectedLaunchInstallPurpose ||
		plan.SoulProtectedLaunch.OwnerPlanMemberSetSHA256 == "" {
		return false
	}
	digest, err := stage2aOwnerMemberSetDigest(roles, commandPath, commandSHA256)
	return err == nil && digest == plan.SoulProtectedLaunch.OwnerPlanMemberSetSHA256
}

func stage2aOwnerMemberSetDigest(roles []stage2aHelloMember,
	commandPath, commandSHA256 string) (string, error) {
	if len(roles) != 2 || !stage2aAbsolutePath(commandPath) ||
		!stage2aPrefixedDigest.MatchString(commandSHA256) {
		return "", errStage2aReservationAuthority
	}
	ordered := slices.Clone(roles)
	slices.SortFunc(ordered, func(a, b stage2aHelloMember) int {
		if a.MemberID < b.MemberID {
			return -1
		}
		if a.MemberID > b.MemberID {
			return 1
		}
		return 0
	})
	projection := make([]struct {
		MemberID       string `json:"member_id"`
		Role           string `json:"role"`
		AdapterID      string `json:"adapter_id"`
		AdapterVersion string `json:"adapter_version"`
		CommandPath    string `json:"command_path"`
		CommandSHA256  string `json:"command_sha256"`
	}, 2)
	leads := 0
	for i, role := range ordered {
		if !stage2aBindingID.MatchString(role.MemberID) ||
			(i > 0 && ordered[i-1].MemberID == role.MemberID) ||
			!stage2aHelloRole.MatchString(role.Role) ||
			!stage2aBindingID.MatchString(role.AdapterID) ||
			!stage2aHelloAdapterVersion.MatchString(role.AdapterVersion) {
			return "", errStage2aReservationAuthority
		}
		if role.Role == "lead" {
			leads++
		}
		projection[i].MemberID, projection[i].Role = role.MemberID, role.Role
		projection[i].AdapterID, projection[i].AdapterVersion = role.AdapterID, role.AdapterVersion
		projection[i].CommandPath, projection[i].CommandSHA256 = commandPath, commandSHA256
	}
	if leads != 1 {
		return "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(projection)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	return stage2aReservationSHA256(canonical), nil
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
