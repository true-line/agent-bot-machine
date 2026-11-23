//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"slices"
	"strings"
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
	cliPath, cliSHA256, ok := stage2aFrozenStockAdapterCLI(p, roles, commandPath, commandSHA256)
	if !ok {
		return false
	}
	digest, err := stage2aOwnerMemberSetDigest(roles, commandPath, commandSHA256, cliPath, cliSHA256)
	return err == nil && digest == plan.SoulProtectedLaunch.OwnerPlanMemberSetSHA256
}

func stage2aOwnerMemberSetDigest(roles []stage2aHelloMember,
	commandPath, commandSHA256, adjacentCLIPath, adjacentCLISHA256 string) (string, error) {
	if len(roles) != 2 || !stage2aAbsolutePath(commandPath) ||
		!stage2aPrefixedDigest.MatchString(commandSHA256) ||
		!stage2aAbsolutePath(adjacentCLIPath) ||
		!stage2aPrefixedDigest.MatchString(adjacentCLISHA256) {
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
		MemberID          string `json:"member_id"`
		Role              string `json:"role"`
		AdapterID         string `json:"adapter_id"`
		AdapterVersion    string `json:"adapter_version"`
		CommandPath       string `json:"command_path"`
		CommandSHA256     string `json:"command_sha256"`
		AdjacentCLIPath   string `json:"adjacent_cli_path"`
		AdjacentCLISHA256 string `json:"adjacent_cli_sha256"`
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
		projection[i].AdjacentCLIPath, projection[i].AdjacentCLISHA256 = adjacentCLIPath, adjacentCLISHA256
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

// The stock declaration is measured definition data, not release attestation.
// It names the adjacent CLI by basename; A joins that name to the measured
// installed ACP path and cross-checks the external file record. The normal
// execution-code recheck separately compares that record with A's sealed R.
func stage2aFrozenStockAdapterCLI(p stage2aInstalledPolicy, roles []stage2aHelloMember,
	commandPath, commandSHA256 string) (string, string, bool) {
	const manifestPath = "Contents/opt/stock-claude.json"
	raw, err := stage2aReadFrozenClaimFile(p.Binding.Snapshots.Definition, p.Definition, manifestPath)
	if err != nil {
		return "", "", false
	}
	return stage2aStockManifestCLI(raw, roles, commandPath, commandSHA256, p.LaunchInputs.Files)
}

func stage2aStockManifestCLI(raw []byte, roles []stage2aHelloMember,
	commandPath, commandSHA256 string, files []Stage2aDefinitionRecord) (string, string, bool) {
	if stage2aStrictJSON(raw) != nil {
		return "", "", false
	}
	var manifest struct {
		AdapterID          string `json:"adapter_id"`
		AdapterVersion     string `json:"adapter_version"`
		SourceRepository   string `json:"source_repository"`
		SourceTag          string `json:"source_tag"`
		SourceCommit       string `json:"source_commit"`
		SourceTree         string `json:"source_tree"`
		ReleaseAsset       string `json:"release_asset"`
		ReleaseAssetSHA256 string `json:"release_asset_sha256"`
		Executable         string `json:"executable"`
		ExecutableSHA256   string `json:"executable_sha256"`
		AdjacentCLI        string `json:"adjacent_cli"`
		AdjacentCLISHA256  string `json:"adjacent_cli_sha256"`
		Model              string `json:"model"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF ||
		len(roles) != 2 || roles[0].AdapterID != manifest.AdapterID ||
		roles[1].AdapterID != manifest.AdapterID ||
		roles[0].AdapterVersion != manifest.AdapterVersion ||
		roles[1].AdapterVersion != manifest.AdapterVersion ||
		filepath.Base(commandPath) != manifest.Executable ||
		manifest.ExecutableSHA256 != commandSHA256 ||
		manifest.AdjacentCLI != "claude" ||
		!stage2aPrefixedDigest.MatchString(manifest.AdjacentCLISHA256) {
		return "", "", false
	}
	cliPath := filepath.Join(filepath.Dir(commandPath), manifest.AdjacentCLI)
	if !stage2aAbsolutePath(cliPath) || cliPath == commandPath {
		return "", "", false
	}
	matched := 0
	for _, file := range files {
		if file.Path == "runtime/bin/claude" {
			if file.Kind != "regular" || file.SHA256 != strings.TrimPrefix(manifest.AdjacentCLISHA256, "sha256:") {
				return "", "", false
			}
			matched++
		}
	}
	if matched != 1 {
		return "", "", false
	}
	return cliPath, manifest.AdjacentCLISHA256, true
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
