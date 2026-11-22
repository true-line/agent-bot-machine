//go:build darwin

package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

const stage2aRetireSchema = "agent-bot-machine/soul-protected-launch-retire/v1"

func planSoulProtectedRetire(deps Deps, installedID string) cli.Result {
	if !ValidApproval(installedID, fmt.Sprintf("%064d", 0)) {
		return failure(diag.MembersListInvalid, "invalid installed protected Soul plan ID")
	}
	state, err := deps.ResolveStateDir("darwin")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate owner plan store: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(state, "members", "plans", installedID+".json"))
	var prior Saved
	if err != nil || len(raw) > 128<<10 || json.Unmarshal(raw, &prior) != nil ||
		prior.PlanID != installedID || prior.Plan.Purpose != SoulProtectedLaunchInstallPurpose {
		return failure(diag.MembersPlanFailed, "installed protected Soul plan is unavailable")
	}
	canonical, err := prior.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != prior.PlanDigest {
		return failure(diag.MembersPlanFailed, "installed protected Soul review differs from its digest")
	}
	owner, err := deps.ResolveUsername(usernameOS(PlatformDarwin))
	if err != nil {
		return failure(diag.MembersAccountRefused, "cannot identify reviewing owner: %v", err)
	}
	request := &SoulProtectedLaunchRetire{Schema: stage2aRetireSchema, InstalledPlanID: prior.PlanID,
		InstalledPlanDigest: prior.PlanDigest, InstalledPlan: canonical}
	var host Host = OSHost{}
	if deps.Host != nil {
		host = deps.Host()
	}
	plan, err := Build(Input{SoulProtectedRetire: request, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, host)
	if err != nil {
		return mapRefusal(err, diag.MembersPlanFailed, "cannot plan protected Soul retirement")
	}
	digest, err := plan.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest protected Soul retirement: %v", err)
	}
	id, err := deps.PlanID(deps.Time())
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make protected Soul retirement ID: %v", err)
	}
	saved := Saved{SoulProtectedRetire: request, PlanID: id, PlanDigest: digest,
		CreatedAt: deps.Time().UTC().Format(approvalTime), Plan: plan}
	if err := save(filepath.Join(state, "members", "plans"), saved); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save protected Soul retirement: %v", err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", id).Set("plan_digest", digest).
		Set("purpose", SoulProtectedLaunchRetirePurpose).Set("members", plan.Members).
		Set("changes", plan.Changes()).Set("applied", false).
		Set("advice", "Paired HQ must obtain the owner's exact proof before root disables this Soul installation.")}}
}

func buildSoulProtectedRetire(in Input, h Host) (Plan, error) {
	r := in.SoulProtectedRetire
	invalid := errors.New("invalid protected Soul retirement")
	if in.Platform != PlatformDarwin || in.HQAccount != DarwinHQAccount || in.Dir != DarwinDir ||
		len(in.Members) != 0 || in.SoulProtectedLaunch != nil || in.HarnessLaunch != nil ||
		in.HQService != nil || in.UpgradeFrom != nil || r == nil || r.Schema != stage2aRetireSchema ||
		!ValidApproval(r.InstalledPlanID, r.InstalledPlanDigest) || len(r.InstalledPlan) == 0 ||
		len(r.InstalledPlan) > 48<<10 || stage2aStrictJSON(r.InstalledPlan) != nil {
		return Plan{}, invalid
	}
	var installed Plan
	d := json.NewDecoder(bytes.NewReader(r.InstalledPlan))
	d.DisallowUnknownFields()
	if d.Decode(&installed) != nil || installed.Purpose != SoulProtectedLaunchInstallPurpose ||
		installed.SoulProtectedLaunch == nil || installed.SoulProtectedRetire != nil {
		return Plan{}, invalid
	}
	canonical, err := installed.Canonical()
	if err != nil || !bytes.Equal(bytes.TrimSpace(canonical), bytes.TrimSpace(r.InstalledPlan)) ||
		fmt.Sprintf("%x", sha256.Sum256(canonical)) != r.InstalledPlanDigest {
		return Plan{}, invalid
	}
	var policy stage2aInstalledPolicy
	if json.Unmarshal(installed.SoulProtectedLaunch.Policy, &policy) != nil ||
		policy.PlanOwner != in.Invoker || policy.Binding.InstallationID == "" ||
		policy.Runner.Account != soulRunnerName(policy.Binding.InstallationID) ||
		policy.Bridge.Account != SoulBridgeName(policy.Binding.InstallationID) {
		return Plan{}, invalid
	}
	for _, role := range []struct {
		name     string
		uid, gid int
	}{
		{DarwinHQAccount, policy.HQUID, policy.HQUID},
		{policy.MachineAccount, policy.MachineUID, policy.MachineGID},
		{policy.Runner.Account, policy.Runner.UID, policy.Runner.GID},
		{policy.Bridge.Account, policy.Bridge.UID, policy.Bridge.GID},
	} {
		account, ok, err := h.Account(role.name)
		if err != nil || !ok || account.UID != role.uid || account.GID != role.gid {
			return Plan{}, invalid
		}
	}
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir,
		Purpose: SoulProtectedLaunchRetirePurpose,
		Members: []string{policy.Runner.Account, policy.Bridge.Account}, SoulProtectedRetire: r,
		Steps: []Step{{Kind: "soul-protected-launch", Target: policy.Binding.InstallationID,
			Action: ActionRemove, Detail: "disable exact per-Soul authority and sudo rule after both role UIDs are idle; retain claims, snapshots and receipts"}}}
	slices.Sort(p.Members)
	if raw, err := p.Canonical(); err != nil || len(raw) > 56<<10 {
		return Plan{}, invalid
	}
	return p, nil
}

func CheckDarwinSoulProtectedRetire(s Saved, owner string, uid int) error {
	if s.SoulProtectedRetire == nil || s.Plan.Purpose != SoulProtectedLaunchRetirePurpose ||
		!ValidApproval(s.PlanID, s.PlanDigest) || uid < 300 || uid > 399 {
		return errStage2aReservationAuthority
	}
	canonical, err := s.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != s.PlanDigest {
		return errStage2aReservationAuthority
	}
	rebuilt, err := Build(Input{SoulProtectedRetire: s.SoulProtectedRetire,
		HQAccount: DarwinHQAccount, Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, OSHost{})
	if err != nil {
		return err
	}
	actual, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(actual, canonical) || len(s.Plan.Steps) != 1 {
		return errStage2aReservationAuthority
	}
	var installed Plan
	if json.Unmarshal(s.SoulProtectedRetire.InstalledPlan, &installed) != nil {
		return errStage2aReservationAuthority
	}
	var policy stage2aInstalledPolicy
	if json.Unmarshal(installed.SoulProtectedLaunch.Policy, &policy) != nil || policy.HQUID != uid {
		return errStage2aReservationAuthority
	}
	return nil
}
