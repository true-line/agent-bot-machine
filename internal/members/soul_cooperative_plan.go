package members

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

// The paired owner reviews the complete cooperative R/H assignment, including
// its fixed per-Soul launchd trigger and request/completion directory access.
func buildSoulCooperativeLaunch(in Input, h Host) (Plan, error) {
	invalid := errors.New("invalid separate cooperative Soul launch plan")
	if in.Platform != PlatformDarwin || in.HQAccount != DarwinHQAccount || in.Dir != DarwinDir ||
		len(in.Members) != 0 || in.HarnessAccounts || in.SoulRunnerAccounts != nil ||
		in.SoulBridgeAccounts != nil || in.SoulProtectedLaunch != nil || in.SoulProtectedRetire != nil ||
		in.HarnessLaunch != nil || in.HQService != nil || in.UpgradeFrom != nil ||
		in.SoulCooperativeLaunch == nil {
		return Plan{}, invalid
	}
	p := *in.SoulCooperativeLaunch
	if p.validate() != nil || !cooperativePackageRoot(p) ||
		p.SourcePackagePath == p.Runner.PackageRoot || p.Runner.Account == in.Invoker {
		return Plan{}, invalid
	}
	for _, role := range []struct {
		name     string
		uid, gid int
	}{
		{DarwinHQAccount, p.HQUID, p.HQUID},
		{p.Runner.Account, p.Runner.UID, p.Runner.GID},
	} {
		account, ok, err := h.Account(role.name)
		if err != nil || !ok || account.UID != role.uid || account.GID != role.gid {
			return Plan{}, invalid
		}
	}
	plan := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir,
		Members: []string{p.Runner.Account}, Purpose: SoulCooperativeLaunchInstallPurpose,
		SoulCooperativeLaunch: &p,
		Steps: []Step{{Kind: "soul-cooperative-launch", Target: p.Runner.InstallationID,
			Action: ActionWrite, Detail: "seal R runtime and frozen Soul inputs; install fixed per-R launchd WatchPaths job; A:runner-group 2700 staging dir, 2750 request dir, and 2770 completion dir; write A-only signed pending journal before one-use claim; publish applied root receipt"}},
	}
	canonical, err := plan.Canonical()
	if err != nil || len(canonical) > PairedPlanFrameBytes {
		return Plan{}, invalid
	}
	return plan, nil
}

func cooperativeArtifactPath(installationID string) string {
	return path.Join(launchRuntimeDir, "cooperative-artifacts", soulEndpointInstallationSlot(installationID)+".soul")
}

func planSoulCooperativeLaunch(deps Deps, file string) cli.Result {
	raw, err := readQualificationInput(file)
	if err != nil {
		return failure(diag.MembersListInvalid, "cannot read cooperative Soul launch request: %v", err)
	}
	request, err := ParseSoulCooperativeLaunchPolicy(raw)
	if err != nil {
		return failure(diag.MembersListInvalid, "invalid cooperative Soul launch policy: %v", err)
	}
	var h Host = OSHost{}
	if deps.Host != nil {
		h = deps.Host()
	}
	owner, err := deps.ResolveUsername(usernameOS(PlatformDarwin))
	if err != nil {
		return failure(diag.MembersAccountRefused, "cannot identify the planning owner: %v", err)
	}
	plan, err := Build(Input{SoulCooperativeLaunch: &request, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
	if err != nil {
		return mapRefusal(err, diag.MembersPlanFailed, "cannot plan cooperative Soul launch")
	}
	digest, err := plan.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest cooperative Soul launch plan: %v", err)
	}
	now := deps.Time()
	id, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make cooperative Soul launch plan ID: %v", err)
	}
	state, err := deps.ResolveStateDir("darwin")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate owner plan store: %v", err)
	}
	saved := Saved{SoulCooperativeLaunch: &request, PlanID: id, PlanDigest: digest,
		CreatedAt: now.UTC().Format(approvalTime), Plan: plan}
	canonical, err := saved.CanonicalForReview()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot render cooperative Soul launch plan: %v", err)
	}
	if _, err := EncodePairedPlanReview(id, digest, canonical); err != nil {
		return failure(diag.MembersPlanFailed, "cannot serve cooperative Soul launch plan: %v", err)
	}
	if err := save(filepath.Join(state, "members", "plans"), saved); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save cooperative Soul launch plan: %v", err)
	}
	row := output.New().Set("plan_id", id).Set("plan_digest", digest).
		Set("purpose", SoulCooperativeLaunchInstallPurpose).Set("members", plan.Members).
		Set("changes", plan.Changes()).Set("applied", false).
		Set("advice", "Review this separate cooperative plan and its exact host changes before paired apply. A protected launch is not authorized by this plan.")
	return cli.Result{Records: []*output.Record{row}}
}

func CheckDarwinSoulCooperativeLaunch(saved Saved, owner string, uid int) error {
	invalid := errors.New("saved cooperative Soul launch plan is not this paired operation")
	if saved.SoulCooperativeLaunch == nil || saved.Plan.Purpose != SoulCooperativeLaunchInstallPurpose ||
		!ValidApproval(saved.PlanID, saved.PlanDigest) {
		return invalid
	}
	canonical, err := saved.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != saved.PlanDigest {
		return invalid
	}
	var h Host = OSHost{}
	rebuilt, err := Build(Input{SoulCooperativeLaunch: saved.SoulCooperativeLaunch, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
	if err != nil {
		return err
	}
	actual, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(actual, canonical) || len(saved.Plan.Steps) != 1 ||
		saved.Plan.Steps[0].UID != 0 || uid != saved.SoulCooperativeLaunch.HQUID {
		return invalid
	}
	return nil
}
