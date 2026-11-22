package members

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/agentenv"
	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
	"github.com/qwts/managed-machine/internal/plan"
	"github.com/qwts/managed-machine/internal/statedir"
)

// ApplyDeps is what apply reads the world through beyond Deps.
type ApplyDeps struct {
	CheckUpgradePair func(dir, account, commitment string, run func() error) error
	// Euid is the effective uid. When nil, os.Geteuid.
	Euid func() int
	// ProcessEnv is this process's environment. When nil, os.Environ.
	ProcessEnv func() []string
	// Ancestors is the environment of each process above this one. When
	// nil, AncestorEnvs.
	Ancestors func() []map[string]string
	// LookupUID names the account and home of a uid. When nil, os/user.
	LookupUID func(uid string) (name, home string, err error)
	// DaemonState returns agent-machine's state directory and the account
	// that owns it, for an owner and the owner's home. It is required.
	DaemonState func(owner, home string) (dir, account string, err error)
	// Root changes the host. When nil, OSRoot.
	Root func() Root
}

func envMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, item := range environ {
		if k, v, ok := strings.Cut(item, "="); ok {
			env[k] = v
		}
	}
	return env
}

func lookupUID(uid string) (string, string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", "", err
	}
	return u.Username, u.HomeDir, nil
}

// mapRefusal turns a Build or Precheck error into a result.
func mapRefusal(err error, fallback, what string) cli.Result {
	var r *Refusal
	if !errors.As(err, &r) {
		return failure(fallback, "%s: %v", what, err)
	}
	id := map[string]string{RefusedList: diag.MembersListInvalid, RefusedAccount: diag.MembersAccountRefused, RefusedPath: diag.MembersPathRefused}[r.Code]
	return failure(id, "%s", r.Message)
}

// runApply is `members apply <plan-id>`. Every refusal comes before the
// first change, and the order of the checks is the order of the spec: the
// caller, then the plan, then the approval, then the host.
func runApply(deps Deps, ctx cli.Context, args []string) cli.Result {
	if len(args) != 1 || !plan.ValidID(args[0]) {
		return cli.Result{Diagnostic: command.UsageErr("members apply takes one saved plan id and nothing else")}
	}
	planID := args[0]
	host, dg := command.DetectHost(ctx)
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	platform, ok := platformOf(string(host.Target))
	if !ok {
		return failure(diag.MembersUnsupported, "account provisioning supports Linux and macOS; this host is %s", host.Target)
	}

	owner, home, dg := membersSudoOwner(deps, "apply "+planID)
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}

	var h Host = OSHost{}
	if deps.Host != nil {
		h = deps.Host()
	}

	// The plan the owner saved. It is the owner's file and is trusted for
	// nothing: only its request is read, and the plan is built again.
	state, err := statedir.Path(usernameOS(platform), func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate %s's state directory: %v", owner, err)
	}
	raw, ok, err := h.ReadFile(filepath.Join(state, "members", "plans", planID+".json"))
	if err != nil || !ok {
		return failure(diag.MembersPlanFailed, "%s has no saved plan %s; run members plan first", owner, planID)
	}
	var saved Saved
	if err := json.Unmarshal([]byte(raw), &saved); err != nil || saved.PlanID != planID {
		return failure(diag.MembersPlanFailed, "the saved plan %s cannot be read", planID)
	}
	if saved.QualificationRun != nil || saved.Plan.Purpose == HarnessQualificationPurpose {
		return failure(diag.MembersNotApproved, "qualification review plans are non-applicable and cannot install or launch a harness")
	}

	if saved.isHarnessLaunchPlan() {
		if platform != PlatformDarwin || saved.HarnessLaunch == nil || saved.HQService != nil || saved.UpgradeFrom != nil {
			return failure(diag.MembersNotApproved, "a harness rule requires its own exact Darwin plan")
		}
		canonical, err := saved.CanonicalForReview()
		if err != nil || !ValidApproval(saved.PlanID, saved.PlanDigest) || fmt.Sprintf("%x", sha256.Sum256(canonical)) != saved.PlanDigest {
			return failure(diag.MembersNotApproved, "invalid saved harness launch policy")
		}
	}

	// The approval agent-machine recorded.
	if deps.DaemonState == nil {
		return failure(diag.MembersNotApproved, "agent-machine's state directory is not known")
	}
	daemonDir, daemonAccount, err := deps.DaemonState(owner, home)
	if err != nil || daemonDir == "" || daemonAccount == "" {
		return failure(diag.MembersNotApproved, "agent-machine's state directory could not be located")
	}
	pairCheck := func(a Approval, run func() error) error {
		if deps.CheckUpgradePair == nil {
			return errors.New("cannot verify the original protected HQ pairing")
		}
		return deps.CheckUpgradePair(daemonDir, daemonAccount, a.PairCommitment, run)
	}
	realUpgrade := saved.UpgradeFrom != nil && platform == PlatformDarwin && deps.Root == nil
	if realUpgrade {
		handled, e := resumeServiceUpgrade(saved, owner, pairCheck)
		if handled {
			if e != nil {
				return failure(diag.MembersApplyFailed, "reconciling earlier approved HQ transition: %v", e)
			}
			return cli.Result{Records: []*output.Record{output.New().Set("plan_id", planID).Set("plan_digest", saved.PlanDigest).Set("applied", true).Set("receipt", ReceiptPath(planID))}}
		}
	}

	if r := saved.HarnessLaunch; r != nil && r.Action == "install" && deps.Root == nil {
		complete, err := completedHarnessInstall(saved, owner, daemonAccount, pairCheck)
		if err != nil {
			return failure(diag.MembersApplyFailed, "checking prior harness installation: %v", err)
		}
		if complete {
			return cli.Result{Records: []*output.Record{output.New().Set("plan_id", planID).Set("plan_digest", saved.PlanDigest).Set("result", "already-applied").Set("receipt", ReceiptPath(planID))}}
		}
	}
	if r := saved.HarnessLaunch; r != nil && r.Action == "retire" && deps.Root == nil {
		result, err := finishAbsentHarnessRetirement(saved, owner, daemonAccount, pairCheck)
		if err != nil {
			return failure(diag.MembersApplyFailed, "reconciling harness retirement: %v", err)
		}
		if result != "" {
			row := output.New().Set("plan_id", planID).Set("plan_digest", saved.PlanDigest).Set("receipt", ReceiptPath(planID))
			if result == "applied" {
				row.Set("applied", true)
			} else {
				row.Set("result", result)
			}
			return cli.Result{Records: []*output.Record{row}}
		}
	}
	approval, why := loadApproval(h, daemonDir, daemonAccount, planID, platform, deps.Time())
	if why != "" {
		return failure(diag.MembersNotApproved, "plan %s is not approved: %s", planID, why)
	}

	if saved.Plan.Purpose == SoulRunnerAccountsPurpose || approval.Purpose == SoulRunnerAccountsPurpose {
		if platform != PlatformDarwin {
			return failure(diag.MembersNotApproved, "Soul runner accounts require macOS")
		}
		return runSoulRunnerAccountApply(saved, approval, owner, h, deps, pairCheck)
	}
	if saved.Plan.Purpose != "" || approval.Purpose == HarnessAccountsPurpose {
		return runHarnessAccountApply(saved, approval, platform, owner, h, deps, pairCheck)
	}
	if r := saved.HarnessLaunch; r != nil {
		if approval.Purpose != HarnessPurpose(r.Action) || !digestPattern.MatchString(approval.PairCommitment) || !digestPattern.MatchString(approval.MachineFingerprint) || approval.PlanDigest != saved.PlanDigest {
			return failure(diag.MembersNotApproved, "harness rule requires its own paired owner approval")
		}
		if err := applyHarnessGrant(saved, approval, owner, daemonAccount, pairCheck); err != nil {
			return failure(diag.MembersApplyFailed, "could not apply the reviewed harness rule: %v", err)
		}
		return cli.Result{Records: []*output.Record{output.New().Set("plan_id", planID).Set("plan_digest", saved.PlanDigest).Set("applied", true).Set("receipt", ReceiptPath(planID))}}
	}
	if saved.UpgradeFrom == nil && (approval.Purpose != "" || approval.MachineFingerprint != "" || approval.PairCommitment != "") {
		return failure(diag.MembersNotApproved, "a paired purpose-specific approval cannot authorize this operation")
	}
	if saved.UpgradeFrom != nil && (approval.Purpose != UpgradePurpose || !digestPattern.MatchString(approval.MachineFingerprint)) {
		return failure(diag.MembersNotApproved, "upgrade requires the paired HQ service upgrade owner approval")
	}

	// The host as it is now.
	p, err := Build(Input{UpgradeFrom: saved.UpgradeFrom, HQService: saved.HQService, HQAccount: saved.Plan.HQAccount, Dir: saved.Plan.Dir, Members: saved.Plan.Members, Invoker: owner, Platform: platform}, h)
	if err != nil {
		return mapRefusal(err, diag.MembersPlanFailed, "cannot read the host")
	}
	digest, err := p.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest the plan: %v", err)
	}
	if digest != approval.PlanDigest {
		return failure(diag.MembersNotApproved, "plan %s is not approved: the host or the request changed after the approval; plan and approve again", planID)
	}
	if prior := saved.UpgradeFrom; prior != nil {
		priorDigest, err := prior.Plan.Digest()
		if err != nil {
			return failure(diag.MembersPlanFailed, "cannot digest the prior HQ plan: %v", err)
		}
		if err := receiptForUpgrade(h, prior.ID, priorDigest, owner, checkDarwinACLs); err != nil {
			return failure(diag.MembersApplyFailed, "cannot verify prior HQ apply receipt: %v", err)
		}
	}
	var r Root = OSRoot{upgradeApproval: approval, checkUpgradePair: pairCheck}
	if deps.Root != nil {
		r = deps.Root()
	}
	if err := Precheck(p, r); err != nil {
		return mapRefusal(err, diag.MembersApplyFailed, "cannot check the host")
	}

	// One apply per approval: the receipt is the record that it was used.
	receipt := Receipt{PlanID: planID, PlanDigest: digest, Owner: owner, HQAccount: p.HQAccount, Dir: p.Dir,
		Members: p.Members, Changes: p.Changes(), StartedAt: deps.Time().UTC().Format(approvalTime), Result: "started"}
	claimed, err := r.Claim(planID, encodeReceipt(receipt))
	if err != nil {
		return failure(diag.MembersApplyFailed, "cannot write the receipt: %v", err)
	}
	if !claimed && realUpgrade {
		// A process may exit between consuming this exact approval and publishing
		// its transaction record. The live-only plan just rebuilt, unexpired fresh
		// approval, and matching started receipt allow that one start to finish.
		prior, e := currentUpgradeReceipt(approval, owner)
		claimed = e == nil && prior.Result == "started"
	}
	if !claimed {
		return failure(diag.MembersNotApproved, "plan %s is not approved: its approval was already used (%s)", planID, ReceiptPath(planID))
	}

	finish := func(result, failedAt string) error {
		receipt.Result, receipt.FailedAt = result, failedAt
		receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
		return r.Finish(planID, encodeReceipt(receipt))
	}
	if realUpgrade {
		// Completion is recorded under the same lock as verification and rollback.
		if err := r.ActivateHQ(p.Steps[1]); err != nil {
			return failure(diag.MembersApplyFailed, "HQ service upgrade: %v", err)
		}
		return cli.Result{Records: []*output.Record{output.New().Set("plan_id", planID).Set("plan_digest", digest).Set("applied", true).Set("receipt", ReceiptPath(planID))}}
	}
	if err := Apply(p, h, r); err != nil {
		at := ""
		var se *StepError
		if errors.As(err, &se) {
			at = se.Step.Kind + " " + se.Step.Target
		}
		finish("failed", at)
		return failure(diag.MembersApplyFailed, "stopped at %v; earlier steps stay applied; plan again to see the host", err)
	}
	after, err := Build(Input{HQService: saved.HQService, HQAccount: p.HQAccount, Dir: p.Dir, Members: p.Members, Invoker: owner, Platform: platform}, h)
	if err != nil {
		finish("failed", "verification")
		return mapRefusal(err, diag.MembersApplyFailed, "the host is not as planned after the apply")
	}
	if n := after.Changes(); n != 0 {
		finish("failed", "verification")
		return failure(diag.MembersApplyFailed, "the host is not as planned after the apply: %d steps remain", n)
	}
	if err := finish("applied", ""); err != nil {
		return failure(diag.MembersApplyFailed, "applied host changes but could not finish the root receipt: %v", err)
	}

	records := []*output.Record{output.New().
		Set("plan_id", planID).
		Set("plan_digest", digest).
		Set("hq_account", p.HQAccount).
		Set("dir", p.Dir).
		Set("members", strings.Join(p.Members, ",")).
		Set("changes", p.Changes()).
		Set("applied", true).
		Set("hq_account_dedicated", p.SharedHQAdvice() == "").
		SetOptional("advice", p.SharedHQAdvice()).
		Set("receipt", ReceiptPath(planID))}
	for _, s := range p.Steps {
		records = append(records, output.New().
			Set("kind", s.Kind).
			Set("target", s.Target).
			Set("action", s.Action))
	}
	return cli.Result{Records: records}
}

func encodeReceipt(r Receipt) []byte {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return []byte("{}\n")
	}
	return append(raw, '\n')
}

// loadApproval reads the approval for planID and says why it does not
// allow an apply, or "" when it does. The file and its directory must
// belong to the daemon's account and be writable by nobody else: an
// approval anyone else could write is not the daemon's word.
func loadApproval(h Host, daemonDir, account, planID, platform string, now time.Time) (Approval, string) {
	for _, p := range []string{ApprovalsDir(daemonDir), ApprovalPath(daemonDir, planID)} {
		e, ok, err := h.Lstat(p)
		if err != nil {
			return Approval{}, "the approval cannot be read"
		}
		if !ok {
			if platform == PlatformDarwin {
				return Approval{}, "there is no approval. If this macOS Machine has an owner pin, use first-hq for the first dedicated HQ role or the paired HQ CLI's hq-service-recovery for its down service. See managed-machine members --help for approval routes"
			}
			return Approval{}, "there is no approval. Approve this plan in the local web UI's Approvals tab first"
		}
		isFile := p != ApprovalsDir(daemonDir)
		if (isFile && !e.Regular) || (!isFile && !e.Dir) {
			return Approval{}, p + " is not what agent-machine writes"
		}
		if e.Owner != account || e.Mode&0o022 != 0 {
			return Approval{}, p + " is not owned by " + account + " alone"
		}
	}
	raw, ok, err := h.ReadFile(ApprovalPath(daemonDir, planID))
	if err != nil || !ok {
		return Approval{}, "the approval cannot be read"
	}
	var a Approval
	if err := json.Unmarshal([]byte(raw), &a); err != nil || a.PlanID != planID || !ValidApproval(a.PlanID, a.PlanDigest) {
		return Approval{}, "the approval cannot be read"
	}
	expires, err := time.Parse(approvalTime, a.ExpiresAt)
	if err != nil {
		return Approval{}, "the approval cannot be read"
	}
	if !now.Before(expires) {
		return Approval{}, "the approval expired at " + a.ExpiresAt + "; approve it again"
	}
	return a, ""
}

func readPriorServicePlan(state, id string) (*priorServicePlan, error) {
	if !plan.ValidID(id) {
		return nil, errors.New("invalid prior members plan id")
	}
	f, err := os.Open(filepath.Join(state, "members", "plans", id+".json"))
	if err != nil {
		return nil, errors.New("cannot open prior saved members plan")
	}
	defer f.Close()
	const limit = 256 << 10
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	var saved Saved
	if err != nil || len(raw) > limit || json.Unmarshal(raw, &saved) != nil || saved.PlanID != id {
		return nil, errors.New("cannot read the prior saved members plan")
	}
	return &priorServicePlan{ID: id, Plan: saved.Plan}, nil
}

func membersSudoOwner(deps Deps, action string) (string, string, *diag.Diagnostic) {
	// The caller: root, through sudo, from a human's own session.
	environ := os.Environ
	if deps.ProcessEnv != nil {
		environ = deps.ProcessEnv
	}
	env := envMap(environ())
	euid := os.Geteuid
	if deps.Euid != nil {
		euid = deps.Euid
	}
	again := "run: sudo managed-machine members " + action
	if euid() != 0 {
		return "", "", failure(diag.MembersRootRequired, "this operation needs root; %s", again).Diagnostic
	}
	sudoUID := env["SUDO_UID"]
	if sudoUID == "" || sudoUID == "0" {
		return "", "", failure(diag.MembersRootRequired, "this operation is started with sudo from the owner's account, not from a root login; %s", again).Diagnostic
	}
	lookup := lookupUID
	if deps.LookupUID != nil {
		lookup = deps.LookupUID
	}
	owner, home, err := lookup(sudoUID)
	if err != nil || owner == "" || home == "" {
		return "", "", failure(diag.MembersRootRequired, "the account that ran sudo (uid %s) could not be found", sudoUID).Diagnostic
	}
	if agentenv.Account(owner) || agentenv.Account(env["AGENT_BOT_ACCOUNT"]) {
		return "", "", failure(diag.MembersCallerRefused, "an agent account cannot change managed service or member resources").Diagnostic
	}
	ancestors := AncestorEnvs
	if deps.Ancestors != nil {
		ancestors = deps.Ancestors
	}
	for _, e := range append([]map[string]string{env}, ancestors()...) {
		if marker := agentenv.Marker(e); marker != "" {
			return "", "", failure(diag.MembersCallerRefused, "an agent session cannot change managed service or member resources (%s); the owner runs it in their own terminal", marker).Diagnostic
		}
	}
	return owner, home, nil
}

// Uninstall is an explicit local administrator decision. It is deliberately
// absent from the daemon protocol and can run when HQ or Machine is stopped.
func runUninstallHQ(deps Deps, ctx cli.Context, args []string) cli.Result {
	list := len(args) == 1 && args[0] == "--list"
	preview := len(args) == 2 && args[1] == "--dry-run"
	if (len(args) != 1 && !preview) || (!list && !plan.ValidID(args[0])) {
		return cli.Result{Diagnostic: command.UsageErr("members uninstall-hq takes the completed HQ service plan ID and optionally --dry-run")}
	}
	host, dg := command.DetectHost(ctx)
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	platform, ok := platformOf(string(host.Target))
	if !ok || platform != PlatformDarwin {
		return failure(diag.MembersUnsupported, "HQ service uninstall requires macOS")
	}
	owner, home, dg := membersSudoOwner(deps, "uninstall-hq "+args[0])
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	state, err := statedir.Path(usernameOS(platform), func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate the original administrator's saved plan")
	}
	if list {
		ids, resume, e := listHQUninstallPlans(owner, state)
		if e != nil {
			return failure(diag.MembersPlanFailed, "checking HQ install receipts: %v", e)
		}
		record := output.New().Set("service", launchLabel).Set("matching_plan_ids", ids)
		if resume != "" {
			record.Set("resume_plan_id", resume)
		}
		return cli.Result{Records: []*output.Record{record}}
	}
	result, err := uninstallDarwinHQ(owner, state, args[0], preview)
	if err != nil {
		return failure(diag.MembersApplyFailed, "HQ service uninstall: %v", err)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", args[0]).Set("result", result).Set("service", launchLabel).Set("retained", []string{"dedicated HQ account and home", "pairing and keys", "externally staged releases and Node", "HQ runtime directory and standalone retirement records", "plans and audit receipts"})}}
}

func validUninstallID(id string) bool { return plan.ValidID(id) }

func lockHQPackage(owner string) (io.Closer, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid <= 0 {
		return nil, errors.New("invalid HQ administrator UID")
	}
	return statedir.LockMacPackage(u.HomeDir, uid)
}
