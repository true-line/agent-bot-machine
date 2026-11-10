package members

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
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
	if !strings.HasPrefix(string(host.Target), "linux/") {
		return failure(diag.MembersUnsupported, "member accounts are Linux only; this host is %s", host.Target)
	}

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
	again := "run: sudo managed-machine members apply " + planID
	if euid() != 0 {
		return failure(diag.MembersRootRequired, "apply changes accounts and /etc and needs root; %s", again)
	}
	sudoUID := env["SUDO_UID"]
	if sudoUID == "" || sudoUID == "0" {
		return failure(diag.MembersRootRequired, "apply is started with sudo from the owner's account, not from a root login; %s", again)
	}
	lookup := lookupUID
	if deps.LookupUID != nil {
		lookup = deps.LookupUID
	}
	owner, home, err := lookup(sudoUID)
	if err != nil || owner == "" || home == "" {
		return failure(diag.MembersRootRequired, "the account that ran sudo (uid %s) could not be found", sudoUID)
	}
	if agentenv.Account(owner) || agentenv.Account(env["AGENT_BOT_ACCOUNT"]) {
		return failure(diag.MembersCallerRefused, "an agent account cannot apply member accounts")
	}
	ancestors := AncestorEnvs
	if deps.Ancestors != nil {
		ancestors = deps.Ancestors
	}
	for _, e := range append([]map[string]string{env}, ancestors()...) {
		if marker := agentenv.Marker(e); marker != "" {
			return failure(diag.MembersCallerRefused, "an agent session cannot apply member accounts (%s); the owner runs it in their own terminal", marker)
		}
	}

	var h Host = OSHost{}
	if deps.Host != nil {
		h = deps.Host()
	}

	// The plan the owner saved. It is the owner's file and is trusted for
	// nothing: only its request is read, and the plan is built again.
	state, err := statedir.Path("linux", func(k string) string {
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

	// The approval agent-machine recorded.
	if deps.DaemonState == nil {
		return failure(diag.MembersNotApproved, "agent-machine's state directory is not known")
	}
	daemonDir, daemonAccount, err := deps.DaemonState(owner, home)
	if err != nil || daemonDir == "" || daemonAccount == "" {
		return failure(diag.MembersNotApproved, "agent-machine's state directory could not be located")
	}
	approval, why := loadApproval(h, daemonDir, daemonAccount, planID, deps.Time())
	if why != "" {
		return failure(diag.MembersNotApproved, "plan %s is not approved: %s", planID, why)
	}

	// The host as it is now.
	p, err := Build(Input{HQAccount: saved.Plan.HQAccount, Dir: saved.Plan.Dir, Members: saved.Plan.Members, Invoker: owner}, h)
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
	var r Root = OSRoot{}
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
	if !claimed {
		return failure(diag.MembersNotApproved, "plan %s is not approved: its approval was already used (%s)", planID, ReceiptPath(planID))
	}

	finish := func(result, failedAt string) {
		receipt.Result, receipt.FailedAt = result, failedAt
		receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
		_ = r.Finish(planID, encodeReceipt(receipt))
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
	after, err := Build(Input{HQAccount: p.HQAccount, Dir: p.Dir, Members: p.Members, Invoker: owner}, h)
	if err != nil {
		finish("failed", "verification")
		return mapRefusal(err, diag.MembersApplyFailed, "the host is not as planned after the apply")
	}
	if n := after.Changes(); n != 0 {
		finish("failed", "verification")
		return failure(diag.MembersApplyFailed, "the host is not as planned after the apply: %d steps remain", n)
	}
	finish("applied", "")

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
func loadApproval(h Host, daemonDir, account, planID string, now time.Time) (Approval, string) {
	for _, p := range []string{ApprovalsDir(daemonDir), ApprovalPath(daemonDir, planID)} {
		e, ok, err := h.Lstat(p)
		if err != nil || !ok {
			return Approval{}, "there is no approval; approve it in the local web UI first"
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
