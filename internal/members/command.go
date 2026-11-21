package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

// Deps is what the command reads the world through; tests inject all of it.
type Deps struct {
	command.Deps
	// Host reads accounts and paths. When nil, the running host is read.
	Host func() Host
	// ReadFile reads the HQ configuration. When nil, os.ReadFile is used.
	ReadFile func(string) ([]byte, error)
	ApplyDeps
}

// Command is `managed-machine members`.
func Command(deps Deps) cli.Command {
	return cli.Command{
		Name:    "members",
		Summary: "Plan and apply HQ and harness accounts on Linux and macOS",
		Usage:   usage,
		Run:     func(ctx cli.Context, args []string) cli.Result { return run(deps, ctx, args) },
	}
}

const usage = `Usage: managed-machine members plan [--hq-account <account>] (--hq-config <path> | --members <a,b,...>) [--dir <path>]
       managed-machine members plan [--hq-service <record.json>]  (macOS dedicated HQ only)
       sudo managed-machine members uninstall-hq --list
       sudo managed-machine members uninstall-hq <applied-plan-id> [--dry-run]
       managed-machine members plan --hq-service <record.json> --upgrade-from <prior-plan-id>
       managed-machine members plan --harness-account-provision (--members <a,b,...> | --hq-config <path>) [--dir <path>]
       managed-machine members plan --harness-launch-install <adapters.json>
       managed-machine members plan --harness-launch-retire <installed-plan-id>
       managed-machine members plan --harness-qualification <request.json>
       sudo managed-machine members apply <plan-id>

Plan the account HQ runs in, one OS account per harness credential, the broker
endpoint directories HQ verifies, the tmpfiles entry that recreates them at
boot, and the sudoers rule that lets HQ start harness processes
(docs/plans/member-accounts.md).

plan reads the host and changes nothing. It saves the plan and prints its
plan_id and plan_digest.

Linux plans all of these steps. macOS plans the HQ account (` + DarwinHQAccount + `, a
hidden role account with home /var/agent-bot-hq) and optional credential
accounts from --members or --hq-config. Each credential account has a
private group and home and cannot log in. Add --hq-service to install the
verified launchd service.

apply needs root and owner approval of the exact plan ID and digest.
On Linux and on macOS channels that accept approve-members, the owner uses
the local web UI's Approvals tab.
A macOS Machine with an owner pin supports these transfers for local owner review:
  First dedicated HQ role: the prefix administrator exports the plan with
  managed-machine daemon first-hq export <plan-id> and submits the owner proof
  with managed-machine daemon first-hq approve <plan-id> --proof-file <path>.
  Down service, healthy paired HQ role: the paired HQ CLI runs
  machine hq-service-recovery export <plan-id> --socket <machine-socket>
  and submits the returned owner proof through the same paired HQ CLI.
  Running Machine-backed HQ, compatible staged update: prepare the replacement
  with --upgrade-from, then use the paired HQ CLI's hq-service-upgrade export
  and approve commands for the new plan ID. An interrupted upgrade resumes
  through members apply with that same ID.
These service transfers require a dedicated HQ-only plan without harness accounts.
For harness accounts, use --harness-account-provision with --members or --hq-config.
The dedicated paired HQ exports the exact reviewed IDs, private homes and optional
broker directories with machine harness-account-provision and returns the owner proof.
After a failed or interrupted apply, plan and approve the remaining steps again.
A Darwin harness launch plan records exact adapter, Machine and sandbox digests
for review. Enrolled dedicated HQ can export and submit the matching owner
proof with machine harness-launch-install or machine harness-launch-retire.
Installation and launch also require a qualified adapter. This build has no
production Darwin adapter qualification verifier.
The prefix administrator then runs apply with sudo in their own terminal within
ten minutes. apply builds the plan again from the host and runs only when
its digest is the approved one. It takes a plan id and nothing else; no
option skips the approval. An agent account or session is refused.

On macOS, uninstall-hq --list shows completed plans matching the installed HQ
plist. After an upgrade, choose the matching completed upgrade plan. Preview
with --dry-run before removing the system job, its exact plist and its verified
endpoint. The dedicated account, home, keys, pairing, release files, runtime
directory and audit receipts remain available. Run this before package removal.

Options
--harness-qualification <file>  Review fixed, pinned, one-use qualification inputs (read-only)
--harness-launch-install <file>  Review a dedicated Darwin adapter mapping and launch rule
--harness-launch-retire <plan-id>  Review retirement of that exact installed rule
-h, --help              Show this usage and read nothing
--hq-account <account>  The account HQ runs in (default ` + DefaultHQAccount + `, or
                        ` + DarwinHQAccount + ` on macOS). It is
                        created as a locked service account when it does not
                        exist. Naming your own account works but is not
                        recommended: the plan says it is not dedicated
--hq-config <path>      Read HQ's harnesses.accounts (adapter ID to account)
                        and optional harnesses.dir. Shared accounts are
                        provisioned once. Legacy members config is refused
--upgrade-from <id>     Replace a running dedicated macOS HQ service from its applied plan
--hq-service <json>     Install the platform HQ service from a verified release record
--members <a,b,...>     Name the harness accounts directly (compatibility flag)
--dir <path>            The endpoint directory, with --members
                        (Linux default ` + DefaultDir + `). On macOS, specify
                        ` + DarwinBrokerDir + ` explicitly
                        to provision broker directories under the existing HQ runtime.
--json                  Return the records as one JSON document
--human                 Render the records in a readable form
`

func failure(id, format string, args ...any) cli.Result {
	d := diag.New(id, fmt.Sprintf(format, args...))
	return cli.Result{Diagnostic: &d}
}

// Saved is the plan file apply reads: the request, so the plan can be built
// again from the host, and the digest the owner is asked to approve.
type Saved struct {
	UpgradeFrom      *priorServicePlan    `json:"upgrade_from,omitempty"`
	HarnessLaunch    *HarnessPolicyRecord `json:"harness_launch,omitempty"`
	QualificationRun *QualificationRun    `json:"qualification_run,omitempty"`
	HQService        *HQService           `json:"hq_service,omitempty"`
	PlanID           string               `json:"plan_id"`
	PlanDigest       string               `json:"plan_digest"`
	CreatedAt        string               `json:"created_at"`
	Plan             Plan                 `json:"plan"`
}

// HQ adapter IDs identify harness credentials (PDR-0053). Several adapters
// may deliberately use the same account; provisioning consumes the unique set.
var adapterID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func configObject(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return object, nil
}

func fromConfig(raw []byte) (dir string, members []string, err error) {
	c, err := configObject(raw, "HQ config")
	if err != nil {
		return "", nil, err
	}
	if _, legacy := c["members"]; legacy {
		return "", nil, errors.New("members config is retired; migrate to harnesses.accounts (adapter ID to account) and harnesses.dir, then remove members")
	}
	harnesses, err := configObject(c["harnesses"], "harnesses")
	if err != nil {
		return "", nil, err
	}
	for key := range harnesses {
		if key != "accounts" && key != "dir" {
			return "", nil, errors.New("harnesses accepts only accounts and dir")
		}
	}
	accounts, err := configObject(harnesses["accounts"], "harnesses.accounts")
	if err != nil {
		return "", nil, err
	}
	if value, present := harnesses["dir"]; present {
		if err := json.Unmarshal(value, &dir); err != nil || !path.IsAbs(dir) || len(dir) > 80 || strings.ContainsAny(dir, "\x00\n") {
			return "", nil, errors.New("harnesses.dir must be an absolute path of at most 80 characters without NUL or newline")
		}
	}
	seen := make(map[string]bool)
	for adapter, value := range accounts {
		if !adapterID.MatchString(adapter) {
			return "", nil, errors.New("harnesses.accounts has an invalid adapter ID")
		}
		var account string
		if err := json.Unmarshal(value, &account); err != nil || !accountName.MatchString(account) {
			return "", nil, errors.New("harnesses.accounts values must be OS account names")
		}
		if !seen[account] {
			members = append(members, account)
			seen[account] = true
		}
	}
	sort.Strings(members)
	return dir, members, nil
}

func run(deps Deps, ctx cli.Context, args []string) cli.Result {
	if len(args) > 0 && args[0] == "uninstall-hq" {
		return runUninstallHQ(deps, ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "apply" {
		return runApply(deps, ctx, args[1:])
	}
	if len(args) == 0 || args[0] != "plan" {
		return cli.Result{Diagnostic: command.UsageErr("members takes one action: plan, apply or uninstall-hq")}
	}
	var hqAccount, hqConfigPath, list, dir, serviceRecord, priorID, qualificationPath string
	var installFile, retireID string
	var launchFlags, qualificationFlags int
	var harnessAccounts bool
	var hasList, hasDir, hasUpgrade, hasQualification, hasHQConfig, hasService bool
	if d := command.Parse(args[1:], command.Spec{
		Bools: map[string]*bool{"--harness-account-provision": &harnessAccounts},
		Values: map[string]command.Flag{
			"--harness-qualification":  {Value: &qualificationPath, Set: &hasQualification, Count: &qualificationFlags},
			"--harness-launch-install": {Value: &installFile, Count: &launchFlags},
			"--harness-launch-retire":  {Value: &retireID, Count: &launchFlags},
			"--upgrade-from":           {Value: &priorID, Set: &hasUpgrade},
			"--hq-service":             {Value: &serviceRecord, Set: &hasService},
			"--hq-account":             {Value: &hqAccount},
			"--hq-config":              {Value: &hqConfigPath, Set: &hasHQConfig},
			"--members":                {Value: &list, Set: &hasList, Optional: true},
			"--dir":                    {Value: &dir, Set: &hasDir},
		},
	}); d != nil {
		return cli.Result{Diagnostic: d}
	}
	host, dg := command.DetectHost(ctx)
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	platform, ok := platformOf(string(host.Target))
	if !ok {
		return failure(diag.MembersUnsupported, "account provisioning supports Linux and macOS; this host is %s", host.Target)
	}
	if hqAccount == "" {
		hqAccount = DefaultHQAccountFor(platform)
	}
	if hasQualification {
		if qualificationPath == "" {
			return failure(diag.MembersListInvalid, "harness qualification request path is empty")
		}
		if qualificationFlags != 1 || platform != PlatformDarwin || hqAccount != DarwinHQAccount || hasHQConfig || hasList || hasDir || hasService || hasUpgrade || launchFlags != 0 || harnessAccounts {
			return failure(diag.MembersListInvalid, "harness qualification planning requires a dedicated Darwin host and no other plan purpose")
		}
		read := deps.ReadFile
		if read == nil {
			read = readQualificationInput
		}
		raw, err := read(qualificationPath)
		if err != nil {
			return failure(diag.MembersListInvalid, "cannot read qualification request: %v", err)
		}
		r, err := decodeQualificationRequest(raw)
		if err != nil {
			return failure(diag.MembersListInvalid, "%v", err)
		}
		var hostReader Host = OSHost{}
		if deps.Host != nil {
			hostReader = deps.Host()
		}
		plan, runRecord, err := qualificationRunPlan(raw, r, hostReader)
		if err != nil {
			return failure(diag.MembersPlanFailed, "%v", err)
		}
		return saveQualificationPlan(deps, plan, runRecord)
	}
	if launchFlags != 0 {
		if launchFlags != 1 || hasUpgrade || (installFile == "" && retireID == "") || platform != PlatformDarwin || hasList || hasDir || hqConfigPath != "" || serviceRecord != "" || hqAccount != DarwinHQAccount {
			return failure(diag.MembersListInvalid, "harness launch requires one dedicated Darwin install or retirement request")
		}
	}
	switch {
	case platform == PlatformDarwin && hasDir && (!hasList || dir != DarwinBrokerDir):
		return failure(diag.MembersUnsupported, "Darwin --dir requires --members and %s", DarwinBrokerDir)
	case platform == PlatformDarwin && hqConfigPath == "" && !hasList:
	case (hqConfigPath != "") == hasList:
		return cli.Result{Diagnostic: command.UsageErr("members plan needs exactly one of --hq-config and --members")}
	case hqConfigPath != "" && hasDir:
		return cli.Result{Diagnostic: command.UsageErr("--dir goes with --members; --hq-config names its own directory")}
	}

	in := Input{HarnessAccounts: harnessAccounts, HQAccount: hqAccount, Dir: dir, Platform: platform}
	if hqConfigPath != "" {
		read := deps.ReadFile
		if read == nil {
			read = os.ReadFile
		}
		raw, err := read(hqConfigPath)
		if err != nil {
			return failure(diag.MembersListInvalid, "cannot read %s: %v", hqConfigPath, err)
		}
		if in.Dir, in.Members, err = fromConfig(raw); err != nil {
			return failure(diag.MembersListInvalid, "%s: %v", hqConfigPath, err)
		}
		// Shared configs may name the Linux broker directory. Keep their
		// original account-only plan on macOS unless the Darwin path is selected.
		if platform == PlatformDarwin && in.Dir != DarwinBrokerDir {
			in.Dir = DarwinDir
		}
	} else {
		for _, m := range strings.Split(list, ",") {
			if m = strings.TrimSpace(m); m != "" {
				in.Members = append(in.Members, m)
			}
		}
	}
	if name, err := deps.ResolveUsername(usernameOS(platform)); err == nil {
		in.Invoker = name
	} else if platform == PlatformDarwin && (len(in.Members) > 0 || installFile != "" || retireID != "") {
		return failure(diag.MembersAccountRefused, "cannot identify the owner planning Darwin harness accounts: %v", err)
	}

	if priorID != "" {
		if platform != PlatformDarwin || serviceRecord == "" || hqAccount != DarwinHQAccount || hqConfigPath != "" || hasList || hasDir {
			return cli.Result{Diagnostic: command.UsageErr("--upgrade-from requires a prior plan id and only a dedicated macOS --hq-service record")}
		}
		state, err := deps.ResolveStateDir(usernameOS(platform))
		if err != nil {
			return failure(diag.MembersPlanFailed, "cannot locate prior plan")
		}
		in.UpgradeFrom, err = readPriorServicePlan(state, priorID)
		if err != nil {
			return failure(diag.MembersPlanFailed, "%s", err)
		}
	}
	if serviceRecord != "" {
		read := deps.ReadFile
		if read == nil {
			read = os.ReadFile
		}
		raw, err := read(serviceRecord)
		if err != nil {
			return failure(diag.MembersListInvalid, "cannot read HQ service record: %v", err)
		}
		in.HQService, err = decodeHQService(raw)
		if err != nil {
			return failure(diag.MembersListInvalid, "%v", err)
		}
	}
	var h Host = OSHost{}
	if deps.Host != nil {
		h = deps.Host()
	}
	if installFile != "" || retireID != "" {
		var err error
		in.HarnessLaunch, err = planHarnessRequest(installFile, retireID, h)
		if err != nil {
			return failure(diag.MembersPlanFailed, "%v", err)
		}
		in.Dir = DarwinBrokerDir
		in.Members, err = in.HarnessLaunch.accounts()
		if err != nil {
			return failure(diag.MembersListInvalid, "%v", err)
		}
	}
	plan, err := Build(in, h)
	if err != nil {
		var r *Refusal
		if !errors.As(err, &r) {
			return failure(diag.MembersPlanFailed, "cannot read the host: %v", err)
		}
		id := map[string]string{RefusedList: diag.MembersListInvalid, RefusedAccount: diag.MembersAccountRefused, RefusedPath: diag.MembersPathRefused}[r.Code]
		return failure(id, "%s", r.Message)
	}
	digest, err := plan.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest the plan: %v", err)
	}
	if in.HarnessLaunch != nil && in.HarnessLaunch.Action == "install" {
		installed, e := matchingInstalledHarness(digest, h)
		if e != nil {
			return failure(diag.MembersPlanFailed, "%v", e)
		}
		if installed != "" {
			return cli.Result{Records: []*output.Record{output.New().Set("installed_plan_id", installed).Set("plan_digest", digest).Set("changes", 0).Set("advice", "The reviewed policy is already recorded. Use the original root receipt to verify installation.")}}
		}
	}
	now := deps.Time()
	planID, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make a plan id: %v", err)
	}
	state, err := deps.ResolveStateDir(usernameOS(platform))
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate the state directory: %v", err)
	}
	saved := Saved{UpgradeFrom: in.UpgradeFrom, HarnessLaunch: in.HarnessLaunch, HQService: in.HQService, PlanID: planID, PlanDigest: digest, CreatedAt: now.UTC().Format("2006-01-02T15:04:05Z"), Plan: plan}
	if err := save(filepath.Join(state, "members", "plans"), saved); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save the plan: %v", err)
	}

	records := []*output.Record{output.New().
		Set("plan_id", planID).
		Set("plan_digest", digest).
		Set("hq_account", plan.HQAccount).
		Set("dir", plan.Dir).
		Set("members", strings.Join(plan.Members, ",")).
		Set("changes", plan.Changes()).
		Set("applied", false).
		Set("hq_account_dedicated", plan.SharedHQAdvice() == "").
		SetOptional("advice", plan.SharedHQAdvice())}
	if in.HarnessAccounts {
		records[0].Set("purpose", HarnessAccountsPurpose)
	}
	if in.HarnessLaunch != nil {
		records[0].Set("advice", "Dedicated paired HQ can request an owner proof for this digest. Production install requires a qualified adapter. Regenerate and approve the plan if the Machine executable changes.")
	}
	for _, s := range plan.Steps {
		if platform == PlatformDarwin && s.Kind == KindHQAccount && s.Target == DarwinHQAccount && s.Action == ActionCreate {
			advice := "For review by the owner, export this saved plan as the prefix administrator with managed-machine daemon first-hq export " + planID
			if len(plan.Members) != 0 {
				advice = "First provision the dedicated HQ role with a members plan without harness accounts, then plan the harness accounts separately."
			}
			records[0].Set("advice", advice)
		}
		records = append(records, output.New().
			Set("kind", s.Kind).
			Set("target", s.Target).
			Set("action", s.Action).
			SetOptional("owner", s.Owner).
			SetOptional("group", s.Group).
			SetOptional("mode", s.Mode).
			SetOptional("detail", s.Detail).
			SetOptional("content", s.Content))
		if s.UID != 0 {
			records[len(records)-1].Set("uid", s.UID).Set("gid", s.GID)
		}
	}
	return cli.Result{Records: records}
}

func readQualificationInput(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 4*1024*1024 {
		return nil, errors.New("qualification request must be a regular file no larger than 4 MiB")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() < 1 || opened.Size() > 4*1024*1024 {
		return nil, errors.New("qualification request changed or is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != opened.Size() {
		return nil, errors.New("qualification request size changed while reading")
	}
	return raw, nil
}

func saveQualificationPlan(deps Deps, plan Plan, runRecord *QualificationRun) cli.Result {
	digest, err := plan.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest the plan: %v", err)
	}
	now := deps.Time()
	planID, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make a plan id: %v", err)
	}
	state, err := deps.ResolveStateDir("darwin")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate the state directory: %v", err)
	}
	saved := Saved{QualificationRun: runRecord, PlanID: planID, PlanDigest: digest, CreatedAt: now.UTC().Format("2006-01-02T15:04:05Z"), Plan: plan}
	if err := save(filepath.Join(state, "members", "plans"), saved); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save the plan: %v", err)
	}
	canonical, _ := plan.Canonical()
	row := output.New().Set("plan_id", planID).Set("plan_digest", digest).Set("purpose", HarnessQualificationPurpose).
		Set("host", runRecord.Request.Host.ID).Set("adapter", runRecord.Request.Adapter.ID).Set("changes", 0).Set("applied", false).
		Set("request_sha256", runRecord.RequestSHA256).Set("plan", string(canonical))
	records := []*output.Record{row}
	for _, s := range plan.Steps {
		records = append(records, output.New().Set("kind", s.Kind).Set("target", s.Target).Set("action", s.Action).Set("detail", s.Detail).Set("content", s.Content))
	}
	return cli.Result{Records: records}
}

// platformOf maps a host target to Input.Platform. Linux plans everything;
// macOS plans the requested role accounts, broker directories and optional HQ service.
func platformOf(target string) (string, bool) {
	switch {
	case strings.HasPrefix(target, "linux/"):
		return "", true
	case strings.HasPrefix(target, "darwin/"):
		return PlatformDarwin, true
	}
	return "", false
}

func usernameOS(platform string) string {
	if platform == PlatformDarwin {
		return "darwin"
	}
	return "linux"
}

// save writes the plan file, private to the account that made it.
func save(dir string, s Saved) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".plan-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, s.PlanID+".json"))
}
