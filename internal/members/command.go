package members

import (
	"encoding/json"
	"errors"
	"fmt"
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
		Summary: "Plan and apply the Linux harness accounts, endpoint directories and launch rule",
		Usage:   usage,
		Run:     func(ctx cli.Context, args []string) cli.Result { return run(deps, ctx, args) },
	}
}

const usage = `Usage: managed-machine members plan [--hq-account <account>] (--hq-config <path> | --members <a,b,...>) [--dir <path>]
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

apply needs root and an approval. The owner approves the plan's digest in
the local web UI or, for first HQ on macOS, the owner approval app.
The prefix administrator then runs apply with sudo in their own terminal within
ten minutes. apply builds the plan again from the host and runs only when
its digest is the approved one. It takes a plan id and nothing else; no
option skips the approval. An agent account or session is refused.

Options
-h, --help              Show this usage and read nothing
--hq-account <account>  The account HQ runs in (default ` + DefaultHQAccount + `, or
                        ` + DarwinHQAccount + ` on macOS). It is
                        created as a locked service account when it does not
                        exist. Naming your own account works but is not
                        recommended: the plan says it is not dedicated
--hq-config <path>      Read HQ's harnesses.accounts (adapter ID to account)
                        and optional Linux harnesses.dir. Shared accounts are
                        provisioned once. Legacy members config is refused
--hq-service <json>     Install the platform HQ service from a verified release record
--members <a,b,...>     Name the harness accounts directly (compatibility flag)
--dir <path>            The endpoint directory, with --members
                        (default ` + DefaultDir + `)
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
	HQService  *HQService `json:"hq_service,omitempty"`
	PlanID     string     `json:"plan_id"`
	PlanDigest string     `json:"plan_digest"`
	CreatedAt  string     `json:"created_at"`
	Plan       Plan       `json:"plan"`
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
	if len(args) > 0 && args[0] == "apply" {
		return runApply(deps, ctx, args[1:])
	}
	if len(args) == 0 || args[0] != "plan" {
		return cli.Result{Diagnostic: command.UsageErr("members takes one action: plan or apply")}
	}
	var hqAccount, hqConfigPath, list, dir, serviceRecord string
	var hasList, hasDir bool
	if d := command.Parse(args[1:], command.Spec{
		Values: map[string]command.Flag{
			"--hq-service": {Value: &serviceRecord},
			"--hq-account": {Value: &hqAccount},
			"--hq-config":  {Value: &hqConfigPath},
			"--members":    {Value: &list, Set: &hasList, Optional: true},
			"--dir":        {Value: &dir, Set: &hasDir},
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
	switch {
	case platform == PlatformDarwin && hasDir:
		return failure(diag.MembersUnsupported, "endpoint directory setup is Linux only")
	case platform == PlatformDarwin && hqConfigPath == "" && !hasList:
	case (hqConfigPath != "") == hasList:
		return cli.Result{Diagnostic: command.UsageErr("members plan needs exactly one of --hq-config and --members")}
	case hqConfigPath != "" && hasDir:
		return cli.Result{Diagnostic: command.UsageErr("--dir goes with --members; --hq-config names its own directory")}
	}

	in := Input{HQAccount: hqAccount, Dir: dir, Platform: platform}
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
		if platform == PlatformDarwin {
			// Only the credential accounts are provisioned on Darwin.
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
	} else if platform == PlatformDarwin && len(in.Members) > 0 {
		return failure(diag.MembersAccountRefused, "cannot identify the owner planning Darwin harness accounts: %v", err)
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
	now := deps.Time()
	planID, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make a plan id: %v", err)
	}
	state, err := deps.ResolveStateDir(usernameOS(platform))
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate the state directory: %v", err)
	}
	saved := Saved{HQService: in.HQService, PlanID: planID, PlanDigest: digest, CreatedAt: now.UTC().Format("2006-01-02T15:04:05Z"), Plan: plan}
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
	for _, s := range plan.Steps {
		if platform == PlatformDarwin && s.Kind == KindHQAccount && s.Target == DarwinHQAccount && s.Action == ActionCreate {
			advice := "The prefix administrator can send this saved plan to the owner approval app with managed-machine daemon first-hq export " + planID
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
	}
	return cli.Result{Records: records}
}

// platformOf maps a host target to Input.Platform. Linux plans everything;
// macOS plans the HQ account alone.
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
