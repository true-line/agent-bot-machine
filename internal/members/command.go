package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		Summary: "Plan and apply the Linux accounts, endpoint directories and launch rule for Soul members",
		Usage:   usage,
		Run:     func(ctx cli.Context, args []string) cli.Result { return run(deps, ctx, args) },
	}
}

const usage = `Usage: managed-machine members plan --hq-account <account> (--hq-config <path> | --members <a,b,...>) [--dir <path>]
       sudo managed-machine members apply <plan-id>

Plan the account HQ runs in, one OS account per Soul member, the broker
endpoint directories HQ verifies, the tmpfiles entry that recreates them at
boot, and the sudoers rule that lets the HQ account start members
(docs/plans/member-accounts.md).

plan reads the host and changes nothing. It saves the plan and prints its
plan_id and plan_digest. Linux only.

apply needs root and an approval. The owner approves the plan's digest in
the local web UI, then runs apply with sudo in their own terminal within
ten minutes. apply builds the plan again from the host and runs only when
its digest is the approved one. It takes a plan id and nothing else; no
option skips the approval. An agent account or session is refused.

Options
-h, --help              Show this usage and read nothing
--hq-account <account>  The account HQ runs in. It is created as a locked
                        service account when it does not exist
--hq-config <path>      Read the member accounts and directory from HQ's
                        config.json (members.accounts, members.dir)
--members <a,b,...>     Name the member accounts directly
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
	PlanID     string `json:"plan_id"`
	PlanDigest string `json:"plan_digest"`
	CreatedAt  string `json:"created_at"`
	Plan       Plan   `json:"plan"`
}

// hqConfig is the part of agent-bot-hq's config.json this command reads.
type hqConfig struct {
	Members *struct {
		Dir      string                       `json:"dir"`
		Accounts map[string]map[string]string `json:"accounts"`
	} `json:"members"`
}

func fromConfig(raw []byte) (dir string, members []string, err error) {
	var c hqConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", nil, fmt.Errorf("not JSON: %v", err)
	}
	if c.Members == nil {
		return "", nil, errors.New("it has no members section")
	}
	for _, byMember := range c.Members.Accounts {
		for _, account := range byMember {
			members = append(members, account)
		}
	}
	sort.Strings(members)
	return c.Members.Dir, members, nil
}

func run(deps Deps, ctx cli.Context, args []string) cli.Result {
	if len(args) > 0 && args[0] == "apply" {
		return runApply(deps, ctx, args[1:])
	}
	if len(args) == 0 || args[0] != "plan" {
		return cli.Result{Diagnostic: command.UsageErr("members takes one action: plan or apply")}
	}
	var hqAccount, hqConfigPath, list, dir string
	var hasList, hasDir bool
	if d := command.Parse(args[1:], command.Spec{
		Values: map[string]command.Flag{
			"--hq-account": {Value: &hqAccount},
			"--hq-config":  {Value: &hqConfigPath},
			"--members":    {Value: &list, Set: &hasList, Optional: true},
			"--dir":        {Value: &dir, Set: &hasDir},
		},
	}); d != nil {
		return cli.Result{Diagnostic: d}
	}
	switch {
	case hqAccount == "":
		return cli.Result{Diagnostic: command.UsageErr("members plan needs --hq-account")}
	case (hqConfigPath != "") == hasList:
		return cli.Result{Diagnostic: command.UsageErr("members plan needs exactly one of --hq-config and --members")}
	case hqConfigPath != "" && hasDir:
		return cli.Result{Diagnostic: command.UsageErr("--dir goes with --members; --hq-config names its own directory")}
	}

	host, dg := command.DetectHost(ctx)
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	if !strings.HasPrefix(string(host.Target), "linux/") {
		return failure(diag.MembersUnsupported, "member accounts are Linux only; this host is %s", host.Target)
	}

	in := Input{HQAccount: hqAccount, Dir: dir}
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
	} else {
		for _, m := range strings.Split(list, ",") {
			if m = strings.TrimSpace(m); m != "" {
				in.Members = append(in.Members, m)
			}
		}
	}
	if name, err := deps.ResolveUsername("linux"); err == nil {
		in.Invoker = name
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
	state, err := deps.ResolveStateDir("linux")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate the state directory: %v", err)
	}
	saved := Saved{PlanID: planID, PlanDigest: digest, CreatedAt: now.UTC().Format("2006-01-02T15:04:05Z"), Plan: plan}
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
		Set("applied", false)}
	for _, s := range plan.Steps {
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
