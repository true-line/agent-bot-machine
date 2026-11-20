// Package members plans the Linux harness accounts of
// docs/plans/member-accounts.md: one OS account per harness credential, the broker
// endpoint directories agent-bot-hq verifies, the tmpfiles entry that
// recreates them at boot, and the sudoers rule that lets the HQ account
// start harness processes. This file is pure: it reads the host through Host and
// changes nothing. Applying a plan is a separate, approved, root step.
package members

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Paths and names fixed by the specification.
const (
	DefaultDir = "/run/agent-bot-hq/members"
	// DefaultHQAccount is the dedicated account HQ runs in on Linux (D6). A
	// plan that names no account uses it, so the dedicated account is what
	// an owner gets without asking.
	DefaultHQAccount = "agent-bot-hq"
	TmpfilesPath     = "/etc/tmpfiles.d/agent-bot-hq-members.conf"
	SudoersPath      = "/etc/sudoers.d/agent-bot-hq-members"
	EgressScriptPath = "/usr/local/sbin/agent-bot-hq-members-egress"
	EgressUnitPath   = "/etc/systemd/system/agent-bot-hq-members-egress.service"
	EgressUnitName   = "agent-bot-hq-members-egress.service"
	HomeBase         = "/home"
	// HQHomeBase is where a new HQ account's home goes: it is a service
	// account, and its home is HQ's state, not a person's files.
	HQHomeBase   = "/var/lib"
	NoLoginShell = "/usr/sbin/nologin"
	// PlatformDarwin plans role accounts without the Linux launch or egress rules.
	PlatformDarwin = "darwin"
	// DarwinHQAccount is the dedicated HQ account on macOS. Role accounts
	// there start with an underscore.
	DarwinHQAccount = "_agent-bot-hq"
	// DarwinHQHomeBase holds the HQ account's home on macOS, named without
	// the underscore: /var/agent-bot-hq.
	DarwinHQHomeBase      = "/var"
	DarwinNoLoginShell    = "/usr/bin/false"
	darwinHarnessRoleName = "Agent Bot Harness"
	darwinHQRoleName      = "Agent Bot HQ"
	// DarwinDir preserves account-only macOS plans and their existing digests.
	DarwinDir       = "none"
	DarwinBrokerDir = launchRuntimeDir + "/ipc"
	// PlanVersion is part of the digest: a change to what a plan means
	// invalidates every approval made before it.
	PlanVersion = 3
)

// EnvKeep is the fixed environment allowlist of the launch rule. HQ passes a
// member nothing else.
var EnvKeep = []string{
	"AGENT_BOT_SOULS_SOCKET",
	"AGENT_BOT_SOULS_MEMBER_TOKEN",
	"AGENT_BOT_SOULS_MEMBER_ID",
	"AGENT_BOT_SOULS_ROLE",
	"AGENT_BOT_SOULS_BROKER",
}

// accountName is the POSIX portable account name agent-bot-hq accepts
// (hq/members.mjs).
var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Actions a step can take.
const (
	ActionNone   = "none"
	ActionCreate = "create"
	ActionRepair = "repair"
	ActionRemove = "remove"
	// ActionWrite is a file written on every apply, whatever is there. The
	// sudoers file and its directory are closed to everyone but root, so a
	// plan made without privilege cannot see them, and a step that depended
	// on them would give root's rebuild a different digest.
	ActionWrite = "write"
)

// Step kinds.
const (
	KindAccount = "account"
	// KindHQAccount is the account HQ runs in (cross-account-channel.md, S6).
	KindHQAccount = "hq-account"
	KindDirectory = "directory"
	KindFile      = "file"
	KindService   = "service"
)

// Input is what the owner asked for.
type Input struct {
	upgradeObservation *upgradeObservation
	UpgradeFrom        *priorServicePlan
	HQService          *HQService
	HQAccount          string
	Dir                string
	Members            []string
	// Invoker is the account running the plan. It can never be a member.
	Invoker string
	// Platform is PlatformDarwin on macOS and empty on Linux. It is not part
	// of the plan: apply takes it from the host it runs on.
	Platform string
}

// DefaultHQAccountFor is the dedicated HQ account of a platform.
func DefaultHQAccountFor(platform string) string {
	if platform == PlatformDarwin {
		return DarwinHQAccount
	}
	return DefaultHQAccount
}

// HQHome is where a new HQ account's home goes.
func HQHome(platform, name string) string {
	if platform == PlatformDarwin {
		return path.Join(DarwinHQHomeBase, strings.TrimPrefix(name, "_"))
	}
	return path.Join(HQHomeBase, name)
}

// A distinct, flat namespace under the root-owned Darwin service-home parent.
func darwinHarnessHome(name string) string {
	return path.Join(DarwinHQHomeBase, "agent-bot-harness-"+name)
}

func hqShell(platform string) string {
	if platform == PlatformDarwin {
		return DarwinNoLoginShell
	}
	return NoLoginShell
}

// Account is the host's record of one account.
type Account struct {
	Name string
	UID  int
	GID  int
	// Group is the name of the primary group.
	Group string
	// GroupMembers are the supplementary members of the primary group.
	GroupMembers []string
	// PrimaryUsers are the accounts whose primary group is GID.
	PrimaryUsers []string
	// Groups are the names of every group the account is in.
	Groups     []string
	Home       string
	Shell      string
	DarwinRole string // label of a verified local Directory Services role
}

// Entry is the host's record of one path, from lstat.
type Entry struct {
	Dir     bool
	Regular bool
	// Mode is the permission bits with setuid, setgid and sticky (07777).
	Mode  uint32
	Owner string
	Group string
}

// Host is everything a plan reads. Each lookup reports false, not an error,
// for a thing that does not exist.
type Host interface {
	Account(name string) (Account, bool, error)
	Lstat(p string) (Entry, bool, error)
	ReadFile(p string) (string, bool, error)
	// List returns the names in a directory, or nil when it does not exist.
	List(p string) ([]string, error)
}

// Step is one thing the plan would create, repair, remove or leave alone.
// Every field is covered by the digest.
type Step struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Action string `json:"action"`
	Owner  string `json:"owner,omitempty"`
	Group  string `json:"group,omitempty"`
	Mode   string `json:"mode,omitempty"`
	// Content is the exact content of a file step.
	Content string `json:"content,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Plan is the exact request the owner approves.
type Plan struct {
	Version   int      `json:"version"`
	HQAccount string   `json:"hq_account"`
	Dir       string   `json:"dir"`
	Members   []string `json:"members"`
	Steps     []Step   `json:"steps"`
}

// Refusal is a host or request the plan will not touch. Code is one of the
// Refused* values; the command maps it to a diagnostic.
type Refusal struct {
	Code    string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

// Refusal codes.
const (
	RefusedList    = "list"
	RefusedAccount = "account"
	RefusedPath    = "path"
)

func refuse(code, format string, args ...any) error {
	return &Refusal{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Normalize validates an input and returns it with the members sorted.
func Normalize(in Input) (Input, error) {
	if !accountName.MatchString(in.HQAccount) {
		return in, refuse(RefusedList, "HQ account %q is not an account name", in.HQAccount)
	}
	if in.Platform == PlatformDarwin {
		switch in.Dir {
		case "", DarwinDir:
			in.Dir = DarwinDir
		case DarwinBrokerDir:
			if in.HQAccount != DarwinHQAccount || len(in.Members) == 0 {
				return in, refuse(RefusedList, "Darwin broker directories require the dedicated HQ account and at least one harness")
			}
		default:
			return in, refuse(RefusedList, "Darwin harness endpoints require %s", DarwinBrokerDir)
		}
	} else if in.Dir == "" {
		in.Dir = DefaultDir
	}
	// agent-bot-hq's own bound on members.dir, plus what a tmpfiles or
	// sudoers line can carry unquoted.
	if in.Platform != PlatformDarwin && (!path.IsAbs(in.Dir) || path.Clean(in.Dir) != in.Dir || in.Dir == "/" || len(in.Dir) > 80 || strings.ContainsAny(in.Dir, " \t\n\\\"'%")) {
		return in, refuse(RefusedList, "members directory %q must be a clean absolute path of at most 80 characters", in.Dir)
	}
	members := append([]string(nil), in.Members...)
	sort.Strings(members)
	for i, m := range members {
		switch {
		case !accountName.MatchString(m):
			return in, refuse(RefusedList, "member account %q is not an account name", m)
		case i > 0 && members[i-1] == m:
			return in, refuse(RefusedList, "member account %q is listed twice", m)
		case m == in.HQAccount:
			return in, refuse(RefusedList, "member account %q is the HQ account; a member needs a separate one", m)
		case in.Platform == PlatformDarwin && darwinHarnessHome(m) == HQHome(in.Platform, in.HQAccount):
			return in, refuse(RefusedList, "member account %q would share the HQ home", m)
		case m == "root" || m == "admin":
			return in, refuse(RefusedList, "%s cannot be a member account", m)
		case in.Invoker != "" && m == in.Invoker:
			return in, refuse(RefusedList, "member account %q is the account running this command", m)
		}
	}
	in.Members = members
	return in, nil
}

// Build reads the host and returns the plan for in. It changes nothing.
func Build(in Input, h Host) (Plan, error) {
	in, err := Normalize(in)
	if err != nil {
		return Plan{}, err
	}
	if in.UpgradeFrom != nil && (in.Platform != PlatformDarwin || in.HQService == nil || in.HQAccount != DarwinHQAccount || len(in.Members) != 0) {
		return Plan{}, refuse(RefusedList, "upgrade requires a dedicated macOS service-only plan")
	}
	p := Plan{Version: PlanVersion, HQAccount: in.HQAccount, Dir: in.Dir, Members: in.Members, Steps: []Step{}}
	if p.Members == nil {
		p.Members = []string{}
	}

	// The HQ account comes first: the directories and the rule name it.
	uids := map[int]string{}
	hq, err := hqAccountStep(in, h, uids)
	if err != nil {
		return Plan{}, err
	}
	p.Steps = append(p.Steps, hq)
	if in.Platform == PlatformDarwin && len(in.Members) > 0 && p.SharedHQAdvice() != "" {
		return Plan{}, refuse(RefusedAccount, "Darwin harness accounts require a dedicated HQ account")
	}
	for _, m := range in.Members {
		step, err := platformAccountStep(in.Platform, m, h, uids)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, step)
	}

	if in.Platform == PlatformDarwin {
		if in.Dir == DarwinBrokerDir {
			if err := appendDarwinBrokerDirectories(&p, h); err != nil {
				return Plan{}, err
			}
		}
		if in.HQService != nil {
			if err := appendLaunchDaemon(&p, in, h); err != nil {
				return Plan{}, err
			}
		}
		return p, nil
	}

	// The endpoint directories, exactly as hq/members.mjs verifies them.
	base, err := dirStep(h, in.Dir, "root", "root", 0o755)
	if err != nil {
		return Plan{}, err
	}
	p.Steps = append(p.Steps, base)
	for _, m := range in.Members {
		step, err := dirStep(h, path.Join(in.Dir, m), in.HQAccount, m, 0o2750)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, step)
	}
	// An endpoint directory of an account no longer listed is removed. The
	// account and its home are kept: a member's home may hold work.
	names, err := h.List(in.Dir)
	if err != nil {
		return Plan{}, err
	}
	sort.Strings(names)
	listed := map[string]bool{}
	for _, m := range in.Members {
		listed[m] = true
	}
	for _, name := range names {
		if listed[name] {
			continue
		}
		if !accountName.MatchString(name) {
			return Plan{}, refuse(RefusedPath, "%s holds %q, which this tool did not create", in.Dir, name)
		}
		p.Steps = append(p.Steps, Step{Kind: KindDirectory, Target: path.Join(in.Dir, name), Action: ActionRemove,
			Detail: "no longer a member; the account and its home are kept"})
	}

	step, err := fileStep(h, TmpfilesPath, "0644", Tmpfiles(in))
	if err != nil {
		return Plan{}, err
	}
	p.Steps = append(p.Steps, step)
	for _, f := range []struct {
		path, mode, content string
	}{
		{EgressScriptPath, "0755", EgressScript(in)},
		{EgressUnitPath, "0644", EgressUnit()},
	} {
		step, err := ownedFileStep(h, f.path, f.mode, f.content)
		if err != nil {
			return Plan{}, err
		}
		p.Steps = append(p.Steps, step)
	}
	p.Steps = append(p.Steps, Step{Kind: KindService, Target: EgressUnitName, Action: ActionWrite,
		Detail: "validate both firewall families, reload systemd, enable for boot and restart before installing the launch rule"})
	// The launch rule stays last: HQ cannot start a member before its egress
	// boundary has been activated successfully.
	p.Steps = append(p.Steps, Step{Kind: KindFile, Target: SudoersPath, Action: ActionWrite, Owner: "root", Group: "root",
		Mode: "0440", Content: Sudoers(in), Detail: "checked with visudo before it is moved into place"})
	if in.HQService != nil {
		if err := appendHQService(&p, in, h); err != nil {
			return Plan{}, err
		}
	}
	return p, nil
}

// sharing returns who else is in an account's primary group and which other
// groups the account is in. Both are empty for a private account.
func sharing(a Account) (others, extra []string) {
	for _, u := range append(append([]string(nil), a.GroupMembers...), a.PrimaryUsers...) {
		if u != a.Name {
			others = append(others, u)
		}
	}
	for _, g := range a.Groups {
		if g != a.Group {
			extra = append(extra, g)
		}
	}
	sort.Strings(others)
	sort.Strings(extra)
	return others, extra
}

// hqAccountStep plans the account HQ runs in. A missing one is created as a
// locked service account. One that exists is never changed beyond its home's
// mode. An existing account that is not private (the owner's own account,
// where HQ runs until it moves) is accepted and the step says so, because
// that is what the owner then approves: HQ's state is only as private as
// that account.
func hqAccountStep(in Input, h Host, uids map[int]string) (Step, error) {
	name := in.HQAccount
	want := Step{Kind: KindHQAccount, Target: name, Group: name, Mode: "0700"}
	a, ok, err := h.Account(name)
	if err != nil {
		return Step{}, err
	}
	if !ok {
		if name == in.Invoker {
			return Step{}, refuse(RefusedAccount, "HQ account %s is the account running this command and has no account record", name)
		}
		want.Action = ActionCreate
		kind := "service account"
		if in.Platform == PlatformDarwin {
			kind = "hidden role account"
		}
		want.Detail = fmt.Sprintf("%s, home %s, shell %s, private group, no password, no other groups", kind, HQHome(in.Platform, name), hqShell(in.Platform))
		return want, nil
	}
	if in.Platform == PlatformDarwin && len(in.Members) != 0 && (a.DarwinRole != darwinHQRoleName || a.Shell != DarwinNoLoginShell || a.Name == in.Invoker) {
		return Step{}, refuse(RefusedAccount, "Darwin harness accounts require a managed, dedicated HQ account")
	}
	if a.UID == 0 {
		return Step{}, refuse(RefusedAccount, "HQ account %s is root", name)
	}
	uids[a.UID] = name
	others, extra := sharing(a)
	var why []string
	if a.Group != name {
		why = append(why, "primary group "+a.Group)
	}
	if len(others) > 0 {
		why = append(why, "its group also has "+strings.Join(others, ", "))
	}
	if len(extra) > 0 {
		why = append(why, "also in "+strings.Join(extra, ", "))
	}
	if len(why) > 0 {
		// No group and no mode: nothing about this account is checked or
		// changed at apply.
		return Step{Kind: KindHQAccount, Target: name, Action: ActionNone,
			Detail: fmt.Sprintf("exists and is not a dedicated account (%s); it is left as it is, and HQ's state is only as private as this account. %s", strings.Join(why, "; "), sharedAdvice(in.Platform, name))}, nil
	}
	home, ok, err := h.Lstat(a.Home)
	if err != nil {
		return Step{}, err
	}
	if !ok || !home.Dir || home.Owner != name {
		return Step{}, refuse(RefusedAccount, "HQ account %s's home %s is missing or not its own directory", name, a.Home)
	}
	want.Action = ActionNone
	want.Detail = fmt.Sprintf("exists; dedicated; home %s; its password is checked at apply", a.Home)
	if home.Mode&0o7777 != 0o700 {
		want.Action = ActionRepair
		want.Detail = fmt.Sprintf("exists; dedicated; home %s has mode %04o and is set to 0700; its password is checked at apply", a.Home, home.Mode&0o7777)
	}
	return want, nil
}

// sharedAdvice is what an owner is told when HQ would run in an account
// that is not dedicated to it.
func sharedAdvice(platform, name string) string {
	dedicated := DefaultHQAccountFor(platform)
	if name == dedicated {
		return "Recommended: take " + name + " out of every other group and give it a private group of its own name, then plan again"
	}
	return "Recommended: plan without --hq-account, which creates and uses the dedicated account " + dedicated
}

// SharedHQAdvice returns the recommendation for a plan whose HQ account is
// not dedicated, or "" when it is dedicated or will be created.
func (p Plan) SharedHQAdvice() string {
	for _, s := range p.Steps {
		if s.Kind == KindHQAccount && s.Action == ActionNone && s.Mode == "" {
			platform := ""
			if p.Dir == DarwinDir || p.Dir == DarwinBrokerDir {
				platform = PlatformDarwin
			}
			return "HQ account " + s.Target + " is not a dedicated account: every process in it can read HQ's state and start members. " + sharedAdvice(platform, s.Target)
		}
	}
	return ""
}

func platformAccountStep(platform, name string, h Host, uids map[int]string) (Step, error) {
	homePath, shell := path.Join(HomeBase, name), NoLoginShell
	if platform == PlatformDarwin {
		homePath, shell = darwinHarnessHome(name), DarwinNoLoginShell
	}
	want := Step{Kind: KindAccount, Target: name, Group: name, Mode: "0700",
		Detail: fmt.Sprintf("home %s, shell %s, private group, no password, no other groups", homePath, shell)}
	a, ok, err := h.Account(name)
	if err != nil {
		return Step{}, err
	}
	if !ok {
		if platform == PlatformDarwin {
			if _, exists, err := h.Lstat(homePath); err != nil {
				return Step{}, err
			} else if exists {
				return Step{}, refuse(RefusedPath, "home for %s already exists without its managed account", name)
			}
		}
		want.Action = ActionCreate
		return want, nil
	}
	if platform == PlatformDarwin && (a.DarwinRole != darwinHarnessRoleName || a.Home != homePath || a.Shell != shell || a.UID != a.GID) {
		return Step{}, refuse(RefusedAccount, "existing account %s is not a managed Darwin harness role", name)
	}
	// An account that exists is verified, never adopted and never changed.
	others, extra := sharing(a)
	switch {
	case a.UID == 0:
		return Step{}, refuse(RefusedAccount, "member account %s is root", name)
	case uids[a.UID] != "":
		return Step{}, refuse(RefusedAccount, "member account %s shares uid %d with %s", name, a.UID, uids[a.UID])
	case a.Group != name:
		return Step{}, refuse(RefusedAccount, "member account %s has primary group %s, not a private group of its own name", name, a.Group)
	case len(others) > 0:
		return Step{}, refuse(RefusedAccount, "member account %s's group also has %s; it must be private", name, strings.Join(others, ", "))
	case len(extra) > 0:
		return Step{}, refuse(RefusedAccount, "member account %s is also in %s; a member is in no other group", name, strings.Join(extra, ", "))
	}
	uids[a.UID] = name
	home, ok, err := h.Lstat(a.Home)
	if err != nil {
		return Step{}, err
	}
	want.Action = ActionNone
	want.Detail = fmt.Sprintf("exists; home %s; its password is checked at apply", a.Home)
	if !ok || !home.Dir || home.Owner != name || platform == PlatformDarwin && home.Group != name {
		return Step{}, refuse(RefusedAccount, "member account %s's home %s is missing or not its own directory", name, a.Home)
	}
	if home.Mode&0o7777 != 0o700 {
		want.Action = ActionRepair
		want.Detail = fmt.Sprintf("exists; home %s has mode %04o and is set to 0700; its password is checked at apply", a.Home, home.Mode&0o7777)
	}
	return want, nil
}

func dirStep(h Host, p, owner, group string, mode uint32) (Step, error) {
	step := Step{Kind: KindDirectory, Target: p, Owner: owner, Group: group, Mode: fmt.Sprintf("%04o", mode), Action: ActionCreate}
	e, ok, err := h.Lstat(p)
	if err != nil {
		return Step{}, err
	}
	if !ok {
		return step, nil
	}
	if !e.Dir {
		return Step{}, refuse(RefusedPath, "%s exists and is not a directory", p)
	}
	step.Action = ActionNone
	if e.Owner != owner || e.Group != group || e.Mode&0o7777 != mode {
		step.Action = ActionRepair
		step.Detail = fmt.Sprintf("is %s:%s %04o", e.Owner, e.Group, e.Mode&0o7777)
	}
	return step, nil
}

func fileStep(h Host, p, mode, content string) (Step, error) {
	step := Step{Kind: KindFile, Target: p, Owner: "root", Group: "root", Mode: mode, Content: content, Action: ActionCreate}
	if p == SudoersPath {
		step.Action = ActionWrite
		step.Detail = "checked with visudo before it is moved into place"
		return step, nil
	}
	e, ok, err := h.Lstat(p)
	if err != nil {
		return Step{}, err
	}
	if !ok {
		return step, nil
	}
	if !e.Regular {
		return Step{}, refuse(RefusedPath, "%s exists and is not a regular file", p)
	}
	have, _, err := h.ReadFile(p)
	if err != nil {
		return Step{}, err
	}
	step.Action = ActionNone
	if have != content || e.Owner != "root" || e.Group != "root" || fmt.Sprintf("%04o", e.Mode&0o7777) != mode {
		step.Action = ActionRepair
	}
	return step, nil
}

// ownedFileStep refuses an occupied tool-owned path that lacks our marker.
// These files are readable without privilege, unlike sudoers, so plan and
// root's rebuild can agree on the refusal before approval is consumed.
func ownedFileStep(h Host, p, mode, content string) (Step, error) {
	step, err := fileStep(h, p, mode, content)
	if err != nil {
		return Step{}, err
	}
	if step.Action == ActionCreate {
		return step, nil
	}
	have, _, err := h.ReadFile(p)
	if err != nil {
		return Step{}, err
	}
	prefix := header
	if strings.HasPrefix(content, "#!/bin/sh\n") {
		prefix = "#!/bin/sh\n" + header
	}
	if !strings.HasPrefix(have, prefix) {
		return Step{}, refuse(RefusedPath, "%s exists and was not written by this tool", p)
	}
	return step, nil
}

const header = "# Managed by managed-machine (members). Do not edit: it is rewritten.\n"

const egressChain = "ABHQ_MEMBER_EGRESS"

// Tmpfiles is the tmpfiles.d entry that recreates the endpoint directories
// at boot, because /run is cleared.
func Tmpfiles(in Input) string {
	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "d %s 0755 root root -\n", in.Dir)
	for _, m := range in.Members {
		fmt.Fprintf(&b, "d %s 2750 %s %s -\n", path.Join(in.Dir, m), in.HQAccount, m)
	}
	return b.String()
}

// Sudoers is the launch rule: the HQ account, and nobody else, may run a
// command as a listed member account, and as no other account. It names no
// group target; the environment is reset to EnvKeep. NOSETENV is written
// out because sudo implies SETENV for a rule whose command is ALL, which
// would let the HQ account pass any variable on the command line.
func Sudoers(in Input) string {
	var b strings.Builder
	b.WriteString(header)
	if len(in.Members) == 0 {
		b.WriteString("# No member accounts: the HQ account may start nothing.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Runas_Alias ABHQ_MEMBERS = %s\n", strings.Join(in.Members, ", "))
	fmt.Fprintf(&b, "Defaults:%s env_reset, !setenv\n", in.HQAccount)
	fmt.Fprintf(&b, "Defaults:%s env_keep = \"%s\"\n", in.HQAccount, strings.Join(EnvKeep, " "))
	fmt.Fprintf(&b, "%s ALL = (ABHQ_MEMBERS) NOPASSWD: NOSETENV: ALL\n", in.HQAccount)
	return b.String()
}

// EgressScript owns one chain in each firewall family. The OUTPUT jump is
// first, so a host-wide accept rule cannot let a harness account bypass it.
// Unix-domain sockets never traverse these chains and remain available.
func EgressScript(in Input) string {
	var accounts strings.Builder
	for _, m := range in.Members {
		fmt.Fprintf(&accounts, "    \"$tool\" -w -A \"$chain\" -m owner --uid-owner %s -j REJECT\n", m)
	}
	return "#!/bin/sh\n" + header + `set -eu

chain=` + egressChain + `

start_family() {
  tool="$1"
  "$tool" -w -N "$chain" 2>/dev/null || "$tool" -w -F "$chain"
  while "$tool" -w -C OUTPUT -j "$chain" >/dev/null 2>&1; do
    "$tool" -w -D OUTPUT -j "$chain"
  done
  "$tool" -w -I OUTPUT 1 -j "$chain"
` + accounts.String() + `}

stop_family() {
  tool="$1"
  while "$tool" -w -C OUTPUT -j "$chain" >/dev/null 2>&1; do
    "$tool" -w -D OUTPUT -j "$chain"
  done
  "$tool" -w -F "$chain" 2>/dev/null || true
  "$tool" -w -X "$chain" 2>/dev/null || true
}

case "${1-}" in
  start)
    start_family /usr/sbin/iptables
    start_family /usr/sbin/ip6tables
    ;;
  stop)
    stop_family /usr/sbin/iptables
    stop_family /usr/sbin/ip6tables
    ;;
  *)
    echo "usage: agent-bot-hq-members-egress start|stop" >&2
    exit 2
    ;;
esac
`
}

// EgressUnit makes the approved policy persistent and active before HQ can
// launch a member. It does not require agent-bot-hq.service to be installed.
func EgressUnit() string {
	return header + `[Unit]
Description=Agent Bot HQ member egress isolation
After=local-fs.target
Before=agent-bot-hq.service

[Service]
Type=oneshot
ExecStart=` + EgressScriptPath + ` start
ExecStop=` + EgressScriptPath + ` stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
}

// EgressRestore is a no-change parse check for the rules the script installs.
// uid 1 is numeric so validation does not depend on accounts that the same
// approved apply may still need to create.
func EgressRestore() string {
	return "*filter\n:" + egressChain + " - [0:0]\n-A " + egressChain + " -m owner --uid-owner 1 -j REJECT\nCOMMIT\n"
}

// Changes counts the steps whose desired content differs from the host. The
// sudoers write and service activation always run and are not counted.
func (p Plan) Changes() int {
	n := 0
	for _, s := range p.Steps {
		if s.Action != ActionNone && s.Action != ActionWrite {
			n++
		}
	}
	return n
}

// Canonical is the byte form the digest covers: the plan as JSON with its
// fields in declaration order and no HTML escaping.
func (p Plan) Canonical() ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Digest is the SHA-256 of Canonical, in hex. An approval names it, and the
// apply step runs only when the plan rebuilt from the host has the same one.
func (p Plan) Digest() (string, error) {
	raw, err := p.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
