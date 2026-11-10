package members

import (
	"errors"
	"strings"
	"testing"
)

// fakeHost is a host held in maps.
type fakeHost struct {
	accounts map[string]Account
	entries  map[string]Entry
	files    map[string]string
	lists    map[string][]string
}

func (f *fakeHost) Account(n string) (Account, bool, error) {
	a, ok := f.accounts[n]
	return a, ok, nil
}
func (f *fakeHost) Lstat(p string) (Entry, bool, error)     { e, ok := f.entries[p]; return e, ok, nil }
func (f *fakeHost) ReadFile(p string) (string, bool, error) { s, ok := f.files[p]; return s, ok, nil }
func (f *fakeHost) List(p string) ([]string, error)         { return f.lists[p], nil }

func member(name string, uid int) Account {
	return Account{Name: name, UID: uid, GID: uid, Group: name, PrimaryUsers: []string{name}, Groups: []string{name}, Home: "/home/" + name, Shell: NoLoginShell}
}

// bare is a host with the HQ account and nothing else.
func bare() *fakeHost {
	return &fakeHost{
		accounts: map[string]Account{"agent-bot-hq": {Name: "agent-bot-hq", UID: 900, GID: 900, Group: "agent-bot-hq"}},
		entries:  map[string]Entry{}, files: map[string]string{}, lists: map[string][]string{},
	}
}

var request = Input{HQAccount: "agent-bot-hq", Members: []string{"abm-spec", "abm-lead"}, Invoker: "owner"}

// provisioned is a host on which request has been applied.
func provisioned() *fakeHost {
	h := bare()
	in, _ := Normalize(request)
	for i, m := range in.Members {
		h.accounts[m] = member(m, 1001+i)
		h.entries["/home/"+m] = Entry{Dir: true, Mode: 0o700, Owner: m, Group: m}
		h.entries[DefaultDir+"/"+m] = Entry{Dir: true, Mode: 0o2750, Owner: "agent-bot-hq", Group: m}
	}
	h.entries[DefaultDir] = Entry{Dir: true, Mode: 0o755, Owner: "root", Group: "root"}
	h.lists[DefaultDir] = []string{"abm-lead", "abm-spec"}
	h.entries[TmpfilesPath] = Entry{Regular: true, Mode: 0o644, Owner: "root", Group: "root"}
	h.files[TmpfilesPath] = Tmpfiles(in)
	return h
}

func actions(p Plan) string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.Kind+" "+s.Target+" "+s.Action)
	}
	return strings.Join(out, "\n")
}

func TestPlanOnABareHostCreatesEverythingInOrder(t *testing.T) {
	p, err := Build(request, bare())
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"account abm-lead create",
		"account abm-spec create",
		"directory /run/agent-bot-hq/members create",
		"directory /run/agent-bot-hq/members/abm-lead create",
		"directory /run/agent-bot-hq/members/abm-spec create",
		"file /etc/tmpfiles.d/agent-bot-hq-members.conf create",
		"file /etc/sudoers.d/agent-bot-hq-members write",
	}, "\n")
	if got := actions(p); got != want {
		t.Fatalf("steps:\n%s\nwant:\n%s", got, want)
	}
	if p.Changes() != 6 {
		t.Errorf("changes = %d, want 6", p.Changes())
	}
	// The endpoint directory is exactly what agent-bot-hq verifies.
	d := p.Steps[3]
	if d.Owner != "agent-bot-hq" || d.Group != "abm-lead" || d.Mode != "2750" {
		t.Errorf("endpoint directory = %+v", d)
	}
}

func TestTheRuleNamesOnlyTheHQAccountAndTheListedMembers(t *testing.T) {
	in, _ := Normalize(request)
	want := header +
		"Runas_Alias ABHQ_MEMBERS = abm-lead, abm-spec\n" +
		"Defaults:agent-bot-hq env_reset, !setenv\n" +
		"Defaults:agent-bot-hq env_keep = \"AGENT_BOT_SOULS_SOCKET AGENT_BOT_SOULS_MEMBER_TOKEN AGENT_BOT_SOULS_MEMBER_ID AGENT_BOT_SOULS_ROLE AGENT_BOT_SOULS_BROKER\"\n" +
		"agent-bot-hq ALL = (ABHQ_MEMBERS) NOPASSWD: NOSETENV: ALL\n"
	if got := Sudoers(in); got != want {
		t.Fatalf("sudoers:\n%s\nwant:\n%s", got, want)
	}
	for _, forbidden := range []string{"root", " SETENV:", "%", "ALL : ALL", "(ALL"} {
		if strings.Contains(strings.TrimPrefix(Sudoers(in), header), forbidden) {
			t.Errorf("the rule contains %q", forbidden)
		}
	}
	wantTmp := header +
		"d /run/agent-bot-hq/members 0755 root root -\n" +
		"d /run/agent-bot-hq/members/abm-lead 2750 agent-bot-hq abm-lead -\n" +
		"d /run/agent-bot-hq/members/abm-spec 2750 agent-bot-hq abm-spec -\n"
	if got := Tmpfiles(in); got != wantTmp {
		t.Fatalf("tmpfiles:\n%s\nwant:\n%s", got, wantTmp)
	}
	// With nobody listed the HQ account may start nothing.
	none := Sudoers(Input{HQAccount: "agent-bot-hq"})
	if strings.Contains(none, "NOPASSWD") || strings.Contains(none, "Runas_Alias") {
		t.Errorf("an empty list still grants something:\n%s", none)
	}
}

func TestAProvisionedHostPlansNoChangeAndTheDigestIsStable(t *testing.T) {
	a, err := Build(request, provisioned())
	if err != nil {
		t.Fatal(err)
	}
	if a.Changes() != 0 {
		t.Fatalf("changes = %d:\n%s", a.Changes(), actions(a))
	}
	// The sudoers file is closed to an unprivileged plan, so its step never
	// depends on the host: root's rebuild must reach the same digest.
	if last := a.Steps[len(a.Steps)-1]; last.Target != SudoersPath || last.Action != ActionWrite {
		t.Errorf("sudoers step = %+v", last)
	}
	// The order the owner named the members in does not matter.
	b, err := Build(Input{HQAccount: "agent-bot-hq", Members: []string{"abm-lead", "abm-spec"}, Invoker: "owner"}, provisioned())
	if err != nil {
		t.Fatal(err)
	}
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db || len(da) != 64 {
		t.Fatalf("digests %s and %s", da, db)
	}
}

func TestAHostThatChangedGivesAnotherDigest(t *testing.T) {
	base, _ := Build(request, provisioned())
	want, _ := base.Digest()
	for name, change := range map[string]func(*fakeHost){
		"an endpoint directory opened to others": func(h *fakeHost) {
			h.entries[DefaultDir+"/abm-lead"] = Entry{Dir: true, Mode: 0o2755, Owner: "agent-bot-hq", Group: "abm-lead"}
		},
		"an endpoint directory given to another group": func(h *fakeHost) {
			h.entries[DefaultDir+"/abm-lead"] = Entry{Dir: true, Mode: 0o2750, Owner: "agent-bot-hq", Group: "abm-spec"}
		},
		"a home opened to others": func(h *fakeHost) {
			h.entries["/home/abm-spec"] = Entry{Dir: true, Mode: 0o755, Owner: "abm-spec", Group: "abm-spec"}
		},
		"an edited tmpfiles entry": func(h *fakeHost) { h.files[TmpfilesPath] += "d /run/other 0777 root root -\n" },
		"a missing member account": func(h *fakeHost) { delete(h.accounts, "abm-spec") },
		"a former member's directory": func(h *fakeHost) {
			h.lists[DefaultDir] = append(h.lists[DefaultDir], "abm-old")
		},
	} {
		h := provisioned()
		change(h)
		p, err := Build(request, h)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got, _ := p.Digest(); got == want {
			t.Errorf("%s: the digest did not change", name)
		}
		if p.Changes() == 0 {
			t.Errorf("%s: no change planned", name)
		}
	}
}

func TestAMemberTakenOffTheListLosesItsDirectoryAndRuleButKeepsItsAccount(t *testing.T) {
	p, err := Build(Input{HQAccount: "agent-bot-hq", Members: []string{"abm-lead"}, Invoker: "owner"}, provisioned())
	if err != nil {
		t.Fatal(err)
	}
	got := actions(p)
	if !strings.Contains(got, "directory /run/agent-bot-hq/members/abm-spec remove") {
		t.Errorf("no removal planned:\n%s", got)
	}
	if strings.Contains(got, "account abm-spec") {
		t.Errorf("the account is touched:\n%s", got)
	}
	for _, s := range p.Steps {
		if s.Kind == KindFile && strings.Contains(s.Content, "abm-spec") {
			t.Errorf("%s still names abm-spec", s.Target)
		}
	}
}

func TestRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		in     Input
		change func(*fakeHost)
		code   string
		says   string
	}{
		"a name that is not an account name": {in: Input{HQAccount: "agent-bot-hq", Members: []string{"Abm Lead"}}, code: RefusedList, says: "not an account name"},
		"a name that would inject a rule":    {in: Input{HQAccount: "agent-bot-hq", Members: []string{"abm,ALL"}}, code: RefusedList, says: "not an account name"},
		"a member listed twice":              {in: Input{HQAccount: "agent-bot-hq", Members: []string{"abm-a", "abm-a"}}, code: RefusedList, says: "twice"},
		"the HQ account as a member":         {in: Input{HQAccount: "agent-bot-hq", Members: []string{"agent-bot-hq"}}, code: RefusedList, says: "HQ account"},
		"root as a member":                   {in: Input{HQAccount: "agent-bot-hq", Members: []string{"root"}}, code: RefusedList, says: "root"},
		"the invoking account as a member":   {in: Input{HQAccount: "agent-bot-hq", Members: []string{"owner"}, Invoker: "owner"}, code: RefusedList, says: "running this command"},
		"a directory that is not clean":      {in: Input{HQAccount: "agent-bot-hq", Dir: "/run/../etc"}, code: RefusedList, says: "clean absolute path"},
		"a directory with a space":           {in: Input{HQAccount: "agent-bot-hq", Dir: "/run/a b"}, code: RefusedList, says: "clean absolute path"},
		"no HQ account":                      {in: request, change: func(h *fakeHost) { delete(h.accounts, "agent-bot-hq") }, code: RefusedAccount, says: "does not exist"},
		"an HQ account that is root": {in: request, change: func(h *fakeHost) {
			h.accounts["agent-bot-hq"] = Account{Name: "agent-bot-hq", UID: 0}
		}, code: RefusedAccount, says: "is root"},
		"a member with uid 0": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.UID = 0
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "is root"},
		"two members with one uid": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-spec"]
			a.UID = h.accounts["abm-lead"].UID
			h.accounts["abm-spec"] = a
		}, code: RefusedAccount, says: "shares uid"},
		"a member sharing HQ's uid": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.UID = 900
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "shares uid"},
		"a member whose group is not its own": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.Group = "users"
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "private group"},
		"a group with another supplementary member": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.GroupMembers = []string{"mallory"}
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "mallory"},
		"a group that is another account's primary group": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.PrimaryUsers = []string{"abm-lead", "mallory"}
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "mallory"},
		"a member in sudo": {in: request, change: func(h *fakeHost) {
			a := h.accounts["abm-lead"]
			a.Groups = []string{"abm-lead", "sudo"}
			h.accounts["abm-lead"] = a
		}, code: RefusedAccount, says: "sudo"},
		"a home that is someone else's": {in: request, change: func(h *fakeHost) {
			h.entries["/home/abm-lead"] = Entry{Dir: true, Mode: 0o700, Owner: "mallory", Group: "abm-lead"}
		}, code: RefusedAccount, says: "home"},
		"an endpoint path that is a file": {in: request, change: func(h *fakeHost) {
			h.entries[DefaultDir+"/abm-lead"] = Entry{Regular: true, Mode: 0o644, Owner: "root", Group: "root"}
		}, code: RefusedPath, says: "not a directory"},
		"a tmpfiles path that is a link": {in: request, change: func(h *fakeHost) {
			h.entries[TmpfilesPath] = Entry{Mode: 0o777, Owner: "root", Group: "root"}
		}, code: RefusedPath, says: "not a regular file"},
		"something else in the members directory": {in: request, change: func(h *fakeHost) {
			h.lists[DefaultDir] = append(h.lists[DefaultDir], "Other.sock")
		}, code: RefusedPath, says: "did not create"},
	} {
		h := provisioned()
		if tc.change != nil {
			tc.change(h)
		}
		_, err := Build(tc.in, h)
		var r *Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s: err = %v, want a refusal", name, err)
			continue
		}
		if r.Code != tc.code || !strings.Contains(r.Message, tc.says) {
			t.Errorf("%s: refused as %s %q; want %s mentioning %q", name, r.Code, r.Message, tc.code, tc.says)
		}
	}
}
