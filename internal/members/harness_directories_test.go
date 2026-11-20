package members

import (
	"errors"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type brokerHost struct {
	*fakeHost
	denied string
}

func (h *brokerHost) CheckDarwinACLs(paths []string) error {
	if slices.Contains(paths, h.denied) {
		return errors.New("ACL inspection refused")
	}
	return nil
}

func brokerFixture() (*brokerHost, Input) {
	h := &brokerHost{fakeHost: emptyHost()}
	for _, p := range pathAncestry(launchRuntimeDir) {
		h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	}
	in := Input{HQAccount: DarwinHQAccount, Platform: PlatformDarwin, Invoker: "owner", Dir: DarwinBrokerDir, Members: []string{"_spec", "_lead"}}
	for i, n := range []string{DarwinHQAccount, "_spec", "_lead"} {
		a := member(n, 320+i)
		a.DarwinRole, a.Home, a.Shell = darwinHarnessRoleName, darwinHarnessHome(n), DarwinNoLoginShell
		if i == 0 {
			a.DarwinRole, a.Home = darwinHQRoleName, HQHome(PlatformDarwin, n)
		}
		h.accounts[n] = a
		h.entries[a.Home] = Entry{Dir: true, Owner: n, Group: n, Mode: 0700}
	}
	return h, in
}

func TestDarwinBrokerDirectoryPlanPreservesAccountsAndExistingEntries(t *testing.T) {
	h, in := brokerFixture()
	r := newRoot(h.fakeHost)
	p, err := Build(in, h)
	if err != nil || p.Changes() != 3 || p.Dir != DarwinBrokerDir {
		t.Fatal(p, err)
	}
	// A selection that omits a previous harness has no authority to delete its directory.
	unlisted := DarwinBrokerDir + "/_previous"
	h.entries[unlisted] = Entry{Dir: true, Owner: DarwinHQAccount, Group: "_previous", Mode: 02750}
	h.files[unlisted+"/keep"] = "existing data"
	if err = Apply(p, h, r); err != nil {
		t.Fatal(err)
	}
	for _, account := range in.Members {
		if got := h.entries[path.Join(DarwinBrokerDir, account)]; got != (Entry{Dir: true, Owner: DarwinHQAccount, Group: account, Mode: 02750}) {
			t.Fatal(got)
		}
	}
	repeat, err := Build(in, h)
	if err != nil || repeat.Changes() != 0 || h.files[unlisted+"/keep"] != "existing data" {
		t.Fatal(repeat, err)
	}
	accountOnly := in
	accountOnly.Dir = ""
	legacy, err := Build(accountOnly, h)
	if err != nil || legacy.Dir != DarwinDir || len(legacy.Steps) != 3 {
		t.Fatal(legacy, err)
	}
	got, _ := legacy.Digest()
	accountOnly.Dir = DarwinDir
	saved, err := Build(accountOnly, h)
	want, _ := saved.Digest()
	if err != nil || got != want {
		t.Fatal("saved account-only plan changed", err)
	}
	if n := len(DarwinBrokerDir + "/" + strings.Repeat("a", 32) + "/broker.sock"); n > 103 {
		t.Fatalf("%d-byte Darwin socket path", n)
	}
}

func TestDarwinBrokerDirectoryRequiresVerifiedLayout(t *testing.T) {
	for _, sc := range []string{"parent missing", "untrusted ancestor", "unknown base", "wrong leaf", "ancestor ACL", "leaf ACL", "empty", "other HQ", "other location"} {
		t.Run(sc, func(t *testing.T) {
			h, in := brokerFixture()
			h.entries[DarwinBrokerDir] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
			leaf := path.Join(DarwinBrokerDir, in.Members[0])
			h.entries[leaf] = Entry{Dir: true, Owner: DarwinHQAccount, Group: in.Members[0], Mode: 02750}
			switch sc {
			case "parent missing":
				delete(h.entries, launchRuntimeDir)
			case "untrusted ancestor":
				h.entries[filepath.Dir(filepath.Dir(launchRuntimeDir))] = Entry{Dir: true, Owner: "root", Mode: 0777}
			case "unknown base":
				h.entries[DarwinBrokerDir] = Entry{Regular: true}
			case "wrong leaf":
				h.entries[leaf] = Entry{Dir: true, Owner: DarwinHQAccount, Group: "staff", Mode: 02750}
			case "ancestor ACL":
				h.denied = filepath.Dir(filepath.Dir(launchRuntimeDir))
			case "leaf ACL":
				h.denied = leaf
			case "empty":
				in.Members = nil
			case "other HQ":
				in.HQAccount = "_other"
			case "other location":
				in.Dir = "/tmp/brokers"
			}
			if _, err := Build(in, h); err == nil {
				t.Fatal("accepted unverified layout")
			}
		})
	}
}

type interruptedBrokerRoot struct{ *fakeRoot }

func (r interruptedBrokerRoot) EnsureDir(p, owner, group string, mode uint32) error {
	if group == "_spec" {
		return errors.New("fixture directory creation interrupted")
	}
	return r.fakeRoot.EnsureDir(p, owner, group, mode)
}

func TestDarwinBrokerDirectoryReplanAfterPartialApply(t *testing.T) {
	h, in := brokerFixture()
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	r := interruptedBrokerRoot{newRoot(h.fakeHost)}
	if err = Apply(p, h, r); err == nil {
		t.Fatal("expected interruption")
	}
	retained := path.Join(DarwinBrokerDir, "_lead", "broker.sock")
	h.files[retained] = "occupied"
	remaining, err := Build(in, h)
	if err != nil || remaining.Changes() != 1 {
		t.Fatal(remaining, err)
	}
	first, _ := p.Digest()
	second, _ := remaining.Digest()
	if first == second {
		t.Fatal("remaining operation reused the old digest")
	}
	if err := Apply(remaining, h, r.fakeRoot); err != nil {
		t.Fatal(err)
	}
	if h.files[retained] != "occupied" {
		t.Fatal("changed an earlier directory's contents")
	}
}
