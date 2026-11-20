package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type uninstallFixture struct {
	dir, endpoint  string
	job            bool
	pid            string
	plist          upgradeNodeIdentity
	stops, unlinks int
	want           uninstallEvidence
	h              uninstallHost
}

func newUninstallFixture(t *testing.T, active bool) *uninstallFixture {
	t.Helper()
	f := &uninstallFixture{dir: t.TempDir(), job: active, pid: "", plist: upgradeNodeIdentity{Inode: 21}, want: uninstallEvidence{Owner: "operator", PlanID: "plan-20261119T041500Z-cafe", Digest: strings.Repeat("a", 64)}}
	if active {
		f.pid = "124"
	}
	f.endpoint = filepath.Join(f.dir, "test.sock")
	f.h = uninstallHost{
		observe:      func() (bool, string, error) { return f.job, f.pid, nil },
		plist:        func() (upgradeNodeIdentity, error) { return f.plist, nil },
		waitPID:      func(string) error { return nil },
		syncPlistDir: func() error { return nil },
		unlinkPlist:  func() error { f.unlinks++; f.plist = upgradeNodeIdentity{}; return nil },
		capture: func(_ string, pid string, active bool) (*stoppingHQ, error) {
			if f.job != active || f.pid != pid {
				return nil, errors.New("unexpected observation")
			}
			return &stoppingHQ{Parent: upgradeNodeIdentity{Inode: 15}, PID: pid}, nil
		},
		clean: func(_ string, s *stoppingHQ, preview bool) error {
			if f.job || s == nil {
				return errors.New("job active or missing evidence")
			}
			return nil
		},
		bootout: func() error { f.stops++; f.job = false; f.pid = ""; return nil },
		readRecord: func(path string, want uninstallEvidence) (*uninstallEvidence, error) {
			raw, e := os.ReadFile(path)
			if errors.Is(e, os.ErrNotExist) {
				return nil, nil
			}
			if e != nil {
				return nil, e
			}
			var r uninstallEvidence
			if json.Unmarshal(raw, &r) != nil || r.Owner != want.Owner || r.PlanID != want.PlanID || r.Digest != want.Digest {
				return nil, errors.New("wrong journal")
			}
			return &r, nil
		},
	}
	return f
}
func (f *uninstallFixture) run(preview bool) (string, error) {
	return removeReviewedHQ(f.dir, f.h, f.endpoint, f.want, preview)
}

func TestHQUninstallLocalTransaction(t *testing.T) {
	for _, active := range []bool{false, true} {
		f := newUninstallFixture(t, active)
		if result, e := f.run(true); e != nil || result != "would-uninstall" {
			t.Fatal(result, e)
		}
		if entries, e := os.ReadDir(f.dir); e != nil || len(entries) != 0 {
			t.Fatal("preview wrote state")
		}
		if result, e := f.run(false); e != nil || result != "uninstalled" {
			t.Fatal(result, e)
		}
		if result, e := f.run(false); e != nil || result != "already-uninstalled" {
			t.Fatal(result, e)
		}
		if f.unlinks != 1 || (active && f.stops != 1) || (!active && f.stops != 0) {
			t.Fatal("unexpected cleanup counts", f.stops, f.unlinks)
		}
		f.job = true
		if _, e := f.run(false); e == nil {
			t.Fatal("old receipt accepted a later job")
		}
	}
}
func TestHQUninstallResumesAndPreservesReplacements(t *testing.T) {
	for _, change := range []string{"unchanged", "new-pid", "new-plist", "another-plan", "changed-endpoint"} {
		t.Run(change, func(t *testing.T) {
			f := newUninstallFixture(t, true)
			bootout := f.h.bootout
			f.h.bootout = func() error { return errors.New("interrupted before bootout") }
			if _, e := f.run(false); e == nil {
				t.Fatal("expected interruption")
			}
			f.h.bootout = bootout
			switch change {
			case "new-pid":
				f.pid = "252"
			case "new-plist":
				f.plist.Inode++
			case "another-plan":
				f.want.PlanID = "plan-20261119T041501Z-beef"
			case "changed-endpoint":
				f.h.capture = func(_ string, pid string, active bool) (*stoppingHQ, error) {
					return &stoppingHQ{PID: pid, Parent: upgradeNodeIdentity{Inode: 15}, Socket: upgradeNodeIdentity{Inode: 70}}, nil
				}
			}
			result, e := f.run(false)
			if change == "unchanged" {
				if e != nil || result != "uninstalled" || f.stops != 1 {
					t.Fatal(result, e)
				}
				return
			}
			if e == nil || f.stops != 0 || f.unlinks != 0 {
				t.Fatal("changed resource was acted on", e)
			}
		})
	}
	f := newUninstallFixture(t, true)
	clean := f.h.clean
	f.h.clean = func(string, *stoppingHQ, bool) error { return errors.New("busy") }
	if _, e := f.run(false); e == nil || f.stops != 1 || f.unlinks != 0 {
		t.Fatal("incorrect handling of unsettled endpoint", e)
	}
	f.h.clean = clean
	if _, e := f.run(false); e != nil || f.stops != 1 || f.unlinks != 1 {
		t.Fatal("retry repeated prior bootout", e)
	}
}
func TestHQUninstallPrivateSavedPlan(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id := "plan-20261119T041500Z-cafe"
	path := filepath.Join(dir, id+".json")
	raw, _ := json.Marshal(Saved{PlanID: id, Plan: Plan{Version: PlanVersion}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := uninstallPlan(state, id, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := uninstallPlan(state, id, uint32(os.Getuid())); err == nil {
		t.Fatal("unprotected plan accepted")
	}
}

func TestHQUninstallAfterPlistRemovalBeforeSync(t *testing.T) {
	f := newUninstallFixture(t, true)
	f.h.syncPlistDir = func() error { return errors.New("interrupted at directory sync") }
	if _, e := f.run(false); e == nil || f.stops != 1 || f.unlinks != 1 {
		t.Fatal(e)
	}
	f.h.syncPlistDir = func() error { return nil }
	if result, e := f.run(false); e != nil || result != "uninstalled" || f.stops != 1 || f.unlinks != 1 {
		t.Fatal(result, e)
	}
}
func TestHQUninstallFindReceiptAfterUpgrade(t *testing.T) {
	old := "plan-20261119T041500Z-cafe"
	newer := "plan-20261119T041501Z-cafe"
	duplicate := "plan-20261119T041502Z-cafe"
	matches := matchingUninstallPlans([]string{duplicate + ".json", old + ".json", newer + ".json", old + ".hq-uninstalled.json", uninstallJournalName}, func(id string) bool { return id == old || id == newer || id == duplicate })
	if len(matches) != 2 || matches[0] != newer || matches[1] != duplicate {
		t.Fatal(matches)
	}
}

func TestHQUninstallOlderKernelPreservesStaleEndpointUntilLaunchdCleanup(t *testing.T) {
	f := newUninstallFixture(t, true)
	f.h.clean = func(string, *stoppingHQ, bool) error { return syscall.EINVAL }
	if _, err := f.run(false); err == nil || !strings.Contains(err.Error(), "kernel") || f.stops != 1 || f.unlinks != 0 {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, uninstallJournalName)); err != nil {
		t.Fatal(err)
	}
	f.h.clean = func(string, *stoppingHQ, bool) error { return nil }
	if result, e := f.run(false); e != nil || result != "uninstalled" || f.stops != 1 {
		t.Fatal(result, e)
	}
}

func TestHQUninstallDiscoveryAfterPlistUnlink(t *testing.T) {
	f := newUninstallFixture(t, true)
	f.h.syncPlistDir = func() error { return errors.New("interrupted before final receipt") }
	if _, e := f.run(false); e == nil || f.plist.Inode != 0 {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(f.dir, uninstallJournalName))
	if e != nil {
		t.Fatal(e)
	}
	lookup := func(id string) (string, error) {
		if id != f.want.PlanID {
			t.Fatal(id)
		}
		return f.want.Digest, nil
	}
	if id, e := resumeUninstallID(raw, f.want.Owner, lookup); e != nil || id != f.want.PlanID {
		t.Fatal(id, e)
	}
	if _, e := resumeUninstallID(raw, "other", lookup); e == nil {
		t.Fatal("cross-owner journal disclosed")
	}
	if _, e := resumeUninstallID(raw, f.want.Owner, func(string) (string, error) { return strings.Repeat("b", 64), nil }); e == nil {
		t.Fatal("mismatched receipt link")
	}
}

func TestHQUninstallRechecksPlistBeforeBootout(t *testing.T) {
	f := newUninstallFixture(t, true)
	reads := 0
	f.h.plist = func() (upgradeNodeIdentity, error) {
		reads++
		value := f.plist
		if reads > 1 {
			value.Inode++
		}
		return value, nil
	}
	if _, e := f.run(false); e == nil || f.stops != 0 || f.unlinks != 0 {
		t.Fatal("acted on replacement plist", e)
	}
}

func TestHQUninstallWaitsForOriginalProcessWithoutSocket(t *testing.T) {
	f := newUninstallFixture(t, true)
	f.h.waitPID = func(pid string) error {
		if pid != "124" {
			t.Fatal("wrong process observation")
		}
		return errors.New("still exiting")
	}
	if _, e := f.run(false); e == nil || f.stops != 1 || f.unlinks != 0 {
		t.Fatal("completed while process was still present", e)
	}
	f.h.waitPID = func(string) error { return nil }
	if result, e := f.run(false); e != nil || result != "uninstalled" || f.stops != 1 {
		t.Fatal(result, e)
	}
}
