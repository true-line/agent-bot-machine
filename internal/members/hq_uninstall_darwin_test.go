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
func TestHQUninstallRetiresReceiptForAlreadyAbsentService(t *testing.T) {
	f := newUninstallFixture(t, false)
	f.plist = upgradeNodeIdentity{}
	if result, err := f.run(true); err != nil || result != "already-absent" {
		t.Fatal(result, err)
	}
	if entries, err := os.ReadDir(f.dir); err != nil || len(entries) != 0 {
		t.Fatal("preview wrote an uninstall record", entries, err)
	}
	if err := os.WriteFile(f.endpoint, []byte("unexpected entry"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(false); err == nil {
		t.Fatal("unverified endpoint was accepted")
	}
	if err := os.Remove(f.endpoint); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(f.dir); err != nil || len(entries) != 0 {
		t.Fatal("refusal consumed the receipt", entries, err)
	}
	if result, err := f.run(false); err != nil || result != "already-absent" {
		t.Fatal(result, err)
	}
	if result, err := f.run(false); err != nil || result != "already-uninstalled" {
		t.Fatal(result, err)
	}
	// The same release is installed again using a new plan. A retry of the
	// earlier explicit removal must leave that installation alone.
	f.plist = upgradeNodeIdentity{Inode: 22}
	f.job, f.pid = true, "125"
	if _, err := f.run(false); err == nil || f.stops != 0 || f.unlinks != 0 || !f.job {
		t.Fatal("the old plan acted on the new installation", f.stops, f.unlinks, err)
	}
	newID := "plan-20261120T101500Z-beef"
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{f.want.PlanID + ".json", newID + ".json"}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if got := matchingUninstallPlans(names, func(string) bool { return true }); len(got) != 1 || got[0] != newID {
		t.Fatal("expected only the new receipt in discovery", got)
	}
	f.want.PlanID, f.want.Digest = newID, strings.Repeat("b", 64)
	if result, err := f.run(false); err != nil || result != "uninstalled" || f.stops != 1 || f.unlinks != 1 {
		t.Fatal(result, f.stops, f.unlinks, err)
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

func TestHQUninstallAuditTailAfterCLIReinstall(t *testing.T) {
	previous := newUninstallFixture(t, true)
	previous.h.syncPlistDir = func() error { return errors.New("interrupted after last public file was removed") }
	if _, e := previous.run(false); e == nil || previous.job || previous.plist.Inode != 0 {
		t.Fatal("incorrect interruption state", e)
	}
	// A fresh command has no process-local state from the old binary. After
	// reinstallation it sees only retained audit files and absent resources.
	fresh := newUninstallFixture(t, false)
	fresh.dir = previous.dir
	fresh.endpoint = previous.endpoint
	fresh.plist = upgradeNodeIdentity{}
	if result, e := fresh.run(false); e != nil || result != "uninstalled" || fresh.stops != 0 || fresh.unlinks != 0 {
		t.Fatal(result, e)
	}
}

func TestUninstallDetachedSocketRequiresUnchangedStoppedJob(t *testing.T) {
	for _, scenario := range []string{"closed", "bound", "listening", "permission changed", "job present", "replacement", "parent replaced"} {
		t.Run(scenario, func(t *testing.T) {
			base, err := os.MkdirTemp("/private/tmp", "hq-rm.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(base) })
			dir := filepath.Join(base, "runtime")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			parent, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			name := "owner.sock"
			path := filepath.Join(dir, name)
			bind := func() int {
				t.Helper()
				fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path + ".original"}); err != nil {
					syscall.Close(fd)
					t.Fatal(err)
				}
				if err := os.Rename(path+".original", path); err != nil {
					syscall.Close(fd)
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0666); err != nil {
					syscall.Close(fd)
					t.Fatal(err)
				}
				return fd
			}
			fd := bind()
			if scenario == "listening" {
				if err := syscall.Listen(fd, 1); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "listening" || scenario == "bound" {
				defer syscall.Close(fd)
			} else {
				syscall.Close(fd)
			}
			recorded, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			confirmed := false
			check := func() error {
				confirmed = true
				switch scenario {
				case "job present":
					return errors.New("reviewed job is still registered")
				case "replacement":
					if err := os.Rename(path, path+".old"); err != nil {
						t.Fatal(err)
					}
					syscall.Close(bind())
				case "permission changed":
					return os.Chmod(path, 0600)
				case "parent replaced":
					if err := os.Rename(dir, dir+".old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					syscall.Close(bind())
				}
				return nil
			}
			err = unlinkDetachedUninstallSocket(parent, name, recorded, uint32(os.Getuid()), check)
			after, statErr := os.Lstat(path)
			if scenario == "closed" {
				if err != nil || !confirmed || !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("closed removal: %v, confirmation %v, stat %v", err, confirmed, statErr)
				}
				return
			}
			if err == nil || statErr != nil {
				t.Fatalf("refused removal: %v, stat %v", err, statErr)
			}
			if (scenario == "replacement" || scenario == "parent replaced") == os.SameFile(recorded, after) {
				t.Fatal("incorrect preserved identity")
			}
		})
	}
}

// v0.12.4 built and encoded these synthetic first-install files. Its writer
// persisted the plan and receipt without creating the later service lock.
func TestUninstallV0124ServiceReceipt(t *testing.T) {
	const id = "plan-20261020T010203Z-cafe"
	legacy := filepath.Join("testdata", "hq-v0.12.4")
	state := t.TempDir()
	plans := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(plans, 0700); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(legacy, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plans, id+".json"), saved, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := uninstallPlan(state, id, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	record, err := priorLaunchRecord(p, "operator")
	if err != nil || record.RuntimeDir != nil || record.OwnerUID != 501 ||
		record.Plist != renderLaunchPlist(record.Service, 501, "operator", launchControlV1) {
		t.Fatal("lost compatibility with the released v1 service plan", err)
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := os.ReadFile(filepath.Join(legacy, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("/private"+DarwinReceiptsDir, id+".json")
	host := emptyHost()
	for _, parent := range pathAncestry(filepath.Dir(path)) {
		host.entries[parent] = Entry{Dir: true, Owner: "root", Mode: 0755}
	}
	host.entries[path] = Entry{Regular: true, Owner: "root", Mode: 0600}
	for _, result := range []string{"applied", "failed", "started"} {
		host.files[path] = strings.Replace(string(receipt), `"applied"`, `"`+result+`"`, 1)
		err := receiptForUpgrade(host, id, digest, "operator", func([]string) error { return nil })
		if (err == nil) != (result == "applied") {
			t.Fatalf("release receipt %s: %v", result, err)
		}
	}
}

func TestUninstallV0124ResourceLock(t *testing.T) {
	f := newUninstallFixture(t, true)
	read := syscall.LOCK_SH | syscall.LOCK_NB
	write := syscall.LOCK_EX | syscall.LOCK_NB
	preview := func() error {
		result, err := f.run(true)
		if err == nil && result != "would-uninstall" {
			t.Fatalf("unexpected preview %q", result)
		}
		return err
	}
	if err := withHQResourceLock(f.dir, read, preview); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(f.dir); err != nil || len(entries) != 0 {
		t.Fatalf("preview wrote state in a legacy directory: %v, %v", entries, err)
	}
	// The legacy reader must discard a snapshot overlapping the first new
	// writer. Every later contender uses the permanent lock created here.
	err := withHQResourceLock(f.dir, read, func() error {
		return withHQResourceLock(f.dir, write, func() error {
			for _, mode := range []int{read, write} {
				err := withHQResourceLock(f.dir, mode, func() error {
					t.Fatal("ran alongside the first writer")
					return nil
				})
				if !errors.Is(err, syscall.EWOULDBLOCK) {
					t.Fatalf("expected held lock, got %v", err)
				}
			}
			return nil
		})
	})
	if err == nil || !strings.Contains(err.Error(), "retry") {
		t.Fatal("accepted overlapping legacy inspection", err)
	}
	if err := withHQResourceLock(f.dir, read, preview); err != nil {
		t.Fatal(err)
	}
	if err := withHQResourceLock(f.dir, write, func() error {
		result, err := f.run(false)
		if err == nil && result != "uninstalled" {
			t.Fatalf("unexpected removal %q", result)
		}
		return err
	}); err != nil || f.stops != 1 {
		t.Fatal("legacy install did not complete removal", err)
	}
}

type uninstallLookupFailure struct{ *fakeHost }

func (h uninstallLookupFailure) Lstat(string) (Entry, bool, error) {
	return Entry{}, false, os.ErrPermission
}

func TestHQUninstallReceiptDiscoveryBeforeFirstApply(t *testing.T) {
	base := filepath.Join("/private", DarwinReceiptsDir)
	db := "/private/var/db"
	trusted := Entry{Owner: "root", Dir: true, Mode: 0755}
	h := bare()
	for _, dir := range pathAncestry(db) {
		h.entries[dir] = trusted
	}
	for _, last := range []string{db, filepath.Dir(filepath.Dir(base)), filepath.Dir(base), base} {
		h.entries[last] = trusted
		var checked []string
		got, err := hqUninstallReceiptsPresent(h, func(paths []string) error {
			checked = paths
			return nil
		})
		if err != nil || got != (last == base) || len(checked) == 0 || checked[0] != last || checked[len(checked)-1] != "/" {
			t.Fatalf("at %s: present=%t ACL paths=%v error=%v", last, got, checked, err)
		}
	}
	delete(h.entries, base)
	for _, unsafe := range []Entry{{Owner: "root"}, {Owner: "other", Dir: true}, {Owner: "root", Dir: true, Mode: 0777}} {
		h.entries[filepath.Dir(base)] = unsafe
		if _, err := hqUninstallReceiptsPresent(h, func([]string) error { return nil }); err == nil {
			t.Fatal("absent leaf concealed an unsafe parent")
		}
	}
	h.entries[filepath.Dir(base)] = trusted
	denied := func([]string) error { return os.ErrPermission }
	if _, err := hqUninstallReceiptsPresent(h, denied); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("ACL inspection error lost: %v", err)
	}
	if _, err := hqUninstallReceiptsPresent(uninstallLookupFailure{h}, func([]string) error { return nil }); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("metadata inspection error lost: %v", err)
	}
}
