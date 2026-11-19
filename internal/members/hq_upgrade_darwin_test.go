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

func upgradeWorld(t *testing.T) (Input, *fakeHost) {
	t.Helper()
	h := emptyHost()
	base := t.TempDir()
	const owner = "operator"
	const uid = 331
	h.accounts[owner] = Account{Name: owner, UID: 501}
	h.accounts[DarwinHQAccount] = Account{Name: DarwinHQAccount, UID: uid, GID: uid, Group: DarwinHQAccount, PrimaryUsers: []string{DarwinHQAccount}, Groups: []string{DarwinHQAccount}, DarwinRole: darwinHQRoleName, Home: HQHome(PlatformDarwin, DarwinHQAccount), Shell: DarwinNoLoginShell}
	h.entries[HQHome(PlatformDarwin, DarwinHQAccount)] = Entry{Dir: true, Owner: DarwinHQAccount, Group: DarwinHQAccount, Mode: 0700}
	node := filepath.Join(base, "node")
	old := makeTestHQRelease(t, h, filepath.Join(base, "old"), launchControlV2, node, "// previous release\n")
	next := makeTestHQRelease(t, h, filepath.Join(base, "next"), launchControlV2, node, "// updated release\n")
	in := Input{Platform: PlatformDarwin, HQAccount: DarwinHQAccount, HQService: old, Invoker: owner}
	blank := func([]string) error { return nil }
	in.upgradeObservation = &upgradeObservation{blank, func(s HQService, who string) (bool, string, error) {
		if s != *old || who != owner {
			return false, "", errors.New("unknown job")
		}
		return true, "123", nil
	}}
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	id := "plan-20261119T041500Z-cafe"
	rec, err := priorLaunchRecord(p, owner)
	if err != nil {
		t.Fatal(err)
	}
	h.entries[launchPlist] = Entry{Regular: true, Owner: "root", Group: "wheel", Mode: 0644}
	h.files[launchPlist] = rec.Plist
	h.entries[launchRuntimeDir] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join("/private"+DarwinReceiptsDir, id+".json")
	for _, p := range pathAncestry(filepath.Dir(receipt)) {
		h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	}
	h.entries[receipt] = Entry{Regular: true, Owner: "root", Group: "wheel", Mode: 0644}
	h.files[receipt] = string(encodeReceipt(Receipt{PlanID: id, PlanDigest: digest, Owner: owner, HQAccount: DarwinHQAccount, Dir: DarwinDir, Result: "applied", StartedAt: "2026-11-19T04:15:00Z", FinishedAt: "2026-11-19T04:16:00Z"}))
	in.UpgradeFrom = &priorServicePlan{id, p}
	in.HQService = next
	return in, h
}
func TestDarwinHQUpgradeBuild(t *testing.T) {
	in, h := upgradeWorld(t)
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 2 || p.Steps[0].Action != ActionNone || p.Steps[1].Action != upgradeAction || p.Changes() != 1 {
		t.Fatal("wrong upgrade steps")
	}
	var rec launchUpgrade
	if err = json.Unmarshal([]byte(p.Steps[1].Content), &rec); err != nil {
		t.Fatal(err)
	}
	d, _ := in.UpgradeFrom.Plan.Digest()
	if rec.PreviousDigest != d || rec.PreviousID != in.UpgradeFrom.ID || rec.Next.Service != *in.HQService || rec.Previous.Service.ArtifactSHA256 == rec.Next.Service.ArtifactSHA256 || rec.Previous.RuntimeDir.Action != ActionCreate || rec.Next.RuntimeDir.Action != ActionNone {
		t.Fatal("incomplete transition approval")
	}
	again, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := again.Digest()
	b, _ := p.Digest()
	if a != b {
		t.Fatal("unstable plan")
	}
	if _, err := priorLaunchRecord(p, in.Invoker); err != nil {
		t.Fatal(err)
	}
}
func TestDarwinHQUpgradeRequiresActivePredecessor(t *testing.T) {
	for _, scenario := range []string{"ordinary plan", "invalid prior ID", "active job gone", "plist changed", "new account requested", "same release"} {
		t.Run(scenario, func(t *testing.T) {
			in, h := upgradeWorld(t)
			switch scenario {
			case "ordinary plan":
				in.UpgradeFrom = nil
			case "invalid prior ID":
				in.UpgradeFrom.ID = "invalid"
			case "active job gone":
				in.upgradeObservation.loaded = func(HQService, string) (bool, string, error) { return false, "", nil }
			case "plist changed":
				h.files[launchPlist] += " "
			case "new account requested":
				in.Members = []string{"some-harness"}
			case "same release":
				rec, _ := priorLaunchRecord(in.UpgradeFrom.Plan, in.Invoker)
				in.HQService = &rec.Service
			}
			if _, err := Build(in, h); err == nil {
				t.Fatal("accepted", scenario)
			}
		})
	}
}

type testUpgradeHost struct {
	activePlist, installedPlist, stagedPlist, phaseName, outcome string
	wrongStatus                                                  string
	starts, stops                                                int
	unknownEndpoint                                              bool
}

func (m *testUpgradeHost) active(r launchRecord) (bool, error) {
	if m.activePlist == "" {
		return false, nil
	}
	if m.activePlist != r.Plist {
		return false, errors.New("different job")
	}
	return true, nil
}
func (m *testUpgradeHost) installed(r launchRecord) error {
	if m.installedPlist != r.Plist {
		return errors.New("different plist")
	}
	return nil
}
func (m *testUpgradeHost) phase(s string) error { m.phaseName = s; return nil }
func (m *testUpgradeHost) stop(r launchRecord, s string) error {
	if m.activePlist != r.Plist || m.installedPlist != r.Plist {
		return errors.New("unverified job")
	}
	m.phaseName = s
	m.activePlist = ""
	m.stops++
	return nil
}
func (m *testUpgradeHost) clearStoppedEndpoint() error {
	if m.unknownEndpoint {
		return errors.New("unverified endpoint")
	}
	return nil
}
func (m *testUpgradeHost) swap(old, next launchRecord) error {
	if m.activePlist != "" || m.installedPlist != old.Plist || m.stagedPlist != next.Plist {
		return errors.New("changed release")
	}
	m.installedPlist, m.stagedPlist = m.stagedPlist, m.installedPlist
	return nil
}
func (m *testUpgradeHost) start(r launchRecord) error {
	if m.unknownEndpoint || m.activePlist != "" || m.installedPlist != r.Plist {
		return errors.New("unverified activation")
	}
	m.activePlist = r.Plist
	m.starts++
	return nil
}
func (m *testUpgradeHost) verify(r launchRecord) error {
	if m.activePlist != r.Plist || m.installedPlist != r.Plist || m.wrongStatus == r.Plist {
		return errors.New("status refused")
	}
	return nil
}
func (m *testUpgradeHost) finish(ok bool) error {
	if ok {
		m.outcome = "applied"
		return nil
	}
	m.outcome = "failed"
	return errors.New("verified rollback")
}

func TestHQUpgradeSwitchAndReconciliation(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"}, Next: launchRecord{Plist: "new"}}
	for _, tc := range []struct {
		name, phase, active, plist, stage, result, status string
		orphan                                            bool
		wantActive, wantResult                            string
		starts, stops                                     int
	}{
		{"fresh apply", "", "old", "old", "new", "started", "", false, "new", "applied", 1, 1},
		{"new status refused", "", "old", "old", "new", "started", "new", false, "old", "failed", 2, 2},
		{"before first stop", "prepared", "old", "old", "new", "started", "", false, "old", "failed", 0, 0},
		{"stopped before exchange", "stopping-previous", "", "old", "new", "started", "", false, "old", "failed", 1, 0},
		{"stopped after exchange", "switching", "", "new", "old", "started", "", false, "old", "failed", 1, 0},
		{"unverified orphan", "stopping-previous", "", "old", "new", "started", "", true, "", "", 0, 0},
		{"new active before commit", "starting-next", "new", "new", "old", "started", "", false, "new", "applied", 0, 0},
		{"candidate failed on restart", "starting-next", "new", "new", "old", "started", "new", false, "old", "failed", 1, 1},
		{"rollback resumed", "restoring-previous", "", "new", "old", "started", "", false, "old", "failed", 1, 0},
		{"restored old already running", "starting-previous", "old", "old", "new", "started", "", false, "old", "failed", 0, 0},
		{"unexpected job", "starting-next", "foreign", "new", "old", "started", "", false, "foreign", "", 0, 0},
		{"unexpected pending plist", "switching", "", "foreign", "old", "started", "", false, "", "", 0, 0},
		{"unknown phase", "unknown", "new", "new", "old", "started", "", false, "new", "", 0, 0},
		{"completed apply awaiting cleanup", "starting-next", "new", "new", "old", "applied", "", false, "new", "applied", 0, 0},
		{"completed rollback awaiting cleanup", "starting-previous", "old", "old", "new", "failed", "", false, "old", "failed", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &testUpgradeHost{activePlist: tc.active, installedPlist: tc.plist, stagedPlist: tc.stage, wrongStatus: tc.status, unknownEndpoint: tc.orphan}
			var err error
			if tc.phase == "" {
				err = performUpgrade(m, rec)
			} else {
				err = reconcileUpgrade(m, rec, tc.result, tc.phase)
			}
			if (err == nil) != (tc.wantResult == "applied") || m.activePlist != tc.wantActive || m.outcome != tc.wantResult || m.starts != tc.starts || m.stops != tc.stops {
				t.Fatalf("err=%v state=%+v", err, m)
			}
		})
	}
}

func TestUpgradeRecordPublicationAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record")
	for _, step := range []struct {
		body               string
		exclusive, success bool
		want               string
	}{{"prepared", true, true, "prepared"}, {"other", true, false, "prepared"}, {"stopping", false, true, "stopping"}} {
		e := writeUpgradeFile(path, []byte(step.body), 0600, step.exclusive)
		b, read := os.ReadFile(path)
		st, se := os.Lstat(path)
		if (e == nil) != step.success || read != nil || string(b) != step.want || se != nil || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatal("incomplete/exclusive publication", e, read, se)
		}
	}
}

func TestHQUpgradeDarwinKernel(t *testing.T) {
	if supportsGuardedUpgrade("24.6.0") || supportsGuardedUpgrade("unknown") || !supportsGuardedUpgrade("25.0.0") {
		t.Fatal("wrong guarded socket support")
	}
}

func TestHQUpgradePlansWithoutRootReceiptAndApplyChecksIt(t *testing.T) {
	for _, tc := range []string{"exact", "missing", "writable", "changed plan", "failed receipt"} {
		t.Run(tc, func(t *testing.T) {
			in, h := upgradeWorld(t)
			path := filepath.Join("/private"+DarwinReceiptsDir, in.UpgradeFrom.ID+".json")
			switch tc {
			case "missing":
				delete(h.entries, path)
			case "writable":
				entry := h.entries[path]
				entry.Mode = 0666
				h.entries[path] = entry
			case "changed plan":
				in.UpgradeFrom.Plan.Steps[1].Detail += " changed"
			case "failed receipt":
				h.files[path] = strings.Replace(h.files[path], "applied", "failed", 1)
			}
			if _, err := Build(in, h); err != nil {
				t.Fatal("unprivileged planning must not require access to the root receipt:", err)
			}
			digest, err := in.UpgradeFrom.Plan.Digest()
			if err != nil {
				t.Fatal(err)
			}
			err = receiptForUpgrade(h, in.UpgradeFrom.ID, digest, in.Invoker, in.upgradeObservation.acl)
			if (err == nil) != (tc == "exact") {
				t.Fatalf("privileged receipt verification: %v", err)
			}
		})
	}
}
