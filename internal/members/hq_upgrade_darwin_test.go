package members

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWaitForApprovedHQPID(t *testing.T) {
	calls := 0
	pid, err := waitForApprovedHQPID(time.Second, func() (bool, string, error) {
		calls++
		if calls == 1 {
			return true, "", nil
		}
		return true, "123", nil
	})
	if err != nil || pid != "123" || calls != 2 {
		t.Fatalf("approved pending process: pid %q, calls %d, error %v", pid, calls, err)
	}
	for _, tc := range []struct {
		name    string
		active  bool
		pid     string
		err     error
		message string
	}{
		{"changed job", false, "", nil, "approved HQ job"},
		{"inspection failure", true, "", errors.New("private detail"), "approved HQ job"},
		{"invalid pid", true, "not-a-pid", nil, "running HQ process"},
		{"missing pid at deadline", true, "", nil, "running HQ process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := waitForApprovedHQPID(0, func() (bool, string, error) {
				return tc.active, tc.pid, tc.err
			})
			if got != "" || err == nil || !strings.Contains(err.Error(), tc.message) || strings.Contains(err.Error(), "private detail") {
				t.Fatalf("invalid process admitted or leaked detail: pid %q, error %v", got, err)
			}
		})
	}
}

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
	bootstrapGuard                                               func(func() error) error
	activePlist, installedPlist, stagedPlist, phaseName, outcome string
	wrongStatus                                                  string
	starts, stops                                                int
	unknownEndpoint                                              bool
	pending                                                      *upgradeJournal
	drainOnObservation                                           bool
	retryAbsent                                                  bool
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
func (m *testUpgradeHost) retryRecordedStop(r launchRecord, phase string) error {
	return m.pending.retryUnconfirmedBootout(phase, func(absent bool) error {
		m.retryAbsent = absent
		return m.stop(r, phase)
	})
}
func (m *testUpgradeHost) clearStoppedEndpoint() error {
	if m.activePlist != "" {
		if !m.drainOnObservation {
			return errHQJobDraining
		}
		m.activePlist = ""
	}
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
	return submitHQBootstrap(m.bootstrapGuard, func() error {
		m.activePlist = r.Plist
		m.starts++
		return nil
	})
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

func TestPendingHQStopCannotCompleteOnResponsivePriorProcess(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"}, Next: launchRecord{Plist: "new"}}
	for _, tc := range []struct {
		name, phase, result          string
		accepted, drains, leafAbsent bool
		stops, starts                int
	}{
		{"before predecessor bootout", "stopping-previous", "started", false, false, false, 1, 1},
		{"predecessor drains before acceptance was saved", "stopping-previous", "started", false, true, false, 0, 1},
		{"accepted stop still drains", "stopping-previous", "started", true, false, false, 0, 0},
		{"accepted stop completes", "stopping-previous", "started", true, true, false, 0, 1},
		{"older failed receipt still has draining predecessor", "stopping-previous", "failed", true, false, false, 0, 0},
		{"older failed receipt restores after stop", "stopping-previous", "failed", true, true, false, 0, 1},
		{"before candidate bootout without published socket", "stopping-next", "started", false, false, true, 1, 1},
		{"accepted candidate stop never reissued", "stopping-next", "started", true, false, true, 0, 0},
		{"candidate drains without published socket", "stopping-next", "started", true, true, true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, stage := "old", "new"
			if tc.phase == "stopping-next" {
				target, stage = stage, target
			}
			evidence := &stoppingHQ{PID: "319"}
			if !tc.leafAbsent {
				evidence.Socket.Inode = 83
			}
			m := &testUpgradeHost{activePlist: target, installedPlist: target, stagedPlist: stage, phaseName: tc.phase,
				pending:            &upgradeJournal{Phase: tc.phase, Stopping: evidence, BootoutAccepted: tc.accepted},
				drainOnObservation: tc.drains}
			err := reconcileUpgrade(m, rec, tc.result, tc.phase)
			if m.stops != tc.stops || m.starts != tc.starts || tc.stops > 0 && m.retryAbsent != tc.leafAbsent {
				t.Fatalf("stops=%d starts=%d absent=%t err=%v", m.stops, m.starts, m.retryAbsent, err)
			}
			if tc.starts == 0 {
				if !errors.Is(err, errHQJobDraining) || m.outcome != "" || m.phaseName != tc.phase {
					t.Fatalf("completed unresolved stop: %+v %v", m, err)
				}
			} else if m.activePlist != "old" || m.outcome != "failed" || m.phaseName != "starting-previous" {
				t.Fatalf("incomplete restoration: %+v %v", m, err)
			}
		})
	}
}

func TestUpgradePersistsBootoutAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	j := &upgradeJournal{Phase: "starting-next"}
	e := &stoppingHQ{Parent: upgradeNodeIdentity{Inode: 44}, PID: "319"}
	if err := j.recordBootout(path, "stopping-next", e, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var resumed upgradeJournal
	if err = json.Unmarshal(data, &resumed); err != nil || !resumed.BootoutAccepted || resumed.Stopping == nil || *resumed.Stopping != *e {
		t.Fatalf("lost accepted stop: %v", err)
	}
	stop := func() error { t.Fatal("repeated accepted bootout"); return nil }
	if !errors.Is(resumed.recordBootout(path, "stopping-next", e, stop), errHQJobDraining) {
		t.Fatal("accepted stop lost")
	}
	// A retry from the original apply may observe progress but cannot submit
	// another stop, including when the command's result remained uncertain.
	j.BootoutAccepted = false
	if err = j.stop(launchRecord{}, "stopping-next"); err == nil {
		t.Fatal("repeated stop in ordinary apply")
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

func TestHQBootstrapGuardCoversOnlySubmission(t *testing.T) {
	for _, tc := range []struct {
		name            string
		paired, revoked bool
	}{{"first install", false, false}, {"paired candidate", true, false}, {"revoked candidate", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			held, launched := false, false
			var guard func(func() error) error
			if tc.paired {
				guard = func(run func() error) error {
					if tc.revoked {
						return errors.New("revoked")
					}
					held = true
					defer func() { held = false }()
					return run()
				}
			}
			err := submitHQBootstrap(guard, func() error {
				if held != tc.paired {
					t.Fatal("wrong launch lock scope")
				}
				launched = true
				return nil
			})
			if (err != nil) != tc.revoked || launched == tc.revoked || held {
				t.Fatalf("submission: err=%v launched=%v lock held at readiness=%v", err, launched, held)
			}
		})
	}
}

func TestHQUpgradeRevokedBeforeLaunchPreservesUnfinishedReceipt(t *testing.T) {
	rec := launchUpgrade{Previous: launchRecord{Plist: "old"}, Next: launchRecord{Plist: "new"}}
	host := &testUpgradeHost{activePlist: "old", installedPlist: "old", stagedPlist: "new"}
	var attempts []string
	host.bootstrapGuard = func(func() error) error {
		attempts = append(attempts, host.installedPlist)
		return errors.New("pair revoked during preflight")
	}
	if err := performUpgrade(host, rec); err == nil || host.starts != 0 || host.activePlist != "" || host.outcome != "" {
		t.Fatalf("revoked upgrade: %v, host=%+v", err, host)
	}
	if len(attempts) != 2 || attempts[0] != "new" || attempts[1] != "old" {
		t.Fatalf("expected candidate and rollback launch guards; got %v", attempts)
	}
}

func TestUpgradeCommitsAppliedReceiptUnderCurrentPair(t *testing.T) {
	started := Receipt{PlanID: "plan-20261110T040000Z-abcd", Result: "started"}
	approval := Approval{PlanID: started.PlanID, Purpose: UpgradePurpose}
	revoked := errors.New("pair revoked after the status probe")
	for _, live := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "receipt.json")
		if err := os.WriteFile(path, encodeReceipt(started), 0600); err != nil {
			t.Fatal(err)
		}
		read := func() Receipt {
			t.Helper()
			b, err := os.ReadFile(path)
			var r Receipt
			if err != nil || json.Unmarshal(b, &r) != nil {
				t.Fatal("cannot read test receipt", err)
			}
			return r
		}
		guarded := false
		j := upgradeJournal{Approval: approval, pair: func(a Approval, publish func() error) error {
			if a != approval || publish == nil || read().Result != "started" {
				t.Fatal("expected receipt publication inside the current approval guard")
			}
			guarded = true
			if !live {
				return revoked
			}
			if err := publish(); err != nil {
				return err
			}
			if r := read(); r.Result != "applied" || r.Upgrade == nil || r.Upgrade.Approval != approval {
				t.Fatal("applied receipt was not committed while the guard was held")
			}
			return nil
		}}
		err := j.commitReceipt(path, started, true)
		if !guarded || (live && err != nil) || (!live && (!errors.Is(err, revoked) || read().Result != "started")) {
			t.Fatalf("live=%t: guarded=%t, result=%s, err=%v", live, guarded, read().Result, err)
		}
	}
}
