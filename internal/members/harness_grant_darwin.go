package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// No Darwin adapter qualification verifier or signed native adapter qualification
// is available yet. A digest of an interpreter does not qualify its
// script, modules, or fixed arguments. Plan review remains available.
func qualifiedHarnessAdapter(a HarnessAdapter) error {
	return fmt.Errorf("no verified Darwin adapter qualification binds %s to its executable and arguments", a.ID)
}

type grantFile struct {
	path   string
	mode   os.FileMode
	digest string
	data   []byte
}
type harnessLedger struct {
	PlanID  string                `json:"plan_id"`
	Digest  string                `json:"digest"`
	Owner   string                `json:"owner"`
	Purpose string                `json:"purpose"`
	Pair    string                `json:"pair_commitment"`
	Files   []upgradeNodeIdentity `json:"files"`
}

func (f grantFile) node(path string) (upgradeNodeIdentity, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return upgradeNodeIdentity{}, e
	}
	stat := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode() != f.mode || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || (os.Geteuid() == 0 && stat.Gid != 0) {
		return upgradeNodeIdentity{}, errors.New("preserving a changed harness installation file")
	}
	if err := checkDarwinACLs([]string{path}); err != nil {
		return upgradeNodeIdentity{}, err
	}
	fd, e := openPinnedFile(path, f.digest)
	if e != nil {
		return upgradeNodeIdentity{}, e
	}
	defer fd.Close()
	checked, e := fd.Stat()
	if e != nil || !os.SameFile(st, checked) {
		return upgradeNodeIdentity{}, errors.New("harness installation file changed")
	}
	return upgradeNode(st), nil
}
func (f grantFile) stage(id string) string {
	return filepath.Join(filepath.Dir(f.path), ".harness-"+id+"-"+filepath.Base(f.path))
}

// Recheck the original live pairing and the exact approval window inside
// its read lock at each durable privilege transition. Artifact scans and
// external status commands run outside this callback.
type harnessBoundary func(func() error) error

func harnessAuthority(a Approval, guard upgradePairGuard, now func() time.Time) harnessBoundary {
	return func(commit func() error) error {
		if guard == nil {
			return errors.New("harness pairing verifier unavailable")
		}
		return guard(a, func() error {
			start, err := time.Parse(approvalTime, a.ApprovedAt)
			end, endErr := time.Parse(approvalTime, a.ExpiresAt)
			t := now()
			if err != nil || endErr != nil || end.Sub(start) != ApprovalTTL || t.Before(start) || !t.Before(end) {
				return errors.New("harness approval is outside its validity window")
			}
			if commit == nil {
				return nil
			}
			return commit()
		})
	}
}

func installGrantFiles(files []grantFile, ledger harnessLedger, ledgerPath string, validate func(string) error, verifyActive func() error, authorize harnessBoundary, finish func() error) error {
	// Staging names live only in the authenticated fixed directories. Preserve
	// occupied final names, even identical bytes from a different installation.
	if _, e := os.Lstat(ledgerPath); errors.Is(e, os.ErrNotExist) {
		for _, f := range files {
			if _, e := os.Lstat(f.path); !errors.Is(e, os.ErrNotExist) {
				return errors.New("an installed harness grant file already exists or cannot be inspected")
			}
		}
		for _, f := range files {
			stage := f.stage(ledger.PlanID)
			if _, e := os.Lstat(stage); errors.Is(e, os.ErrNotExist) {
				if e = writeUpgradeFile(stage, f.data, f.mode, true); e != nil {
					return e
				}
			}
			node, e := f.node(stage)
			if e != nil {
				return e
			}
			ledger.Files = append(ledger.Files, node)
		}
		if err := validate(files[len(files)-1].stage(ledger.PlanID)); err != nil {
			return err
		}
		raw, e := json.Marshal(ledger)
		if e != nil {
			return e
		}
		if e = writeUpgradeFile(ledgerPath, raw, 0600, true); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	original, e := readHarnessLedger(ledgerPath, ledger)
	if e != nil {
		return e
	}
	// The target-UID launcher requires the final policy path. Keep that
	// file staged through sudo's check and the durable root receipt.
	policy := files[2]
	if _, err := os.Lstat(policy.path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unfinished harness installation already has a public policy")
	}
	for _, i := range []int{0, 1, 3} {
		f := files[i]
		node, err := f.node(f.path)
		if err == nil {
			if node != original.Files[i] {
				return errors.New("preserving a replaced harness installation")
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		stage := f.stage(ledger.PlanID)
		node, err = f.node(stage)
		if err != nil || node != original.Files[i] {
			return errors.New("staged harness installation no longer matches its receipt")
		}
		publish := func() error { return unix.RenamexNp(stage, f.path, unix.RENAME_EXCL) }
		if i == len(files)-1 {
			err = authorize(publish)
		} else {
			err = publish()
		}
		if err != nil {
			return err
		}
		if err = syncUpgradeDir(filepath.Dir(f.path)); err != nil {
			return err
		}
	}
	// An earlier attempt can already have published the exact rule. The
	// affirmative receipt is still a separate privileged decision.
	err := verifyActive()
	if err == nil {
		// Confirm the original staged policy immediately before committing.
		if node, e := policy.node(policy.stage(original.PlanID)); e != nil || node != original.Files[2] {
			err = errors.New("harness policy no longer matches its staging receipt")
		} else {
			err = authorize(finish)
			if err == nil {
				// Receipt sync may block while revocation or expiry takes effect.
				return authorize(func() error { return publishHarnessPolicy(policy, original.PlanID) })
			}
			if errors.Is(err, errHarnessReceiptVisible) {
				// A retry verifies the completed receipt and original file identities
				// before making a still-staged policy available to the launcher.
				return err
			}
		}
	}
	rule := files[len(files)-1]
	node, observed := rule.node(rule.path)
	if observed != nil || node != original.Files[len(files)-1] {
		return errors.Join(err, errors.New("preserving an unrecognized harness rule"))
	}
	if e := unix.RenamexNp(rule.path, rule.stage(ledger.PlanID), unix.RENAME_EXCL); e != nil {
		return errors.Join(err, e)
	}
	return errors.Join(err, syncUpgradeDir(filepath.Dir(rule.path)))
}

// An atomic rename can succeed before the parent directory sync fails.
// Keep an already visible exact receipt and its verified authorization together.
// The caller still reports the sync error.
var errHarnessReceiptVisible = errors.New("harness receipt is visible but its durability is unconfirmed")

func finishHarnessReceipt(path string, receipt Receipt) error {
	receipt.Result = "applied"
	receipt.FinishedAt = time.Now().UTC().Format(approvalTime)
	want := encodeReceipt(receipt)
	if err := writeUpgradeFile(path, want, 0600, false); err != nil {
		current, readErr := readProtectedUpgradeFile(path)
		if readErr == nil && bytes.Equal(current, want) {
			return errors.Join(err, errHarnessReceiptVisible)
		}
		return err
	}
	return nil
}

func publishHarnessPolicy(policy grantFile, planID string) error {
	if err := unix.RenamexNp(policy.stage(planID), policy.path, unix.RENAME_EXCL); err != nil {
		return err
	}
	return syncUpgradeDir(filepath.Dir(policy.path))
}

// A crash after receipt sync and before policy publication leaves a closed
// runtime. Reopen only from the exact protected receipt and original staged inode.
func completeInstalledGrant(files []grantFile, ledger harnessLedger, receiptDir string, check func() error, authorize harnessBoundary) error {
	pending := false
	for i, f := range files {
		node, err := f.node(f.path)
		if i == 2 && errors.Is(err, os.ErrNotExist) {
			pending = true
			node, err = f.node(f.stage(ledger.PlanID))
		}
		if err != nil || node != ledger.Files[i] {
			return errors.New("completed harness receipt no longer matches its files")
		}
	}
	if err := check(); err != nil {
		return err
	}
	if err := syncUpgradeDir(receiptDir); err != nil {
		return err
	}
	return authorize(func() error {
		if pending {
			return publishHarnessPolicy(files[2], ledger.PlanID)
		}
		return syncUpgradeDir(filepath.Dir(files[2].path))
	})
}

func verifyHarnessCommands(accounts []string) error {
	for _, account := range accounts {
		cmd := exec.Command("/usr/bin/sudo", "-n", "-l", "-U", DarwinHQAccount, "-u", account, "--", HarnessLauncher, "harness-run")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		if err := cmd.Run(); err != nil {
			return errors.New("sudo did not confirm the reviewed command for every target role")
		}
	}
	return nil
}

func readHarnessLedger(path string, want harnessLedger) (harnessLedger, error) {
	var r harnessLedger
	fd, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return r, e
	}
	defer fd.Close()
	st, e := fd.Stat()
	if e != nil || st.Mode() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || (os.Geteuid() == 0 && st.Sys().(*syscall.Stat_t).Gid != 0) {
		return r, errors.New("invalid protected harness installation metadata")
	}
	if e = checkDarwinACLs([]string{path}); e != nil {
		return r, e
	}
	data, e := io.ReadAll(io.LimitReader(fd, 16385))
	if e != nil {
		return r, e
	}
	if len(data) > 16384 || json.Unmarshal(data, &r) != nil || len(r.Files) != 4 || r.PlanID != want.PlanID || r.Digest != want.Digest || r.Purpose != HarnessInstall || r.Owner != want.Owner || r.Pair != want.Pair {
		return r, errors.New("unmatched protected harness installation receipt")
	}
	for _, n := range r.Files {
		if n == (upgradeNodeIdentity{}) {
			return r, errors.New("invalid harness installation file identity")
		}
	}
	return r, nil
}
func retireGrantFiles(files []grantFile, original harnessLedger, authorize harnessBoundary) error {
	// Disable the rule before removing the matching payload. The readable
	// policy is last, allowing a subsequent run to identify an interrupted retire.
	order := []int{3, 0, 1, 2}
	for _, i := range order {
		f := files[i]
		node, e := f.node(f.path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if node != original.Files[i] {
			return errors.New("preserving replaced harness grant file")
		}
	}
	for _, i := range order {
		f := files[i]
		node, e := f.node(f.path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || node != original.Files[i] {
			return errors.New("harness grant changed during retirement")
		}
		if e = authorize(func() error { return os.Remove(f.path) }); e != nil {
			return e
		}
		if e = syncUpgradeDir(filepath.Dir(f.path)); e != nil {
			return e
		}
	}
	return nil
}

func harnessGrantFiles(installed installedHarness, manager []byte, rule string) ([]grantFile, error) {
	raw, err := harnessJSON(installed)
	if err != nil {
		return nil, err
	}
	p := installed.Policy
	return []grantFile{
		{HarnessLauncher, 0755, p.Launcher.SHA256, manager},
		{HarnessSandbox, 0644, p.Sandbox.SHA256, harnessProfile},
		{HarnessPolicy, 0644, harnessSHA([]byte(raw)), []byte(raw)},
		{HarnessRule, 0440, harnessSHA([]byte(rule)), []byte(rule)},
	}, nil
}

// A prior success can be reported without fetching a new approval. This path
// only observes the four final files and never publishes a staged policy.
func completedHarnessInstall(s Saved, owner string, guard upgradePairGuard) (bool, error) {
	if _, err := os.Lstat(HarnessPolicy); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if os.Geteuid() != 0 || guard == nil {
		return false, errors.New("cannot verify prior harness installation")
	}
	err := withLaunchLock(syscall.LOCK_SH|syscall.LOCK_NB, func() error {
		handle, current, err := readInstalledHarness()
		if err != nil {
			return err
		}
		defer handle.Close()
		if current.ID != s.PlanID || current.Digest != s.PlanDigest {
			return errors.New("another harness installation is present")
		}
		dir := "/private" + DarwinReceiptsDir
		raw, err := readProtectedUpgradeFile(filepath.Join(dir, s.PlanID+".json"))
		var rec Receipt
		if err != nil || json.Unmarshal(raw, &rec) != nil || rec.Result != "applied" || rec.FinishedAt == "" || rec.StartedAt == "" || rec.PlanID != s.PlanID || rec.PlanDigest != s.PlanDigest || rec.Owner != owner || rec.HQAccount != DarwinHQAccount || rec.Dir != DarwinBrokerDir || !slices.Equal(rec.Members, s.Plan.Members) || rec.HarnessApproval == nil {
			return errors.New("missing completed receipt for this harness installation")
		}
		approval := *rec.HarnessApproval
		if approval.Purpose != HarnessInstall || approval.PlanID != s.PlanID || approval.PlanDigest != s.PlanDigest || !digestPattern.MatchString(approval.PairCommitment) || !digestPattern.MatchString(approval.MachineFingerprint) {
			return errors.New("original harness install authority is unavailable")
		}
		prior, err := readHarnessLedger(filepath.Join(dir, s.PlanID+".harness-install.json"), harnessLedger{PlanID: s.PlanID, Digest: s.PlanDigest, Owner: owner, Pair: approval.PairCommitment})
		if err != nil {
			return err
		}
		files, err := harnessGrantFiles(current, nil, s.Plan.Steps[1].Content)
		if err != nil {
			return err
		}
		for _, dir := range []string{filepath.Dir(HarnessLauncher), filepath.Dir(HarnessRule)} {
			if err := trustedPath(OSHost{}, dir, true); err != nil {
				return err
			}
			if err := checkDarwinACLs(pathAncestry(dir)); err != nil {
				return err
			}
		}
		if err := verifyHarnessRoles(current.Policy); err != nil {
			return err
		}
		for _, adapter := range current.Policy.Adapters {
			if err := verifyHarnessExecutable(adapter.Executable, adapter.SHA256); err != nil {
				return err
			}
		}
		return observeCompletedHarnessFiles(files, prior, approval, guard)
	})
	return err == nil, err
}

func observeCompletedHarnessFiles(files []grantFile, ledger harnessLedger, a Approval, guard upgradePairGuard) error {
	for i, f := range files {
		node, err := f.node(f.path)
		if err != nil || node != ledger.Files[i] {
			return errors.New("completed harness receipt no longer matches its installed files")
		}
	}
	return guard(a, nil)
}

func applyHarnessGrant(s Saved, a Approval, owner string, guard upgradePairGuard) error {
	r := s.HarnessLaunch
	if r == nil || a.Purpose != HarnessPurpose(r.Action) || !ValidApproval(a.PlanID, a.PlanDigest) || a.PlanID != s.PlanID || a.PlanDigest != s.PlanDigest || !digestPattern.MatchString(a.PairCommitment) || os.Geteuid() != 0 || guard == nil {
		return errors.New("invalid protected harness grant approval")
	}
	if r.Action == "install" {
		for _, adapter := range r.Adapters {
			if err := qualifiedHarnessAdapter(adapter); err != nil {
				return err
			}
		}
	}
	// Existing managed roles imply a receipt directory from provisioning.
	receiptDir := "/private" + DarwinReceiptsDir
	for _, dir := range []string{receiptDir, launchRuntimeDir, filepath.Dir(HarnessRule)} {
		if e := trustedPath(OSHost{}, dir, true); e != nil {
			return e
		}
		if e := checkDarwinACLs(pathAncestry(dir)); e != nil {
			return e
		}
	}
	return withLaunchLock(syscall.LOCK_EX|syscall.LOCK_NB, func() error {
		authorize := harnessAuthority(a, guard, time.Now)
		if err := authorize(nil); err != nil {
			return err
		}
		plan, e := savedHarnessPlan(s, a.Purpose, owner, r.HQUID, OSHost{})
		if e != nil {
			return e
		}
		if sum, e := plan.Digest(); e != nil || sum != a.PlanDigest {
			return errors.New("harness policy changed after owner approval")
		}
		if e := verifyHarnessRoles(*r); e != nil {
			return e
		}
		roleSteps, e := Build(Input{Platform: PlatformDarwin, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: plan.Members, Invoker: owner}, OSHost{})
		if e != nil {
			return e
		}
		if e := Precheck(roleSteps, OSRoot{}); e != nil {
			return e
		}
		install := r.installation()
		id, digest := s.PlanID, s.PlanDigest
		var manager []byte
		if r.Action == "install" {
			manager, e = managerBytes()
			if e != nil || harnessSHA(manager) != r.Launcher.SHA256 || harnessSHA(harnessProfile) != r.Sandbox.SHA256 {
				return errors.New("Machine or profile differs from approval")
			}
		} else {
			id, digest = r.InstalledID, r.InstalledDigest
		}
		files, e := harnessGrantFiles(installedHarness{id, digest, install}, manager, plan.Steps[1].Content)
		if e != nil {
			return e
		}
		ledger := harnessLedger{PlanID: id, Digest: digest, Owner: owner, Purpose: HarnessInstall, Pair: a.PairCommitment}
		ledgerPath := filepath.Join(receiptDir, id+".harness-install.json")
		var original harnessLedger
		if r.Action == "retire" {
			handle, live, e := lockInstalledHarness(true)
			if e != nil {
				return e
			}
			defer handle.Close()
			if e := requireIdleHarnessRoles(r.Adapters, unix.SysctlKinfoProcSlice); e != nil {
				return e
			}
			if live.ID != id || live.Digest != digest {
				return errors.New("installed grant changed")
			}
			data, e := readProtectedUpgradeFile(filepath.Join(receiptDir, id+".json"))
			var prior Receipt
			if e != nil || json.Unmarshal(data, &prior) != nil || prior.Result != "applied" || prior.FinishedAt == "" || prior.Owner != owner || prior.PlanID != id || prior.PlanDigest != digest {
				return errors.New("retirement requires the matching completed original root receipt")
			}
			if e = trustedPath(OSHost{}, ledgerPath, false); e != nil {
				return e
			}
			if e = checkDarwinACLs(pathAncestry(ledgerPath)); e != nil {
				return e
			}
			original, e = readHarnessLedger(ledgerPath, ledger)
			if e != nil {
				return e
			}
		}
		receipt := Receipt{HarnessApproval: &a, PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner, HQAccount: DarwinHQAccount, Dir: DarwinBrokerDir, Members: plan.Members, Changes: plan.Changes(), StartedAt: time.Now().UTC().Format(approvalTime), Result: "started"}
		rp := filepath.Join(receiptDir, s.PlanID+".json")
		if e = writeUpgradeFile(rp, encodeReceipt(receipt), 0600, true); errors.Is(e, os.ErrExist) {
			data, e := readProtectedUpgradeFile(rp)
			var previous Receipt
			if e != nil || json.Unmarshal(data, &previous) != nil || previous.PlanID != receipt.PlanID || previous.PlanDigest != receipt.PlanDigest || previous.Owner != owner || previous.HQAccount != receipt.HQAccount || previous.Dir != receipt.Dir || !slices.Equal(previous.Members, receipt.Members) || previous.HarnessApproval == nil || !sameHarnessAuthority(*previous.HarnessApproval, a) {
				return errors.New("harness approval previously spent or receipt changed")
			}
			if previous.Result == "applied" && previous.FinishedAt != "" && a.Purpose == HarnessInstall {
				installed, err := readHarnessLedger(ledgerPath, ledger)
				if err != nil {
					return err
				}
				return completeInstalledGrant(files, installed, receiptDir, func() error {
					return verifyHarnessCommands(plan.Members)
				}, authorize)
			}
			if previous.Result != "started" || previous.FinishedAt != "" {
				return errors.New("harness approval already spent")
			}
			receipt = previous
		} else if e != nil {
			return e
		}
		finish := func() error { return finishHarnessReceipt(rp, receipt) }
		if r.Action == "install" {
			return installGrantFiles(files, ledger, ledgerPath, func(stage string) error {
				cmd := exec.Command("/usr/sbin/visudo", "-c", "-f", stage)
				cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
				cmd.Stdout = io.Discard
				cmd.Stderr = io.Discard
				return cmd.Run()
			}, func() error { return verifyHarnessCommands(plan.Members) }, authorize, finish)
		}
		if err := retireGrantFiles(files, original, authorize); err != nil {
			return err
		}
		return authorize(finish)
	})
}

// A crash after unlinking the last file can leave a started receipt. Verify the
// exact previously authorized intent and complete only its audit record.
func finishAbsentHarnessRetirement(s Saved, owner string, guard upgradePairGuard) (string, error) {
	r := s.HarnessLaunch
	if r == nil || r.Action != "retire" {
		return "", nil
	}
	if _, e := os.Lstat(HarnessPolicy); !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	if os.Geteuid() != 0 || guard == nil || s.HQService != nil || s.UpgradeFrom != nil || !ValidApproval(s.PlanID, s.PlanDigest) {
		return "", errors.New("invalid saved harness retirement")
	}
	dir := "/private" + DarwinReceiptsDir
	rp := filepath.Join(dir, s.PlanID+".json")
	data, e := readProtectedUpgradeFile(rp)
	var previous Receipt
	if e != nil || json.Unmarshal(data, &previous) != nil || previous.HarnessApproval == nil {
		return "", errors.New("missing protected pending harness retirement")
	}
	a := *previous.HarnessApproval
	if a.Purpose != HarnessRetire || a.PlanID != s.PlanID || a.PlanDigest != s.PlanDigest || !digestPattern.MatchString(a.PairCommitment) || !digestPattern.MatchString(a.MachineFingerprint) {
		return "", errors.New("missing matching recorded harness retirement approval")
	}
	p, e := r.plan()
	if e != nil {
		return "", e
	}
	sum, e := p.Digest()
	saved, e2 := s.Plan.Digest()
	if e != nil || e2 != nil || sum != a.PlanDigest || sum != saved {
		return "", errors.New("retirement approval differs from the saved policy")
	}
	original := r.InstalledDigest // r.plan verified this against the complete original installation.
	var result string
	err := withLaunchLock(syscall.LOCK_EX|syscall.LOCK_NB, func() error {
		for _, path := range []string{HarnessLauncher, HarnessSandbox, HarnessPolicy, HarnessRule} {
			parent := filepath.Dir(path)
			if e := trustedPath(OSHost{}, parent, true); e != nil {
				return e
			}
			if e := checkDarwinACLs(pathAncestry(parent)); e != nil {
				return e
			}
			if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				return errors.New("retirement is incomplete or a different installation is present")
			}
		}
		// A previous process may have exited between the last unlink and fsync.
		for _, parent := range []string{filepath.Dir(HarnessRule), filepath.Dir(HarnessPolicy)} {
			if err := syncUpgradeDir(parent); err != nil {
				return err
			}
		}
		if e := requireIdleHarnessRoles(r.Adapters, unix.SysctlKinfoProcSlice); e != nil {
			return e
		}
		for _, item := range []struct {
			id, digest string
			previous   bool
		}{{r.InstalledID, original, true}, {s.PlanID, a.PlanDigest, false}} {
			rp := filepath.Join(dir, item.id+".json")
			data, e := readProtectedUpgradeFile(rp)
			var rec Receipt
			if e != nil || json.Unmarshal(data, &rec) != nil || rec.Owner != owner || rec.PlanID != item.id || rec.PlanDigest != item.digest || rec.HQAccount != DarwinHQAccount || rec.Dir != DarwinBrokerDir || !slices.Equal(rec.Members, p.Members) || rec.StartedAt == "" {
				return errors.New("missing protected receipt for this exact retirement")
			}
			if item.previous {
				if rec.Result != "applied" || rec.FinishedAt == "" {
					return errors.New("original installation is not complete")
				}
				_, e = readHarnessLedger(filepath.Join(dir, item.id+".harness-install.json"), harnessLedger{PlanID: item.id, Digest: item.digest, Owner: owner, Pair: a.PairCommitment})
				if e != nil {
					return e
				}
				continue
			}
			if rec.HarnessApproval == nil || !sameHarnessAuthority(*rec.HarnessApproval, a) {
				return errors.New("recorded harness retirement authority changed")
			}
			result, e = recordObservedHarnessRetirement(rec, a, guard, func(observed Receipt) error {
				return writeUpgradeFile(rp, encodeReceipt(observed), 0600, false)
			})
			return e
		}
		return errors.New("missing protected retirement receipt")
	})
	return result, err
}

// The completed filesystem checks can be recorded even after the original
// window closed. This records observed absence only and cannot authorize or
// perform removal. Previously completed positive receipts keep their meaning.
func recordObservedHarnessRetirement(rec Receipt, a Approval, guard upgradePairGuard, write func(Receipt) error) (string, error) {
	switch rec.Result {
	case "applied", "retirement-observed":
		if rec.FinishedAt != "" {
			return rec.Result, guard(a, nil)
		}
	case "started":
		if rec.FinishedAt == "" {
			rec.Result = "retirement-observed"
			return rec.Result, guard(a, func() error {
				rec.FinishedAt = time.Now().UTC().Format(approvalTime)
				return write(rec)
			})
		}
	}
	return "", errors.New("invalid pending harness retirement receipt")
}

// The shared supervisor lease normally accounts for an active group. A
// supervisor itself can die first. Under the exclusive lease, corroborate
// quiescence for every dedicated target UID before retiring its grant.
func requireIdleHarnessRoles(adapters []HarnessAdapter, query func(string, ...int) ([]unix.KinfoProc, error)) error {
	seen := map[int]bool{}
	for _, a := range adapters {
		if seen[a.UID] {
			continue
		}
		seen[a.UID] = true
		for _, name := range []string{"kern.proc.uid", "kern.proc.ruid"} {
			procs, e := query(name, a.UID)
			if e != nil {
				return errors.New("cannot confirm dedicated harness role is idle")
			}
			if len(procs) != 0 {
				return fmt.Errorf("dedicated harness role %s still has a process; stop its launches before retirement", a.Account)
			}
		}
	}
	return nil
}

func sameHarnessAuthority(a, b Approval) bool {
	return a.Purpose == b.Purpose && a.PlanID == b.PlanID && a.PlanDigest == b.PlanDigest && a.MachineFingerprint == b.MachineFingerprint && a.PairCommitment == b.PairCommitment
}
