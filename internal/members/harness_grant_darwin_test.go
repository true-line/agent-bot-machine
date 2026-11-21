package members

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func allowTestHarnessCommit(commit func() error) error {
	if commit == nil {
		return nil
	}
	return commit()
}
func harnessFilesFixture(t *testing.T) ([]grantFile, harnessLedger, string) {
	t.Helper()
	return harnessFixtureAt(t.TempDir())
}

func harnessFixtureAt(dir string) ([]grantFile, harnessLedger, string) {
	var files []grantFile
	for i, name := range []string{"launcher", "profile", "policy", "rule"} {
		mode := []os.FileMode{0755, 0644, 0644, 0440}[i]
		data := []byte(name + "\n")
		files = append(files, grantFile{filepath.Join(dir, name), mode, harnessSHA(data), data})
	}
	record := harnessLedger{PlanID: "plan-20261120T120000Z-abcd", Digest: harnessSHA([]byte("plan")), Owner: "fixture", Purpose: HarnessInstall, Pair: harnessSHA([]byte("pair"))}
	ledger := filepath.Join(dir, "receipt")
	return files, record, ledger
}

func TestReviewedHarnessGrantPublicationAndRetirement(t *testing.T) {
	files, record, ledger := harnessFilesFixture(t)
	pass := func() error { return nil }
	validate := func(stage string) error {
		if _, e := os.Stat(ledger); !os.IsNotExist(e) {
			t.Fatal("receipt predates validation")
		}
		if _, e := os.Stat(files[3].path); !os.IsNotExist(e) {
			t.Fatal("authorization visible before validation")
		}
		_, e := files[3].node(stage)
		return e
	}
	if e := installGrantFiles(files, record, ledger, validate, func() error { return errors.New("synthetic command is absent") }, allowTestHarnessCommit, pass); e == nil {
		t.Fatal("inactive command reported installed")
	}
	if _, e := os.Lstat(files[3].path); !os.IsNotExist(e) {
		t.Fatal("unverified rule retained")
	}
	if e := installGrantFiles(files, record, ledger, validate, pass, allowTestHarnessCommit, pass); e != nil {
		t.Fatal(e)
	}
	original, e := readHarnessLedger(ledger, record)
	if e != nil {
		t.Fatal(e)
	}
	if e = completeInstalledGrant(files, original, filepath.Dir(ledger), pass, allowTestHarnessCommit); e != nil {
		t.Fatal("exact retry", e)
	}
	for i, f := range files {
		node, e := f.node(f.path)
		if e != nil || node != original.Files[i] {
			t.Fatal(i, e)
		}
	}
	// Preserve independently replaced files with identical bytes and permissions.
	swapped := files[0]
	if e = os.Rename(swapped.path, swapped.path+".saved"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(swapped.path, swapped.data, swapped.mode); e != nil {
		t.Fatal(e)
	}
	if e = retireGrantFiles(files, original, allowTestHarnessCommit); e == nil {
		t.Fatal("retired replaced file")
	}
	if _, e = os.Lstat(files[3].path); e != nil {
		t.Fatal("removed rule on inconsistent preflight", e)
	}
	if e = os.Remove(swapped.path); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(swapped.path+".saved", swapped.path); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(files[3].path); e != nil {
		t.Fatal(e)
	} // interrupted after first authorized removal
	if e = retireGrantFiles(files, original, allowTestHarnessCommit); e != nil {
		t.Fatal(e)
	}
	if e = retireGrantFiles(files, original, allowTestHarnessCommit); e != nil {
		t.Fatal("repeat retirement", e)
	}
	for _, f := range files {
		if _, e := os.Lstat(f.path); !os.IsNotExist(e) {
			t.Fatal("file survived", f.path, e)
		}
	}
	if _, e := readHarnessLedger(ledger, record); e != nil {
		t.Fatal("receipt failed after retirement", e)
	}
}
func TestInterpreterDigestDoesNotQualifyAnAdapter(t *testing.T) {
	raw, e := os.ReadFile("/bin/sh")
	if e != nil {
		t.Fatal(e)
	}
	if e := qualifiedHarnessAdapter(HarnessAdapter{ID: "script-adapter", Executable: "/bin/sh", SHA256: harnessSHA(raw), Args: []string{"/example/adapter.sh"}}); e == nil {
		t.Fatal("interpreter's digest accepted as an adapter qualification")
	}
}

func TestReviewedHarnessRetirementNeedsIdleRoles(t *testing.T) {
	adapters := exampleHarness().Adapters
	for _, mode := range []string{"idle", "effective", "real", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			e := requireIdleHarnessRoles(adapters, func(key string, ids ...int) ([]unix.KinfoProc, error) {
				calls++
				if mode == "unknown" {
					return nil, errors.New("process table unavailable")
				}
				if (mode == "effective" && key == "kern.proc.uid") || (mode == "real" && key == "kern.proc.ruid") {
					return []unix.KinfoProc{{}}, nil
				}
				return nil, nil
			})
			if mode == "idle" {
				if e != nil || calls != 4 {
					t.Fatal(calls, e)
				}
			} else if e == nil {
				t.Fatal("unconfirmed exit allowed retirement")
			}
		})
	}
}

func TestHarnessGrantPublicationAndReceiptCutoff(t *testing.T) {
	for _, scenario := range []string{"healthy", "revoked before publication", "expired before publication", "revoked during effective check", "expired during effective check", "receipt write failed", "receipt rename visible before sync failed", "revoked after receipt sync", "expired after receipt sync"} {
		t.Run(scenario, func(t *testing.T) {
			files, ledger, ledgerPath := harnessFilesFixture(t)
			start := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
			end := start.Add(ApprovalTTL)
			a := Approval{PlanID: ledger.PlanID, PlanDigest: ledger.Digest, Purpose: HarnessInstall, PairCommitment: ledger.Pair, ApprovedAt: start.Format(approvalTime), ExpiresAt: end.Format(approvalTime)}
			now := start
			live, held := true, false
			guard := func(received Approval, commit func() error) error {
				if held || received != a {
					t.Fatal("incorrect authority or nested pairing lock")
				}
				if !live {
					return errors.New("pair revoked")
				}
				held = true
				defer func() { held = false }()
				return commit()
			}
			boundary := harnessAuthority(a, guard, func() time.Time { return now })
			checkRule := func(want bool) {
				t.Helper()
				_, e := files[3].node(files[3].path)
				if want && e != nil || !want && !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("expected rule present=%v, got %v", want, e)
				}
			}
			validate := func(string) error {
				if held {
					t.Fatal("external syntax check held pairing lock")
				}
				checkRule(false)
				switch scenario {
				case "revoked before publication":
					live = false
				case "expired before publication":
					now = end
				}
				return nil
			}
			verified, wrote := false, false
			check := func() error {
				if held {
					t.Fatal("external effective-rule check held pairing lock")
				}
				checkRule(true)
				if _, err := os.Lstat(files[2].path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("launcher can use the policy before its receipt", err)
				}
				verified = true
				switch scenario {
				case "revoked during effective check":
					live = false
				case "expired during effective check":
					now = end
				}
				return nil
			}
			finish := func() error {
				if !held || !verified {
					t.Fatal("receipt outside verified commit boundary")
				}
				if scenario == "receipt write failed" {
					return errors.New("fixture receipt unavailable")
				}
				wrote = true
				if scenario == "revoked after receipt sync" {
					live = false
				}
				if scenario == "expired after receipt sync" {
					now = end
				}
				if scenario == "receipt rename visible before sync failed" {
					return errHarnessReceiptVisible
				}
				return nil
			}
			err := installGrantFiles(files, ledger, ledgerPath, validate, check, boundary, finish)
			success := scenario == "healthy"
			wantVisible := success || scenario == "receipt rename visible before sync failed" || scenario == "revoked after receipt sync" || scenario == "expired after receipt sync"
			if (err == nil) != success || wrote != wantVisible {
				t.Fatalf("error=%v receipt=%v", err, wrote)
			}
			checkRule(wantVisible)
			if _, err := os.Lstat(files[2].path); (err == nil) != success {
				t.Fatal("policy activation before durable receipt", err)
			}
			if scenario == "receipt rename visible before sync failed" {
				original, err := readHarnessLedger(ledgerPath, ledger)
				if err != nil {
					t.Fatal(err)
				}
				live = false
				if err := completeInstalledGrant(files, original, filepath.Dir(ledgerPath), func() error { return nil }, boundary); err == nil {
					t.Fatal("revoked receipt activated policy")
				}
				if _, err := os.Lstat(files[2].path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("policy after revoke", err)
				}
				live = true
				if err := completeInstalledGrant(files, original, filepath.Dir(ledgerPath), func() error { return nil }, boundary); err != nil {
					t.Fatal("could not complete exact interrupted installation", err)
				}
				if err := verifyInstalledGrantFiles(files, original); err != nil {
					t.Fatal(err)
				}
			}
			if !wantVisible && verified {
				if _, err := files[3].node(files[3].stage(ledger.PlanID)); err != nil {
					t.Fatal("missing withdrawn original", err)
				}
			}
		})
	}
}

func TestHarnessRetirementCutoffBeforeRemovalAndReceipt(t *testing.T) {
	files, ledger, path := harnessFilesFixture(t)
	pass := func() error { return nil }
	if err := installGrantFiles(files, ledger, path, func(string) error { return nil }, pass, allowTestHarnessCommit, pass); err != nil {
		t.Fatal(err)
	}
	original, err := readHarnessLedger(path, ledger)
	if err != nil {
		t.Fatal(err)
	}
	deny := func(func() error) error { return errors.New("pair revoked") }
	if err := retireGrantFiles(files, original, deny); err == nil {
		t.Fatal("unapproved retirement")
	}
	if err := verifyInstalledGrantFiles(files, original); err != nil {
		t.Fatal("withdrawal on initial refusal", err)
	}
	calls := 0
	stopAfterRule := func(do func() error) error {
		calls++
		if calls == 1 {
			return do()
		}
		return deny(do)
	}
	if err := retireGrantFiles(files, original, stopAfterRule); err == nil {
		t.Fatal("lost cutoff")
	}
	if _, err := os.Lstat(files[3].path); !os.IsNotExist(err) {
		t.Fatal("effective rule retained after authorized first step", err)
	}
	for _, f := range files[:3] {
		if _, err := f.node(f.path); err != nil {
			t.Fatal("removed payload after cutoff", err)
		}
	}
	if err := retireGrantFiles(files, original, allowTestHarnessCommit); err != nil {
		t.Fatal("exact authorized resume", err)
	}
}

func verifyInstalledGrantFiles(files []grantFile, ledger harnessLedger) error {
	for i, f := range files {
		node, err := f.node(f.path)
		if err != nil || node != ledger.Files[i] {
			return errors.New("completed harness receipt no longer matches the installed files")
		}
	}
	return nil
}

func TestHarnessGrantInterruptedBeforePolicy(t *testing.T) {
	const modeEnv = "MM_TEST_HARNESS_GRANT_INTERRUPT"
	const dirEnv = "MM_TEST_HARNESS_GRANT_DIR"
	pass := func() error { return nil }
	if phase := os.Getenv(modeEnv); phase != "" {
		files, ledger, path := harnessFixtureAt(os.Getenv(dirEnv))
		check := func() error {
			if phase == "before receipt" {
				os.Exit(37)
			}
			return nil
		}
		finish := func() error {
			if err := finishHarnessReceipt(filepath.Join(os.Getenv(dirEnv), "final.json"), Receipt{PlanID: ledger.PlanID, PlanDigest: ledger.Digest}); err != nil {
				return err
			}
			os.Exit(37)
			return nil
		}
		t.Fatal(installGrantFiles(files, ledger, path, func(string) error { return nil }, check, allowTestHarnessCommit, finish))
	}
	for _, phase := range []string{"before receipt", "after receipt"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestHarnessGrantInterruptedBeforePolicy$")
			cmd.Env = append(os.Environ(), modeEnv+"="+phase, dirEnv+"="+dir)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 37 {
				t.Fatalf("fixture failed outside requested cut: %v %s", err, out)
			}
			files, ledger, path := harnessFixtureAt(dir)
			if _, err := files[3].node(files[3].path); err != nil {
				t.Fatal("missing reviewed rule", err)
			}
			if _, err := os.Lstat(files[2].path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("interrupted installation exposed policy", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "final.json"))
			if phase == "after receipt" {
				var receipt Receipt
				if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.PlanID != ledger.PlanID || receipt.PlanDigest != ledger.Digest || receipt.Result != "applied" || receipt.FinishedAt == "" {
					t.Fatal("completed receipt unavailable", err)
				}
				original, err := readHarnessLedger(path, ledger)
				if err != nil {
					t.Fatal(err)
				}
				err = completeInstalledGrant(files, original, dir, pass, allowTestHarnessCommit)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unexpected receipt", err)
				}
				if err := installGrantFiles(files, ledger, path, func(string) error { return nil }, pass, allowTestHarnessCommit, pass); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := files[2].node(files[2].path); err != nil {
				t.Fatal("authorized retry did not publish policy", err)
			}
		})
	}
}

func TestInterruptedHarnessRetirementReportsOnlyObservedAbsence(t *testing.T) {
	past := time.Now().Add(-2 * ApprovalTTL).UTC()
	approval := Approval{Purpose: HarnessRetire, ApprovedAt: past.Format(approvalTime), ExpiresAt: past.Add(ApprovalTTL).Format(approvalTime)}
	receipt := Receipt{Result: "started", HarnessApproval: &approval}
	live := false
	guard := func(a Approval, do func() error) error {
		if !live || a != approval {
			return errors.New("original pairing missing")
		}
		if do == nil {
			return nil
		}
		return do()
	}
	writes := 0
	write := func(next Receipt) error { writes++; receipt = next; return nil }
	if _, err := recordObservedHarnessRetirement(receipt, approval, guard, write); err == nil || writes != 0 {
		t.Fatal("cutoff ignored")
	}
	live = true
	for i := 0; i < 2; i++ {
		result, err := recordObservedHarnessRetirement(receipt, approval, guard, write)
		if err != nil || result != "retirement-observed" || receipt.Result != result || receipt.FinishedAt == "" || writes != 1 {
			t.Fatal(result, err, writes)
		}
	}
	receipt.Result = "applied"
	result, err := recordObservedHarnessRetirement(receipt, approval, guard, write)
	if err != nil || result != "applied" || writes != 1 {
		t.Fatal("changed previous completion", result, err)
	}
}

func TestCompletedHarnessInstallObservationCannotReactivate(t *testing.T) {
	files, ledger, path := harnessFilesFixture(t)
	pass := func() error { return nil }
	if err := installGrantFiles(files, ledger, path, func(string) error { return nil }, pass, allowTestHarnessCommit, pass); err != nil {
		t.Fatal(err)
	}
	original, err := readHarnessLedger(path, ledger)
	if err != nil {
		t.Fatal(err)
	}
	prior := Approval{Purpose: HarnessInstall, PairCommitment: ledger.Pair, PlanID: ledger.PlanID, PlanDigest: ledger.Digest, ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(approvalTime)}
	live := true
	guard := func(a Approval, do func() error) error {
		if do != nil || a != prior {
			t.Fatal("receipt read requested a mutation or changed the recorded approval")
		}
		if !live {
			return errors.New("pair retired")
		}
		return nil
	}
	if err := observeCompletedHarnessFiles(files, original, prior, guard); err != nil {
		t.Fatal(err)
	}
	live = false
	if err := observeCompletedHarnessFiles(files, original, prior, guard); err == nil {
		t.Fatal("pair cutoff ignored")
	}
	live = true
	policy := files[2]
	if err := os.Rename(policy.path, policy.stage(ledger.PlanID)); err != nil {
		t.Fatal(err)
	}
	if err := observeCompletedHarnessFiles(files, original, prior, guard); err == nil {
		t.Fatal("staged installation reported complete")
	}
	if _, err := os.Lstat(policy.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged policy was activated", err)
	}
}
