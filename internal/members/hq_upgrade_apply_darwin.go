package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Exchange only this manager's reviewed, protected plist. The other inode is
// retained at the staging name through the transition. A failed observation
// leaves both files for review rather than overwriting an unexpected input.
func swapReviewedPlists(stage, before, after string) error {
	if e := verifyReviewedPlist(launchPlist, before); e != nil {
		return e
	}
	if e := verifyReviewedPlist(stage, after); e != nil {
		return e
	}
	if err := unix.RenamexNp(stage, launchPlist, unix.RENAME_SWAP); err != nil {
		return err
	}
	return syncUpgradeDir(filepath.Dir(stage))
}
func verifyReviewedPlist(path, want string) error {
	if err := trustedPath(OSHost{}, path, false); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	st, e := f.Stat()
	var raw []byte
	if e == nil && st.Sys().(*syscall.Stat_t).Nlink == 1 && st.Sys().(*syscall.Stat_t).Gid == 0 && st.Mode().IsRegular() && st.Mode().Perm() == 0644 && st.Size() == int64(len(want)) {
		raw, e = io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	}
	f.Close()
	if e != nil || string(raw) != want {
		return errors.New("reviewed HQ plist or its prepared replacement changed")
	}
	return nil
}

func syncUpgradeDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func observedSigner(rec launchRecord, owner string) (upgradeSigner, error) {
	var out struct {
		HQ struct{ Signer upgradeSigner }
	}
	program := rec.Service.Node
	args := []string{filepath.Join(rec.Service.ReleaseDir, "hq/main.mjs"), "status", "--owner-control", "--json"}
	if os.Geteuid() != rec.OwnerUID {
		if os.Geteuid() != 0 {
			return upgradeSigner{}, errors.New("the approved service owner is required to read HQ status")
		}
		args = append([]string{"-n", "-H", "-u", owner, "--", program}, args...)
		program = "/usr/bin/sudo"
	}
	b, err := hqProgramOutput(program, args...)
	if err != nil || !confirmsServiceOwner(b, owner, strconv.Itoa(rec.OwnerUID), DarwinHQAccount, launchRuntimeSocket, "getpeereid") || json.Unmarshal(b, &out) != nil || !out.HQ.Signer.Available || out.HQ.Signer.Thumbprint == "" || out.HQ.Signer.Generation < 1 {
		return upgradeSigner{}, errors.New("HQ did not confirm the expected owner endpoint and available signer")
	}
	return out.HQ.Signer, nil
}
func pairedReleaseStatus(s HQService, fingerprint string) error {
	// The supported Darwin release installs the Machine channel in the arm64 Homebrew prefix.
	const socket = "/opt/homebrew/var/agent-machine/daemon.sock"
	if runtime.GOARCH != "arm64" || !digestPattern.MatchString(fingerprint) {
		return errors.New("missing reviewed Machine channel")
	}
	b, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", DarwinHQAccount, "--", s.Node, filepath.Join(s.ReleaseDir, "hq/main.mjs"), "machine", "status", "--socket", socket)
	var status struct {
		Client, Channel, State string
		Fingerprint            string `json:"daemon_fingerprint"`
	}
	if err != nil || json.Unmarshal(b, &status) != nil || status.Client != "agent-daemon" || status.Channel != "signed" || status.State != "reported" || status.Fingerprint != fingerprint {
		return errors.New("dedicated HQ did not confirm its previously paired Machine")
	}
	return nil
}

func activateUpgrade(step Step, approval Approval, pair upgradePairGuard) error {
	return withLaunchLock(syscall.LOCK_EX|syscall.LOCK_NB, func() error { return upgradeUnderLock(step, approval, pair) })
}

func upgradeUnderLock(step Step, approval Approval, pair upgradePairGuard) (err error) {
	if pair == nil {
		return errors.New("missing protected pairing verifier")
	}
	if err = pair(approval, nil); err != nil {
		return err
	}
	kernel, e := unix.Sysctl("kern.osrelease")
	if e != nil || !supportsGuardedUpgrade(kernel) {
		return errors.New("this macOS kernel cannot guarantee guarded removal of a stopped HQ socket; the current service is still running")
	}
	fp := approval.MachineFingerprint
	current, err := currentUpgradeReceipt(approval, step.Owner)
	if err != nil || current.Result != "started" {
		return errors.New("upgrade requires its exact in-progress root receipt")
	}
	var rec launchUpgrade
	if step.Target != launchLabel || step.Action != upgradeAction || json.Unmarshal([]byte(step.Content), &rec) != nil {
		return errors.New("invalid HQ upgrade step")
	}
	if err = receiptForUpgrade(OSHost{}, rec.PreviousID, rec.PreviousDigest, step.Owner, checkDarwinACLs); err != nil {
		return err
	}
	journal := filepath.Join(receiptsDir(), upgradeJournalName)
	if _, e := os.Lstat(journal); !errors.Is(e, os.ErrNotExist) {
		return errors.New("an interrupted HQ upgrade already requires reconciliation")
	}
	for _, r := range []launchRecord{rec.Previous, rec.Next} {
		cap, e := verifyDarwinRelease(r.Service, OSHost{})
		if e != nil {
			return e
		}
		if cap != launchControlV2 || r.Plist != renderLaunchPlist(r.Service, r.OwnerUID, step.Owner, cap) {
			return errors.New("approved HQ release changed before cutover")
		}
	}
	if e := verifyReviewedPlist(launchPlist, rec.Previous.Plist); e != nil {
		return e
	}
	currentDir, e := planLaunchDirectory(OSHost{}, checkDarwinACLs)
	if e != nil || !upgradeDirectory(currentDir, false) {
		return errors.New("prior protected HQ runtime directory changed")
	}
	// Verify the already running job, uid and owner endpoint under the same lock;
	// the ordinary activator may also start a stopped job, so check first.
	live, pid, e := loadedLaunchDaemon(rec.Previous.Service, step.Owner)
	n, pe := strconv.Atoi(pid)
	if e != nil || !live || pe != nil || n <= 0 {
		return errors.New("prior HQ job is no longer running")
	}
	if e = verifyHQProcessUID(pid); e != nil {
		return e
	}
	if e = pairedReleaseStatus(rec.Next.Service, fp); e != nil {
		return e
	}
	if e = pairedReleaseStatus(rec.Previous.Service, fp); e != nil {
		return e
	}
	priorSigner, e := observedSigner(rec.Previous, step.Owner)
	if e != nil {
		return e
	}
	if priorSigner.Backend != "machine" || priorSigner.Storage != "hardware" {
		return errors.New("the prior HQ signer requires a separately authorized custody migration before a service-only upgrade; the current service is still running")
	}
	if e = validateUpgradeRoleCapability(rec.Next); e != nil {
		return e
	}
	stage, e := os.CreateTemp(filepath.Dir(launchPlist), ".hq-reviewed-upgrade-*.plist")
	if e != nil {
		return e
	}
	staged := stage.Name()
	journalOwned := false
	defer func() {
		if !journalOwned {
			os.Remove(staged)
		}
	}()
	if _, e = stage.WriteString(rec.Next.Plist); e == nil {
		e = stage.Chown(0, 0)
	}
	if e == nil {
		e = stage.Chmod(0644)
	}
	if e == nil {
		e = stage.Sync()
	}
	if closed := stage.Close(); e == nil {
		e = closed
	}
	if e != nil {
		return e
	}
	if e = runProgram("/usr/bin/plutil", "-lint", staged); e != nil {
		return e
	}
	if e = syncUpgradeDir(filepath.Dir(staged)); e != nil {
		return e
	}
	oldInfo, e := os.Lstat(launchPlist)
	if e != nil {
		return e
	}
	newInfo, e := os.Lstat(staged)
	if e != nil {
		return e
	}
	j := upgradeJournal{OriginalPlist: upgradeNode(oldInfo), PreparedPlist: upgradeNode(newInfo), pair: pair, Approval: approval, Owner: step.Owner, Upgrade: rec, Stage: staged, Signer: priorSigner, Phase: "prepared"}
	if e = j.write(journal, true); e != nil {
		if _, x := os.Lstat(journal); !errors.Is(x, os.ErrNotExist) {
			journalOwned = true
		}
		return e
	}
	journalOwned = true
	return performUpgrade(&j, rec)
}
func startReviewedRecord(r launchRecord, owner string, stopStarted func(*os.File, os.FileInfo) error) error {
	r.RuntimeDir = &launchDirectory{launchRuntimeDir, ActionNone, "root", "wheel", "0755"}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	return activateReviewedLaunch(Step{Kind: KindService, Target: launchLabel, Action: ActionWrite, Owner: owner, Content: string(raw)}, stopStarted)
}
func validateUpgradeRoleCapability(r launchRecord) error {
	b, err := hqProgramOutput("/usr/bin/sudo", "-n", "-H", "-u", DarwinHQAccount, "--", r.Service.Node, filepath.Join(r.Service.ReleaseDir, "hq/main.mjs"), "check-owner-control")
	var c launchRoleCapability
	if err != nil || json.Unmarshal(b, &c) != nil || c.Capability != launchControlV2 {
		return errors.New("candidate HQ did not confirm version 2 owner control before cutover")
	}
	return nil
}

func performUpgrade(j upgradeOperations, rec launchUpgrade) (e error) {
	if e = j.stop(rec.Previous, "stopping-previous"); e != nil {
		return fmt.Errorf("preserved HQ transition evidence after stop: %w", e)
	}
	if e = j.phase("switching"); e != nil {
		return e
	}
	if e = j.swap(rec.Previous, rec.Next); e != nil {
		return fmt.Errorf("preserved HQ transition evidence after attempted swap: %w", e)
	}
	if e = j.phase("starting-next"); e != nil {
		return e
	}
	if e = j.start(rec.Next); e == nil {
		e = j.verify(rec.Next)
	}
	if e == nil {
		return j.finish(true)
	}
	return errors.Join(e, restorePrevious(j, rec))
}

func supportsGuardedUpgrade(kernel string) bool {
	major, _, ok := strings.Cut(kernel, ".")
	n, err := strconv.Atoi(major)
	return ok && err == nil && n >= 25
}
