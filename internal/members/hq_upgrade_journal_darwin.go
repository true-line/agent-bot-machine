package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type upgradeNodeIdentity struct {
	Device     int32            `json:"device"`
	Inode      uint64           `json:"inode"`
	Generation uint32           `json:"generation"`
	Birth      syscall.Timespec `json:"birth"`
}

func upgradeNode(info os.FileInfo) upgradeNodeIdentity {
	s := info.Sys().(*syscall.Stat_t)
	return upgradeNodeIdentity{s.Dev, s.Ino, s.Gen, s.Birthtimespec}
}

type stoppingHQ struct {
	Parent upgradeNodeIdentity `json:"parent"`
	Socket upgradeNodeIdentity `json:"socket"`
	PID    string              `json:"pid"`
}
type upgradeJournal struct {
	OriginalPlist upgradeNodeIdentity `json:"original_plist"`
	PreparedPlist upgradeNodeIdentity `json:"prepared_plist"`
	pair          upgradePairGuard
	Approval      Approval      `json:"approval"`
	Owner         string        `json:"owner"`
	Upgrade       launchUpgrade `json:"upgrade"`
	Stage         string        `json:"staged_plist"`
	Signer        upgradeSigner `json:"previous_signer"`
	Phase         string        `json:"phase"`
	Stopping      *stoppingHQ   `json:"stopping,omitempty"`
}

func currentUpgradeReceipt(a Approval, owner string) (Receipt, error) {
	var result Receipt
	if a.Purpose != UpgradePurpose || !ValidApproval(a.PlanID, a.PlanDigest) || !digestPattern.MatchString(a.MachineFingerprint) {
		return result, errors.New("invalid upgrade approval identity")
	}
	path := filepath.Join("/private"+DarwinReceiptsDir, a.PlanID+".json")
	raw, e := readProtectedUpgradeFile(path)
	if e != nil {
		return result, e
	}
	if json.Unmarshal(raw, &result) != nil || result.PlanID != a.PlanID || result.PlanDigest != a.PlanDigest || result.Owner != owner || result.HQAccount != DarwinHQAccount || result.Dir != DarwinDir || len(result.Members) != 0 || result.StartedAt == "" {
		return result, errors.New("root receipt does not identify this exact paired upgrade")
	}
	return result, nil
}
func readProtectedUpgradeFile(path string) ([]byte, error) {
	if e := trustedPath(OSHost{}, path, false); e != nil {
		return nil, e
	}
	if e := checkDarwinACLs(pathAncestry(path)); e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Gid != 0 || st.Size() < 1 || st.Size() > 256<<10 {
		return nil, errors.New("unexpected protected HQ transition record")
	}
	return os.ReadFile(path)
}

// Link the first complete record exclusively, and atomically replace it on
// subsequent phase changes. Every returned success includes directory sync.
func writeUpgradeFile(path string, data []byte, mode os.FileMode, exclusive bool) error {
	parent := filepath.Dir(path)
	f, e := os.CreateTemp(parent, ".hq-transition-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if exclusive {
		e = unix.RenamexNp(f.Name(), path, unix.RENAME_EXCL)
	} else {
		e = os.Rename(f.Name(), path)
	}
	if e != nil {
		return e
	}
	return syncUpgradeDir(parent)
}
func (j *upgradeJournal) write(exclusive bool) error {
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return writeUpgradeFile(filepath.Join(receiptsDir(), upgradeJournalName), append(b, '\n'), 0600, exclusive)
}
func (j *upgradeJournal) phase(phase string) error {
	j.Phase = phase
	j.Stopping = nil
	return j.write(false)
}

func (j *upgradeJournal) stop(r launchRecord, phase string) error {
	if err := j.pair(j.Approval, nil); err != nil {
		return err
	}
	active, pid, err := loadedLaunchDaemon(r.Service, j.Owner)
	n, parse := strconv.Atoi(pid)
	if err != nil || !active || parse != nil || n <= 0 {
		return errors.New("cannot identify the running HQ job to stop")
	}
	if err = verifyReviewedPlist(launchPlist, r.Plist); err != nil {
		return err
	}
	parent, err := os.OpenFile(launchRuntimeDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	dir, err := parent.Stat()
	if err != nil {
		return err
	}
	sock, err := waitForLaunchSocket(launchRuntimeSocket, 0, 0)
	if err != nil {
		return err
	}
	j.Phase = phase
	j.Stopping = &stoppingHQ{upgradeNode(dir), upgradeNode(sock), pid}
	if err = j.write(false); err != nil {
		return err
	}
	if err = runProgram(launchctl, "bootout", "system/"+launchLabel); err != nil {
		return err
	}
	active, _, err = loadedLaunchDaemon(r.Service, j.Owner)
	if err != nil || active {
		return errors.New("cannot confirm reviewed HQ job stopped")
	}
	return removeStoppedLaunchSocket(launchRuntimeSocket, parent, sock, pid)
}
func (j *upgradeJournal) clearStoppedEndpoint() error {
	info, err := os.Lstat(launchRuntimeSocket)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || j.Stopping == nil || upgradeNode(info) != j.Stopping.Socket {
		return errors.New("preserving endpoint without exact recorded stop provenance")
	}
	parent, err := os.OpenFile(launchRuntimeDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	dir, err := parent.Stat()
	if err != nil || upgradeNode(dir) != j.Stopping.Parent {
		return errors.New("protected HQ runtime directory changed after stop")
	}
	return removeStoppedLaunchSocket(launchRuntimeSocket, parent, info, j.Stopping.PID)
}
func (j *upgradeJournal) verify(r launchRecord) error {
	if err := j.pair(j.Approval, nil); err != nil {
		return err
	}
	if e := verifyReviewedPlist(launchPlist, r.Plist); e != nil {
		return e
	}
	run, pid, e := loadedLaunchDaemon(r.Service, j.Owner)
	n, pe := strconv.Atoi(pid)
	if e != nil || !run || pe != nil || n <= 0 {
		return errors.New("reviewed HQ job is not running")
	}
	if e = verifyHQProcessUID(pid); e != nil {
		return e
	}
	if e = pairedReleaseStatus(r.Service, j.Approval.MachineFingerprint); e != nil {
		return e
	}
	signer, e := observedSigner(r, j.Owner)
	if e != nil || signer != j.Signer {
		return errors.New("HQ did not confirm its original Machine hardware signer")
	}
	return nil
}

func (j *upgradeJournal) finish(applied bool) error {
	r, e := currentUpgradeReceipt(j.Approval, j.Owner)
	if e != nil {
		return e
	}
	wanted := "applied"
	if !applied {
		wanted = "failed"
	}
	if r.Result != "started" && r.Result != wanted {
		return errors.New("conflicting root receipt; preserving HQ journal")
	}
	if r.Result == "started" {
		r.Result = wanted
		r.Upgrade = &upgradeReceiptEvidence{Approval: j.Approval, Signer: j.Signer}
		r.FinishedAt = time.Now().UTC().Format(approvalTime)
		if !applied {
			r.FailedAt = "service upgrade; previous release restored"
		}
		if e = writeUpgradeFile(ReceiptPath(r.PlanID), encodeReceipt(r), 0644, false); e != nil {
			return e
		}
	}
	want, identity := j.Upgrade.Next.Plist, j.PreparedPlist
	if applied {
		want, identity = j.Upgrade.Previous.Plist, j.OriginalPlist
	}
	if st, err := os.Lstat(j.Stage); err == nil {
		if upgradeNode(st) != identity {
			return errors.New("preserving changed HQ staging inode")
		}
		if e = verifyReviewedPlist(j.Stage, want); e != nil {
			return e
		}
		if e = os.Remove(j.Stage); e != nil {
			return e
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if e = syncUpgradeDir(filepath.Dir(j.Stage)); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(receiptsDir(), upgradeJournalName)); e != nil {
		return e
	}
	if e = syncUpgradeDir(receiptsDir()); e != nil {
		return e
	}
	if !applied {
		return errors.New("previous HQ release, Machine pairing and original hardware signer verified after rollback")
	}
	return nil
}

// Re-entry can finish a verified running candidate or restore the previous
// release. It never starts a new candidate using an expired owner approval.
func resumeServiceUpgrade(saved Saved, owner string, pair upgradePairGuard) (bool, error) {
	path := filepath.Join("/private"+DarwinReceiptsDir, upgradeJournalName)
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return completedUpgrade(saved, owner, pair)
	}
	e := withLaunchLock(syscall.LOCK_EX|syscall.LOCK_NB, func() error {
		data, e := readProtectedUpgradeFile(path)
		if e != nil {
			return e
		}
		j := upgradeJournal{pair: pair}
		if json.Unmarshal(data, &j) != nil || saved.UpgradeFrom == nil || j.Owner != owner || j.Approval.PlanID != saved.PlanID || j.Approval.PlanDigest != saved.PlanDigest || filepath.Dir(j.Stage) != filepath.Dir(launchPlist) || !strings.HasPrefix(filepath.Base(j.Stage), ".hq-reviewed-upgrade-") || filepath.Clean(j.Stage) != j.Stage || j.Signer.Backend != "machine" || j.Signer.Storage != "hardware" {
			return errors.New("protected journal does not identify this upgrade")
		}
		d, e := saved.Plan.Digest()
		if e != nil || d != j.Approval.PlanDigest || len(saved.Plan.Steps) != 2 {
			return errors.New("saved approved upgrade digest changed")
		}
		b, e := json.Marshal(j.Upgrade)
		if e != nil || !bytes.Equal(b, []byte(saved.Plan.Steps[1].Content)) {
			return errors.New("saved upgrade does not match the protected release records")
		}
		if e := pair(j.Approval, nil); e != nil {
			return e
		}
		r, e := currentUpgradeReceipt(j.Approval, owner)
		if e != nil {
			return e
		}
		for _, rec := range []launchRecord{j.Upgrade.Previous, j.Upgrade.Next} {
			capability, err := verifyDarwinRelease(rec.Service, OSHost{})
			if err != nil || capability != launchControlV2 || rec.Plist != renderLaunchPlist(rec.Service, rec.OwnerUID, owner, capability) {
				return errors.New("preserving upgrade state because a retained release no longer verifies")
			}
		}
		return reconcileUpgrade(&j, j.Upgrade, r.Result, j.Phase)
	})
	return true, e
}

// Once the journal is gone, a matching completed receipt supports a strictly
// read-only retry. It cannot start HQ or renew a consumed approval.
func completedUpgrade(saved Saved, owner string, pair upgradePairGuard) (bool, error) {
	if !ValidApproval(saved.PlanID, saved.PlanDigest) {
		return false, nil
	}
	path := filepath.Join("/private"+DarwinReceiptsDir, saved.PlanID+".json")
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	raw, e := readProtectedUpgradeFile(path)
	if e != nil {
		return true, e
	}
	var r Receipt
	if json.Unmarshal(raw, &r) != nil {
		return true, errors.New("cannot read upgrade receipt")
	}
	if r.Result == "started" {
		return false, nil
	}
	if r.Upgrade == nil {
		return true, errors.New("members approval already consumed")
	}
	return true, withLaunchLock(syscall.LOCK_EX|syscall.LOCK_NB, func() error {
		if _, e := os.Lstat(filepath.Join(receiptsDir(), upgradeJournalName)); !errors.Is(e, os.ErrNotExist) {
			return errors.New("another HQ transition is in progress")
		}
		a := r.Upgrade.Approval
		if _, e := currentUpgradeReceipt(a, owner); e != nil {
			return e
		}
		digest, e := saved.Plan.Digest()
		if e != nil || saved.PlanID != a.PlanID || saved.PlanDigest != digest || digest != a.PlanDigest || len(saved.Plan.Steps) != 2 || saved.Plan.Steps[1].Action != upgradeAction {
			return errors.New("saved plan differs from the completed service transition")
		}
		var rec launchUpgrade
		if e := json.Unmarshal([]byte(saved.Plan.Steps[1].Content), &rec); e != nil {
			return e
		}
		j := upgradeJournal{pair: pair, Approval: a, Owner: owner, Signer: r.Upgrade.Signer}
		verify := rec.Next
		if r.Result == "failed" {
			verify = rec.Previous
		} else if r.Result != "applied" {
			return errors.New("unknown upgrade outcome")
		}
		capability, e := verifyDarwinRelease(verify.Service, OSHost{})
		if e != nil || capability != launchControlV2 || verify.Plist != renderLaunchPlist(verify.Service, verify.OwnerUID, owner, capability) {
			return errors.New("previously verified HQ release changed")
		}
		if e := j.verify(verify); e != nil {
			return e
		}
		if r.Result == "failed" {
			return errors.New("prior upgrade rolled back; previous release remains verified")
		}
		return nil
	})
}

func claimUpgradeReceipt(id string, raw []byte) error {
	return writeUpgradeFile(ReceiptPath(id), raw, 0644, true)
}

func reconcileUpgrade(j upgradeOperations, rec launchUpgrade, result, phase string) error {
	if result == "applied" {
		if e := j.verify(rec.Next); e != nil {
			return e
		}
		return j.finish(true)
	}
	if result == "failed" {
		if e := j.verify(rec.Previous); e != nil {
			return e
		}
		return j.finish(false)
	}
	if result != "started" {
		return errors.New("unknown HQ receipt state")
	}
	switch phase {
	case "starting-next":
		if j.verify(rec.Next) == nil {
			return j.finish(true)
		}
	case "prepared", "stopping-previous", "switching", "stopping-next", "restoring-previous", "starting-previous":
	default:
		return errors.New("unrecognized upgrade phase; preserving verified inputs")
	}
	return restorePrevious(j, rec)
}
func restorePrevious(j upgradeOperations, rec launchUpgrade) error {
	old, next := rec.Previous, rec.Next
	activeOld, oldErr := j.active(old)
	if activeOld && oldErr == nil {
		if e := j.verify(old); e != nil {
			return e
		}
		return j.finish(false)
	}
	activeNew, newErr := j.active(next)
	if newErr != nil || (!activeNew && oldErr != nil) {
		return errors.New("preserving an unrecognized HQ job during upgrade rollback")
	}
	if activeNew {
		if e := j.stop(next, "stopping-next"); e != nil {
			return e
		}
	}
	if e := j.clearStoppedEndpoint(); e != nil {
		return e
	}
	if e := j.installed(old); e != nil {
		if e = j.phase("restoring-previous"); e != nil {
			return e
		}
		if e = j.swap(next, old); e != nil {
			return e
		}
	}
	if e := j.phase("starting-previous"); e != nil {
		return e
	}
	if e := j.start(old); e != nil {
		return e
	}
	if e := j.verify(old); e != nil {
		return e
	}
	return j.finish(false)
}

type upgradeOperations interface {
	active(launchRecord) (bool, error)
	installed(launchRecord) error
	stop(launchRecord, string) error
	clearStoppedEndpoint() error
	phase(string) error
	swap(launchRecord, launchRecord) error
	start(launchRecord) error
	verify(launchRecord) error
	finish(bool) error
}

func (j *upgradeJournal) active(r launchRecord) (bool, error) {
	active, _, err := loadedLaunchDaemon(r.Service, j.Owner)
	return active, err
}
func (j *upgradeJournal) installed(r launchRecord) error {
	return verifyReviewedPlist(launchPlist, r.Plist)
}
func (j *upgradeJournal) swap(old, next launchRecord) error {
	live, stage := j.OriginalPlist, j.PreparedPlist
	if old.Plist == j.Upgrade.Next.Plist {
		live, stage = stage, live
	}
	for path, identity := range map[string]upgradeNodeIdentity{launchPlist: live, j.Stage: stage} {
		info, e := os.Lstat(path)
		if e != nil || upgradeNode(info) != identity {
			return errors.New("preserving changed reviewed HQ plist inode")
		}
	}
	return j.pair(j.Approval, func() error { return swapReviewedPlists(j.Stage, old.Plist, next.Plist) })
}
func (j *upgradeJournal) start(r launchRecord) error {
	if e := j.pair(j.Approval, nil); e != nil {
		return e
	}
	return startReviewedRecord(r, j.Owner)
}
