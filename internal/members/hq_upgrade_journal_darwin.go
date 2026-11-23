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
	BootoutAccepted      bool                `json:"bootout_accepted,omitempty"`
	OriginalPlist        upgradeNodeIdentity `json:"original_plist"`
	PreparedPlist        upgradeNodeIdentity `json:"prepared_plist"`
	pair                 upgradePairGuard
	protectedEvidence    *hqStage2aUpgradeEvidence
	protectedPublication *hqStage2aPublication
	ProtectedDescriptor  *hqStage2aJournalDescriptor `json:"protected_descriptor,omitempty"`
	Approval             Approval                    `json:"approval"`
	Owner                string                      `json:"owner"`
	Upgrade              launchUpgrade               `json:"upgrade"`
	Stage                string                      `json:"staged_plist"`
	Signer               upgradeSigner               `json:"previous_signer"`
	Phase                string                      `json:"phase"`
	Stopping             *stoppingHQ                 `json:"stopping,omitempty"`
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
func (j *upgradeJournal) write(path string, exclusive bool) error {
	b, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return writeUpgradeFile(path, append(b, '\n'), 0600, exclusive)
}
func (j *upgradeJournal) phase(phase string) error {
	j.Phase = phase
	j.Stopping = nil
	j.BootoutAccepted = false
	return j.write(filepath.Join(receiptsDir(), upgradeJournalName), false)
}

func (j *upgradeJournal) stop(r launchRecord, phase string) error {
	if j.Phase == phase {
		return errors.New("an interrupted recorded HQ stop requires reapply")
	}
	return j.stopPublished(r, phase, false)
}

// Only a fresh authenticated apply reaches this method, after bounded observation
// of the exact recorded process. A crash can fall on either side of bootout;
// if acceptance never became durable, recheck the original record before retry.
func (j *upgradeJournal) retryRecordedStop(r launchRecord, phase string) error {
	return j.retryUnconfirmedBootout(phase, func(absent bool) error { return j.stopPublished(r, phase, absent) })
}

func (j *upgradeJournal) retryUnconfirmedBootout(phase string, retry func(bool) error) error {
	if j.BootoutAccepted {
		return errHQJobDraining
	}
	if j.Phase != phase || j.Stopping == nil {
		return errors.New("missing matching HQ stop record")
	}
	return retry(j.Stopping.Socket.Inode == 0)
}

func (j *upgradeJournal) stopPublished(r launchRecord, phase string, absent bool) error {
	parent, err := os.OpenFile(launchRuntimeDir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	var sock os.FileInfo
	if !absent {
		// A failed status probe can coincide with launchd's socket mode
		// publication. Stop only after the same inode reaches its reviewed mode.
		sock, err = waitForLaunchSocket(launchRuntimeSocket, 0, 3*time.Second)
		if err != nil {
			return err
		}
	}
	return j.stopObserved(r, phase, parent, sock)
}

// The caller stopping a failed activation supplies the original directory
// descriptor and socket observed after bootstrap, before the owner status check.
func (j *upgradeJournal) stopObserved(r launchRecord, phase string, parent *os.File, sock os.FileInfo) error {
	err := j.pair(j.Approval, func() error {
		if parent == nil || parent.Name() != launchRuntimeDir {
			return errors.New("missing approved HQ socket directory")
		}
		directory, err := planLaunchDirectory(OSHost{}, checkDarwinACLs)
		if err != nil || !upgradeDirectory(directory, false) {
			return errors.New("protected HQ runtime directory changed before stop")
		}
		if err := verifyReviewedPlist(launchPlist, r.Plist); err != nil {
			return err
		}
		pid, err := waitForApprovedHQPID(3*time.Second, func() (bool, string, error) {
			return loadedLaunchDaemon(r.Service, j.Owner)
		})
		if err != nil {
			return err
		}
		if err := verifyReviewedPlist(launchPlist, r.Plist); err != nil {
			return err
		}
		if err := verifyHQProcessUID(pid); err != nil {
			return err
		}
		evidence, err := observedStopEvidence(parent, filepath.Base(launchRuntimeSocket), sock, pid, 0)
		if err != nil {
			return err
		}
		return j.recordBootout(filepath.Join(receiptsDir(), upgradeJournalName), phase, evidence, func() error {
			return runProgram(launchctl, "bootout", "system/"+launchLabel)
		})
	})
	if err != nil {
		return err
	}
	return j.clearStoppedEndpoint()
}

// launchd can report an approved loaded job before it publishes the child PID.
// A changed or absent job refuses immediately; only that pending PID gets a
// bounded retry before the existing UID and socket-inode checks.
func waitForApprovedHQPID(limit time.Duration, observe func() (bool, string, error)) (string, error) {
	deadline := time.Now().Add(limit)
	for {
		active, pid, err := observe()
		if err != nil || !active {
			return "", errors.New("cannot identify the approved HQ job to stop")
		}
		if pid != "" {
			n, err := strconv.Atoi(pid)
			if err != nil || n <= 0 {
				return "", errors.New("cannot identify the running HQ process to stop")
			}
			return pid, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", errors.New("cannot identify the running HQ process to stop")
		}
		time.Sleep(min(25*time.Millisecond, remaining))
	}
}

func (j *upgradeJournal) recordBootout(path, phase string, evidence *stoppingHQ, bootout func() error) error {
	// A crash can also precede bootout. A repeated stop must identify the
	// same job and endpoint as the first attempt, even when no leaf existed.
	if evidence == nil || (j.Phase == phase && (j.Stopping == nil || *j.Stopping != *evidence)) {
		return errors.New("preserving changed HQ endpoint or process at recorded stop")
	}
	if j.Phase == phase && j.BootoutAccepted {
		return errHQJobDraining
	}
	j.Phase, j.Stopping, j.BootoutAccepted = phase, evidence, false
	if err := j.write(path, false); err != nil {
		return err
	}
	if err := bootout(); err != nil {
		return err
	}
	j.BootoutAccepted = true
	return j.write(path, false)
}

var errHQJobDraining = errors.New("reviewed HQ process remains registered after bootout")

func (j *upgradeJournal) clearStoppedEndpoint() error {
	return j.afterBootout(loadedLaunchDaemon, func() error {
		return clearRecordedEndpoint(launchRuntimeSocket, j.Stopping, func(parent *os.File, sock os.FileInfo, pid string) error {
			return removeStoppedLaunchSocket(launchRuntimeSocket, parent, sock, pid)
		})
	}, 250*time.Millisecond)
}

// Wait only for the job named in this stop record. Every observation and
// removal uses a fresh pairing check. Once absence has been observed, any
// registration is new and must be preserved, even if it has the same argv.
func (j *upgradeJournal) afterBootout(inspect func(HQService, string) (bool, string, error), cleanup func() error, limit time.Duration) error {
	release := j.Upgrade.Next.Service
	if j.Phase == "stopping-previous" {
		release = j.Upgrade.Previous.Service
	}
	recordedPID := ""
	if j.Stopping != nil && (j.Phase == "stopping-previous" || j.Phase == "stopping-next") {
		if n, err := strconv.Atoi(j.Stopping.PID); err == nil && n > 0 && strconv.Itoa(n) == j.Stopping.PID {
			recordedPID = j.Stopping.PID
		}
	}
	gone := false
	deadline := time.Now().Add(limit)
	for {
		retry := false
		err := j.pair(j.Approval, func() error {
			active, pid, err := inspect(release, j.Owner)
			if err != nil {
				return errors.New("cannot verify the registered HQ job after bootout")
			}
			if active {
				if !gone && recordedPID != "" && pid == recordedPID {
					retry = true
					return errHQJobDraining
				}
				return errors.New("preserving a different or unrecorded HQ process after bootout")
			}
			gone = true
			err = cleanup()
			retry = errors.Is(err, syscall.EBUSY)
			return err
		})
		if err == nil || !retry || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(min(25*time.Millisecond, time.Until(deadline)))
	}
}

func observedStopEvidence(parent *os.File, name string, sock os.FileInfo, pid string, uid uint32) (*stoppingHQ, error) {
	dir, err := parent.Stat()
	if err != nil {
		return nil, err
	}
	currentDir, err := os.Lstat(parent.Name())
	if err != nil || !dir.IsDir() || upgradeNode(currentDir) != upgradeNode(dir) {
		return nil, errors.New("protected HQ runtime directory changed before stop")
	}
	path := filepath.Join(parent.Name(), name)
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Record the actual job and parent but no authority to unlink a leaf,
		// including a previously published inode that later reappears.
		return &stoppingHQ{Parent: upgradeNode(dir), PID: pid}, nil
	}
	if err != nil || sock == nil || current.Mode() != os.ModeSocket|0666 || current.Sys().(*syscall.Stat_t).Uid != uid ||
		current.Sys().(*syscall.Stat_t).Nlink != 1 || upgradeNode(current).Inode == 0 || upgradeNode(current) != upgradeNode(sock) {
		return nil, errors.New("preserving changed or unobserved HQ endpoint before stop")
	}
	return &stoppingHQ{upgradeNode(dir), upgradeNode(sock), pid}, nil
}
func clearRecordedEndpoint(path string, stop *stoppingHQ, remove func(*os.File, os.FileInfo, string) error) error {
	unverified := errors.New("preserving endpoint without exact recorded stop provenance")
	if stop == nil {
		// Journals written before any stop have no endpoint ownership evidence.
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return unverified
	}
	parent, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	dir, err := parent.Stat()
	if err != nil || upgradeNode(dir) != stop.Parent {
		return errors.New("protected HQ runtime directory changed after stop")
	}
	// The label and its published leaf can both disappear before the prior
	// process releases the shared HQ state. The outer observation loop retries
	// EBUSY with the pairing lock released between samples.
	pid, err := strconv.Atoi(stop.PID)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != stop.PID {
		return errors.New("missing verified HQ process at recorded stop")
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		if err == nil {
			return errors.Join(errors.New("recorded HQ process is still exiting"), unix.EBUSY)
		}
		return errors.Join(errors.New("cannot confirm recorded HQ process exit"), err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || stop.Socket.Inode == 0 || upgradeNode(info) != stop.Socket {
		return unverified
	}
	return remove(parent, info, stop.PID)
}
func (j *upgradeJournal) verify(r launchRecord) error {
	if r.Stage2a != nil {
		if j.protectedPublication == nil {
			return errors.New(hqStage2aCutoverRefusal)
		}
		if err := j.protectedPublication.recheck(); err != nil {
			return err
		}
	}
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

// The external service and signer probes must finish before this boundary.
func (j *upgradeJournal) commitReceipt(path string, r Receipt, applied bool) error {
	wanted := "applied"
	if !applied {
		wanted = "failed"
	}
	if r.Result != "started" && r.Result != wanted {
		return errors.New("conflicting root receipt; preserving HQ journal")
	}
	if r.Result == wanted {
		if applied {
			return j.pair(j.Approval, nil)
		}
		return nil
	}
	r.Result = wanted
	r.Upgrade = &upgradeReceiptEvidence{Approval: j.Approval, Signer: j.Signer}
	r.FinishedAt = time.Now().UTC().Format(approvalTime)
	if !applied {
		r.FailedAt = "service upgrade; previous release restored"
	}
	data := encodeReceipt(r)
	publish := func() error { return writeUpgradeFile(path, data, 0644, false) }
	if applied {
		return j.pair(j.Approval, publish)
	}
	return publish()
}

func (j *upgradeJournal) finish(applied bool) error {
	r, e := currentUpgradeReceipt(j.Approval, j.Owner)
	if e != nil {
		return e
	}
	if e = j.commitReceipt(ReceiptPath(r.PlanID), r, applied); e != nil {
		return e
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
	e := withLaunchLock(owner, syscall.LOCK_EX|syscall.LOCK_NB, func() error {
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
		if j.ProtectedDescriptor != nil && (j.Upgrade.Next.Stage2a == nil || j.Upgrade.Next.Service.Stage2a == nil) {
			return errors.New("protected descriptor evidence belongs to a different upgrade")
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
			if err != nil || capability != launchControlV2 || !matchesReviewedHQPlist(rec, owner, capability) {
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
	return true, withLaunchLock(owner, syscall.LOCK_EX|syscall.LOCK_NB, func() error {
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
		if e != nil || capability != launchControlV2 || !matchesReviewedHQPlist(verify, owner, capability) {
			return errors.New("previously verified HQ release changed")
		}
		if e := j.verify(verify); e != nil {
			return e
		}
		if r.Result == "failed" {
			return errors.New("prior upgrade rolled back; previous release remains verified")
		}
		return pair(a, nil)
	})
}

func claimUpgradeReceipt(id string, raw []byte) error {
	return writeUpgradeFile(ReceiptPath(id), raw, 0644, true)
}

func reconcileUpgrade(j upgradeOperations, rec launchUpgrade, result, phase string) error {
	// A responsive predecessor may still be serving while launchd drains the
	// recorded process. Its status cannot complete rollback in either stop phase.
	if phase == "stopping-previous" || phase == "stopping-next" {
		if result != "started" && result != "failed" {
			return errors.New("receipt conflicts with a pending HQ stop")
		}
		if err := j.clearStoppedEndpoint(); err != nil {
			if !errors.Is(err, errHQJobDraining) {
				return err
			}
			stopping := rec.Previous
			if phase == "stopping-next" {
				stopping = rec.Next
			}
			if err := j.retryRecordedStop(stopping, phase); err != nil {
				return err
			}
		}
		return restartPrevious(j, rec)
	}
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
	case "prepared", "switching", "restoring-previous", "starting-previous":
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
		if e := rollbackProtectedHQ(j, rec); e != nil {
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
	return restartPrevious(j, rec)
}

func restartPrevious(j upgradeOperations, rec launchUpgrade) error {
	if err := rollbackProtectedHQ(j, rec); err != nil {
		return err
	}
	old, next := rec.Previous, rec.Next
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
	retryRecordedStop(launchRecord, string) error
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
	guardBootstrap := func(submit func() error) error { return j.pair(j.Approval, submit) }
	var protectedCheck func() error
	if r.Stage2a != nil {
		if j.protectedPublication == nil {
			return errors.New(hqStage2aCutoverRefusal)
		}
		protectedCheck = j.protectedPublication.recheck
	}
	return startReviewedRecord(r, j.Owner, guardBootstrap, func(parent *os.File, published os.FileInfo) error {
		phase := "stopping-previous"
		if r.Plist == j.Upgrade.Next.Plist {
			phase = "stopping-next"
		}
		return j.stopObserved(r, phase, parent, published)
	}, protectedCheck)
}
