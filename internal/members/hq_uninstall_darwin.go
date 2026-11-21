package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The root journal describes the concrete resources observed for this removal.
// Its permanent receipt prevents a retry from acting on a later installation.
type uninstallEvidence struct {
	PlanID          string              `json:"plan_id"`
	Digest          string              `json:"plan_digest"`
	Owner           string              `json:"owner"`
	Plist           upgradeNodeIdentity `json:"plist"`
	Job             bool                `json:"job"`
	Endpoint        *stoppingHQ         `json:"endpoint,omitempty"`
	BootoutAccepted bool                `json:"bootout_accepted,omitempty"`
}

func uninstallPlan(state, id string, uid uint32) (Plan, error) {
	var empty Plan
	root, err := os.OpenRoot(state)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Join("members", "plans", id+".json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Sys().(*syscall.Stat_t).Uid != uid {
		return empty, errors.New("expected the original administrator's private saved plan")
	}
	const limit = 256 << 10
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	var saved Saved
	if err != nil || len(raw) > limit || json.Unmarshal(raw, &saved) != nil || saved.PlanID != id {
		return empty, errors.New("cannot read the original saved plan")
	}
	return saved.Plan, nil
}

func uninstallDarwinHQ(owner, state, id string, preview bool) (string, error) {
	uid, err := uninstallOwnerUID(owner)
	if err != nil {
		return "", err
	}
	rec, cap, digest, err := uninstallRecord(owner, state, id, uid)
	if err != nil {
		return "", err
	}
	outer, e := lockHQPackage(owner)
	if e != nil {
		return "", e
	}
	defer outer.Close()
	physicalReceipts := filepath.Join("/private", DarwinReceiptsDir)
	var result string
	mode := syscall.LOCK_EX
	if preview {
		mode = syscall.LOCK_SH
	}
	err = withHQResourceLock(physicalReceipts, mode|syscall.LOCK_NB, func() error {
		if _, e := os.Lstat(filepath.Join(physicalReceipts, upgradeJournalName)); !errors.Is(e, os.ErrNotExist) {
			return errors.New("an HQ upgrade requires reconciliation before uninstall")
		}
		if e := receiptForUpgrade(OSHost{}, id, digest, owner, checkDarwinACLs); e != nil {
			return e
		}
		var e error
		result, e = removeReviewedHQ(physicalReceipts, newUninstallHost(rec, owner), socketForCapability(cap), uninstallEvidence{PlanID: id, Digest: digest, Owner: owner}, preview)
		return e
	})
	return result, err
}

func readUninstallEvidence(path string, want uninstallEvidence) (*uninstallEvidence, error) {
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil, nil
	} else if e != nil {
		return nil, e
	}
	raw, e := readProtectedUpgradeFile(path)
	if e != nil {
		return nil, e
	}
	var j uninstallEvidence
	if json.Unmarshal(raw, &j) != nil || j.PlanID != want.PlanID || j.Owner != want.Owner || j.Digest != want.Digest {
		return nil, errors.New("an HQ uninstall record belongs to a different plan or administrator")
	}
	return &j, nil
}

func checkedUninstallPlist(want string) (upgradeNodeIdentity, error) {
	var zero upgradeNodeIdentity
	if e := trustedPath(OSHost{}, filepath.Dir(launchPlist), true); e != nil {
		return zero, e
	}
	if e := checkDarwinACLs(pathAncestry(filepath.Dir(launchPlist))); e != nil {
		return zero, e
	}
	st, e := os.Lstat(launchPlist)
	if errors.Is(e, os.ErrNotExist) {
		return zero, nil
	}
	if e != nil {
		return zero, e
	}
	if e = verifyReviewedPlist(launchPlist, want); e != nil {
		return zero, e
	}
	return upgradeNode(st), nil
}

func uninstallEndpoint(path, pid string, job bool) (*stoppingHQ, error) {
	parentPath := filepath.Dir(path)
	if !job && path == launchRuntimeSocket {
		if _, e := os.Lstat(parentPath); errors.Is(e, os.ErrNotExist) {
			if e = trustedPath(OSHost{}, filepath.Dir(parentPath), true); e != nil {
				return nil, e
			}
			if e = checkDarwinACLs(pathAncestry(filepath.Dir(parentPath))); e != nil {
				return nil, e
			}
			return &stoppingHQ{}, nil
		}
	}
	if e := trustedPath(OSHost{}, parentPath, true); e != nil {
		return nil, e
	}
	if e := checkDarwinACLs(pathAncestry(parentPath)); e != nil {
		return nil, e
	}
	parent, e := os.OpenFile(parentPath, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	st, e := os.Lstat(path)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if st != nil && !job {
		return nil, errors.New("preserving an occupied endpoint without an identified running HQ")
	}
	if pid != "" {
		n, e := strconv.Atoi(pid)
		if e != nil || n <= 0 || strconv.Itoa(n) != pid {
			return nil, errors.New("unverified HQ process ID")
		}
		if e = verifyHQProcessUID(pid); e != nil {
			return nil, e
		}
	}
	return observedStopEvidence(parent, filepath.Base(path), st, pid, 0)
}

// CheckDarwinHarnessLaunchRemoval preserves the paired approval path until the
// exact installed launch grant has been retired. Call under the lifecycle lock.
func CheckDarwinHarnessLaunchRemoval() error {
	return checkUninstallLaunchFiles(os.Lstat, readUninstallGrantDir, os.Geteuid() == 0)
}

func readUninstallGrantDir(path string) ([]os.DirEntry, error) {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.ReadDir(-1)
}

func checkUninstallLaunchFiles(lstat func(string) (os.FileInfo, error), readDir func(string) ([]os.DirEntry, error), privileged bool) error {
	const sudoers = "/private/etc/sudoers.d"
	unknown := errors.New("cannot verify absence of harness launch files. Have the administrator inspect the grant before uninstall")
	for _, group := range []struct {
		dir   string
		files []string
	}{
		{launchRuntimeDir, []string{"harness-launch", "harness-egress.sb", "harness-launch-policy.json"}},
		{sudoers, []string{"agent-bot-hq-harness-launch"}},
	} {
		// The prefix owner may be unable to inspect sudoers.d. By the time
		// we reach it all public payloads and their staging names are absent.
		inaccessibleRule := !privileged && group.dir == sudoers
		for _, name := range group.files {
			_, err := lstat(filepath.Join(group.dir, name))
			if err == nil {
				return errors.New("retire the installed harness launch grant through paired HQ before uninstall, or have the administrator reconcile partial or changed files")
			}
			if !errors.Is(err, os.ErrNotExist) && !(inaccessibleRule && errors.Is(err, os.ErrPermission)) {
				return unknown
			}
		}
		entries, err := readDir(group.dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || inaccessibleRule && errors.Is(err, os.ErrPermission) {
				continue
			}
			return unknown
		}
		for _, entry := range entries {
			staged, ok := strings.CutPrefix(entry.Name(), ".harness-")
			if !ok {
				continue
			}
			for _, name := range group.files {
				id, ok := strings.CutSuffix(staged, "-"+name)
				if ok && validUninstallID(id) {
					return errors.New("a harness launch transition has staged files. Have the administrator resume or reconcile the original plan before uninstall")
				}
			}
		}
	}
	return nil
}

// The two launchd calls and protected file observations are independent
// system boundaries. Fixture tests run the same journal and removal ordering.
type uninstallHost struct {
	grantAbsent  func() error
	observe      func() (bool, string, error)
	plist        func() (upgradeNodeIdentity, error)
	unlinkPlist  func() error
	syncPlistDir func() error
	capture      func(string, string, bool) (*stoppingHQ, error)
	clean        func(string, *stoppingHQ, bool) error
	bootout      func() error
	waitPID      func(string) error
	readRecord   func(string, uninstallEvidence) (*uninstallEvidence, error)
}

func newUninstallHost(r launchRecord, owner string) uninstallHost {
	observe := func() (bool, string, error) { return loadedLaunchDaemon(r.Service, owner) }
	return uninstallHost{
		grantAbsent:  CheckDarwinHarnessLaunchRemoval,
		observe:      observe,
		plist:        func() (upgradeNodeIdentity, error) { return checkedUninstallPlist(r.Plist) },
		unlinkPlist:  func() error { return os.Remove(launchPlist) },
		syncPlistDir: func() error { return syncUpgradeDir(filepath.Dir(launchPlist)) },
		capture:      uninstallEndpoint,
		clean: func(path string, stop *stoppingHQ, preview bool) error {
			return checkUninstallEndpoint(path, stop, preview, func() error {
				active, _, err := observe()
				if err != nil || active {
					return errors.New("cannot verify absence of the reviewed HQ job")
				}
				return waitForUninstalledHQPID(stop.PID)
			})
		},
		waitPID:    waitForUninstalledHQPID,
		bootout:    func() error { return runProgram(launchctl, "bootout", "system/"+launchLabel) },
		readRecord: readUninstallEvidence,
	}
}

// A registered on-demand job may have no running process. Its exact plist
// and argv permit targeted bootout. Only launchd may clear an occupied leaf
// in this case; the removal has no identified process from which to claim it.
func checkUninstallEndpoint(path string, s *stoppingHQ, preview bool, confirmStopped func() error) error {
	if s != nil && s.Parent.Inode == 0 {
		if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return errors.New("preserving an endpoint that appeared after the runtime directory was absent")
	}
	return clearRecordedEndpoint(path, s, func(parent *os.File, sock os.FileInfo, pid string) error {
		if pid == "" {
			return errors.New("preserving an occupied HQ endpoint without a recorded running process")
		}
		if preview {
			return nil
		}
		err := removeStoppedLaunchSocket(path, parent, sock, pid)
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
			return err
		}
		release, sysErr := unix.Sysctl("kern.osrelease")
		major, _, _ := strings.Cut(release, ".")
		if sysErr != nil || major != "24" {
			return err
		}
		return unlinkDetachedUninstallSocket(parent, filepath.Base(path), sock, 0, func() error {
			if err := confirmStopped(); err != nil {
				return err
			}
			if err := trustedPath(OSHost{}, parent.Name(), true); err != nil {
				return err
			}
			return checkDarwinACLs(pathAncestry(parent.Name()))
		})
	})
}

// Only receipt-backed uninstall can take this Darwin 24 path. The callers
// hold the package and HQ lifecycle locks and have captured the running job,
// PID, protected parent and socket before bootout. Recheck them after probes.
func unlinkDetachedUninstallSocket(parent *os.File, name string, sock os.FileInfo, uid uint32, confirmStopped func() error) error {
	if err := checkStoppedSocketIdentity(parent, name, sock, uid); err != nil {
		return err
	}
	if err := CheckDetachedDarwinSocket(filepath.Join(parent.Name(), name)); err != nil {
		return err
	}
	if err := confirmStopped(); err != nil {
		return err
	}
	if err := checkStoppedSocketIdentity(parent, name, sock, uid); err != nil {
		return err
	}
	return unix.Unlinkat(int(parent.Fd()), name, 0)
}

func removeReviewedHQ(dir string, h uninstallHost, endpoint string, want uninstallEvidence, preview bool) (string, error) {
	journal := filepath.Join(dir, uninstallJournalName)
	donePath := filepath.Join(dir, want.PlanID+".hq-uninstalled.json")
	j, e := h.readRecord(journal, want)
	if e != nil {
		return "", e
	}
	done, e := h.readRecord(donePath, want)
	if e != nil {
		return "", e
	}
	active, pid, e := h.observe()
	if e != nil {
		return "", e
	}
	plist, e := h.plist()
	if e != nil {
		return "", e
	}
	if done != nil {
		if j != nil || active || plist.Inode != 0 {
			return "", errors.New("completed removal cannot authorize a later HQ installation")
		}
		if _, e = os.Lstat(endpoint); !errors.Is(e, os.ErrNotExist) {
			return "", errors.New("preserving an endpoint that appeared after completed removal")
		}
		// An interrupted publication may have renamed the receipt before its
		// directory was synced. Confirm that last step on an explicit retry.
		if !preview {
			if e = syncUpgradeDir(dir); e != nil {
				return "", e
			}
		}
		return "already-uninstalled", nil
	}
	// Even an absent service can still have the only unspent installation
	// receipt. Keep it available for retirement rather than consuming it here.
	if e = h.grantAbsent(); e != nil {
		return "", e
	}
	if active && plist.Inode == 0 {
		return "", errors.New("preserving a registered HQ job without its matching plist")
	}
	if j == nil {
		if !active && plist.Inode == 0 {
			if _, e = os.Lstat(endpoint); !errors.Is(e, os.ErrNotExist) {
				return "", errors.New("preserving an unverified endpoint from an absent service")
			}
			// Retire this plan even when there are no service resources left.
			// Its plist bytes may match a later installation of the same release.
			if !preview {
				if e = writeUninstallEvidence(donePath, &want, true); e != nil {
					return "", e
				}
			}
			return "already-absent", nil
		}
		stop, e := h.capture(endpoint, pid, active)
		if e != nil {
			return "", e
		}
		want.Plist, want.Job, want.Endpoint = plist, active, stop
		j = &want
		if !preview {
			if e = writeUninstallEvidence(journal, j, true); e != nil {
				return "", e
			}
		}
	}
	if j.Endpoint == nil || plist.Inode != 0 && plist != j.Plist {
		return "", errors.New("preserving changed HQ plist or missing uninstall evidence")
	}
	// Recheck identity after the durable capture and before requesting bootout.
	active, pid, e = h.observe()
	if e != nil {
		return "", e
	}
	if active {
		if !j.Job || pid != j.Endpoint.PID {
			return "", errors.New("preserving a different HQ job")
		}
		observed, e := h.capture(endpoint, pid, true)
		if e != nil {
			return "", e
		}
		if *observed != *j.Endpoint && !(j.BootoutAccepted && observed.PID == j.Endpoint.PID && observed.Parent == j.Endpoint.Parent && observed.Socket.Inode == 0) {
			return "", errors.New("preserving a changed endpoint or process before bootout")
		}
	}
	if preview {
		if !active {
			if e = h.clean(endpoint, j.Endpoint, true); e != nil {
				return "", e
			}
		}
		return "would-uninstall", nil
	}
	if active && !j.BootoutAccepted {
		current, e := h.plist()
		if e != nil || current != j.Plist {
			return "", errors.New("preserving a changed HQ plist before bootout")
		}
		if e = h.bootout(); e != nil {
			return "", e
		}
		j.BootoutAccepted = true
		if e = writeUninstallEvidence(journal, j, false); e != nil {
			return "", e
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		active, pid, e = h.observe()
		if e != nil {
			return "", e
		}
		if !active {
			break
		}
		if !j.Job || pid != j.Endpoint.PID || !time.Now().Before(deadline) {
			return "", errors.New("HQ bootout has not settled; preserving files")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if e = h.waitPID(j.Endpoint.PID); e != nil {
		return "", e
	}
	if e = h.clean(endpoint, j.Endpoint, false); e != nil {
		if errors.Is(e, unix.EINVAL) || errors.Is(e, unix.ENOTSUP) {
			return "", errors.New("HQ job unloaded; this macOS kernel cannot prove the retained endpoint is unused. Keep the uninstall journal and retry after the endpoint has been independently cleared")
		}
		return "", e
	}
	if active, _, e := h.observe(); e != nil || active {
		return "", errors.New("cannot verify absence of the reviewed HQ job")
	}
	plist, e = h.plist()
	if e != nil {
		return "", e
	}
	if plist.Inode != 0 {
		if plist != j.Plist {
			return "", errors.New("preserving a replacement HQ plist")
		}
		if e = h.unlinkPlist(); e != nil {
			return "", e
		}
	}
	// Also sync on re-entry after interruption between unlink and directory sync.
	if e = h.syncPlistDir(); e != nil {
		return "", e
	}
	// One exclusive rename in the same protected directory converts pending
	// evidence to the final receipt. No separate deletion follows publication.
	if e = unix.RenamexNp(journal, donePath, unix.RENAME_EXCL); e != nil {
		return "", fmt.Errorf("publishing completed HQ uninstall receipt: %w", e)
	}
	if e = syncUpgradeDir(dir); e != nil {
		return "", e
	}
	return "uninstalled", nil
}

func writeUninstallEvidence(path string, j *uninstallEvidence, exclusive bool) error {
	raw, e := json.Marshal(j)
	if e != nil {
		return e
	}
	return writeUpgradeFile(path, raw, 0600, exclusive)
}

func uninstallOwnerUID(owner string) (uint64, error) {
	u, err := user.Lookup(owner)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, errors.New("invalid invoking administrator")
	}
	return uid, nil
}
func uninstallRecord(owner, state, id string, uid uint64) (launchRecord, string, string, error) {
	p, err := uninstallPlan(state, id, uint32(uid))
	if err != nil {
		return launchRecord{}, "", "", err
	}
	return reviewedUninstallRecord(p, owner, id, uid, OSHost{}, checkDarwinACLs)
}

func reviewedUninstallRecord(p Plan, owner, id string, uid uint64, h Host, checkACL func([]string) error) (launchRecord, string, string, error) {
	digest, err := p.Digest()
	if err != nil {
		return launchRecord{}, "", "", err
	}
	rec, err := priorLaunchRecord(p, owner)
	if err != nil {
		return launchRecord{}, "", "", err
	}
	cap := launchControlV1
	if rec.RuntimeDir != nil {
		if !upgradeDirectory(rec.RuntimeDir, true) {
			return launchRecord{}, "", "", errors.New("invalid reviewed HQ runtime directory")
		}
		cap = launchControlV2
	}
	if rec.OwnerUID != int(uid) || rec.Service.validate() != nil || rec.Plist != renderLaunchPlist(rec.Service, int(uid), owner, cap) {
		return launchRecord{}, "", "", errors.New("the applied plan does not identify this administrator's exact HQ plist")
	}
	// No program or file from the retained release is executed. The original
	// root receipt authenticates its canonical plan, including argv and plist.
	if err := receiptForUpgrade(h, id, digest, owner, checkACL); err != nil {
		return launchRecord{}, "", "", err
	}
	return rec, cap, digest, nil
}

// Before the first root apply, some or all of Machine's receipt directories
// can be absent. Validate the existing ancestry, including the system's db
// directory, before treating that absence as an empty read-only snapshot.
func hqUninstallReceiptsPresent(h Host, checkACL func([]string) error) (bool, error) {
	base := filepath.Join("/private", DarwinReceiptsDir)
	dir := base
	for dir != "/private/var/db" && dir != filepath.Dir(dir) {
		_, present, err := h.Lstat(dir)
		if err != nil {
			return false, err
		}
		if present {
			break
		}
		dir = filepath.Dir(dir)
	}
	if err := trustedPath(h, dir, true); err != nil {
		return false, err
	}
	if err := checkACL(pathAncestry(dir)); err != nil {
		return false, err
	}
	return dir == base, nil
}

// Candidate IDs are offered only when a completed root receipt authenticates
// the retained plan and the live plist has exactly its reviewed contents.
func listHQUninstallPlans(owner, state string) ([]string, string, error) {
	uid, err := uninstallOwnerUID(owner)
	if err != nil {
		return nil, "", err
	}
	present, err := hqUninstallReceiptsPresent(OSHost{}, checkDarwinACLs)
	if err != nil {
		return nil, "", err
	}
	ids := []string{}
	if !present {
		return ids, "", nil
	}
	base := filepath.Join("/private", DarwinReceiptsDir)
	var resume string
	err = withHQResourceLock(base, syscall.LOCK_SH|syscall.LOCK_NB, func() error {
		pending := filepath.Join(base, uninstallJournalName)
		if _, e := os.Lstat(pending); e == nil {
			raw, e := readProtectedUpgradeFile(pending)
			if e != nil {
				return e
			}
			resume, e = resumeUninstallID(raw, owner, func(id string) (string, error) {
				_, _, digest, e := uninstallRecord(owner, state, id, uid)
				return digest, e
			})
			if e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		f, e := os.Open(base)
		if e != nil {
			return e
		}
		defer f.Close()
		names, e := f.Readdirnames(4097)
		if e != nil && !errors.Is(e, io.EOF) {
			return e
		}
		if len(names) > 4096 {
			return errors.New("too many receipt files for automatic discovery")
		}
		ids = matchingUninstallPlans(names, func(id string) bool {
			r, _, _, e := uninstallRecord(owner, state, id, uid)
			if e != nil {
				return false
			}
			m, e := checkedUninstallPlist(r.Plist)
			return e == nil && m.Inode != 0
		})
		return nil
	})
	return ids, resume, err
}

func resumeUninstallID(raw []byte, owner string, receiptDigest func(string) (string, error)) (string, error) {
	var j uninstallEvidence
	if json.Unmarshal(raw, &j) != nil || !ValidApproval(j.PlanID, j.Digest) || j.Owner != owner {
		return "", errors.New("an outstanding HQ uninstall requires its original administrator and receipt")
	}
	digest, err := receiptDigest(j.PlanID)
	if err != nil || digest != j.Digest {
		return "", errors.New("the outstanding uninstall no longer matches the original plan and root receipt")
	}
	return j.PlanID, nil
}

func matchingUninstallPlans(names []string, matches func(string) bool) []string {
	// A later installation can have identical plist bytes. An existing
	// completion entry permanently disqualifies its earlier plan ID.
	spent := make(map[string]bool)
	for _, name := range names {
		if id, ok := strings.CutSuffix(name, ".hq-uninstalled.json"); ok {
			spent[id] = true
		}
	}
	result := []string{}
	for _, name := range names {
		if id, ok := strings.CutSuffix(name, ".json"); ok && validUninstallID(id) && !spent[id] && matches(id) {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

// A successful bootout and missing pathname can precede process exit.
// Probe the recorded PID without terminating it. A remaining or reused PID
// leaves the progress record intact for the administrator's next attempt.
func waitForUninstalledHQPID(pid string) error {
	if pid == "" {
		return nil
	}
	n, e := strconv.Atoi(pid)
	if e != nil || n <= 0 || strconv.Itoa(n) != pid {
		return errors.New("invalid recorded HQ PID")
	}
	deadline := time.Now().Add(time.Second)
	for {
		e = unix.Kill(n, 0)
		if errors.Is(e, unix.ESRCH) {
			return nil
		}
		if e != nil || !time.Now().Before(deadline) {
			return errors.New("recorded HQ process may still exist; retaining the uninstall journal and plist")
		}
		time.Sleep(25 * time.Millisecond)
	}
}
