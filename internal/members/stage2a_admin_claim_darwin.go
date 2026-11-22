package members

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// stage2aAdminClaimStore is populated only by the installed authority loader
// after it verifies the local enrolled account and exact approved plan. It is
// deliberately disjoint from the incoming reservation wire format.
type stage2aAdminClaimStore struct {
	path      string
	uid, gid  uint32
	device    int32
	inode     uint64
	birthtime unix.Timespec

	// Historical lookup must authenticate an immutable inventory covering the
	// legacy root-owned store or prove this installation never used that store.
	legacyUnspent func(installationID, startID string) error
}

func (store stage2aAdminClaimStore) open() (*os.File, error) {
	if store.uid == 0 || uint32(os.Getuid()) != store.uid || uint32(os.Geteuid()) != store.uid ||
		store.inode == 0 || store.birthtime.Sec <= 0 || store.legacyUnspent == nil {
		return nil, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(store.path, store.uid)
	if err != nil {
		return nil, err
	}
	if err := store.checkDirectory(dir); err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

// Use a no-follow descriptor walk. The ordinary path ACL check is safe only
// after each opened ancestor has been checked before descending into it;
// updates by the two trusted custodians (root and A) are outside that boundary.
func openStage2aAdminDirectory(path string, uid uint32) (*os.File, error) {
	if !stage2aAbsolutePath(path) {
		return nil, errStage2aReservationAuthority
	}
	fd, err := unix.Open("/", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	current := ""
	for _, part := range strings.Split(path[1:], "/") {
		aclPath := current
		if aclPath == "" {
			aclPath = "/"
		}
		if err := checkStage2aAdminDirectoryNode(fd, aclPath, uid); err != nil {
			unix.Close(fd)
			return nil, err
		}
		child, err := unix.Openat(fd, part, stage2aDirectoryOpenFlags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = child
		current += "/" + part
	}
	if err := checkStage2aAdminDirectoryNode(fd, path, uid); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func checkStage2aAdminDirectoryNode(fd int, path string, uid uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if (st.Uid != 0 && st.Uid != uid) || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
		return errStage2aReservationAuthority
	}
	if path != "/" {
		actual, err := stage2aFDPath(fd)
		if err != nil || actual != path {
			return errStage2aReservationAuthority
		}
	}
	return checkDarwinACLs([]string{path})
}

func (store stage2aAdminClaimStore) checkDirectory(dir *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return err
	}
	if st.Uid != store.uid || st.Gid != store.gid || st.Mode != unix.S_IFDIR|0700 ||
		st.Dev != store.device || st.Ino != store.inode || st.Btim != store.birthtime {
		return errStage2aReservationAuthority
	}
	return nil
}

// stage2aAdminSpend accepts an already authenticated request. Under the
// installation lock it verifies the historical fence and spends the start
// before invoking the signer. Every error after exclusive creation leaves the
// stable name occupied. The authenticated approval lease must be scoped to
// this Machine service incarnation and invalidated on restart.
func stage2aAdminSpend(store stage2aAdminClaimStore, req stage2aReservationRequest,
	authenticate func() error, sign func(*os.File) error) error {
	if authenticate == nil || sign == nil || !req.start.valid() || !soulLaunchID.MatchString(req.launchID) {
		return errStage2aReservationAuthority
	}
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	return stage2aAdminSpendIn(store, dir, req, authenticate, sign)
}

func stage2aAdminSpendIn(store stage2aAdminClaimStore, dir *os.File, req stage2aReservationRequest,
	authenticate func() error, sign func(*os.File) error) error {
	if err := store.checkDirectory(dir); err != nil {
		return err
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, req.start.InstallationID)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := store.checkDirectory(dir); err != nil {
		return err
	}
	name := soulStartClaimName(req.start.InstallationID, req.start.StartID)
	if err := requireUnspentStage2aReservation(dir, name); err != nil {
		return err
	}
	if err := authenticate(); err != nil {
		return err
	}
	if err := store.legacyUnspent(req.start.InstallationID, req.start.StartID); err != nil {
		return err
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return err
	}
	return sign(dir)
}

func spendStage2aAdminName(dir *os.File, name string, uid, gid uint32) (err error) {
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_EXCL|unix.O_CREAT|unix.O_WRONLY, 0600)
	if errors.Is(err, unix.EEXIST) {
		return errStage2aReservationSpent
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, "stage2a-admin-spent/v1"); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	_, err = unix.FcntlInt(file.Fd(), unix.F_FULLFSYNC, 0)
	return err
}

// This is a candidate wire purpose. Wiring any consumer requires the reviewed
// successor contract and an installed local loader, signer and replay fence.
const stage2aAdminReservationPurpose = "agent-bot/stage2a-reservation/v2"

func reserveStage2aAdminStart(store stage2aAdminClaimStore, snapshots stage2aAdminSnapshots,
	req stage2aReservationRequest, authority stage2aReservationAuthority) (stage2aReservation, error) {
	if store.uid != snapshots.uid || authority.load == nil || authority.sign == nil {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	var in stage2aReservationInputs
	var payload stage2aReservationPayload
	var envelope []byte
	err := stage2aAdminSpend(store, req, func() error {
		if err := snapshots.check(); err != nil {
			return err
		}
		var err error
		in, err = authority.load(req)
		if err != nil {
			return err
		}
		for _, identity := range []Stage2aSnapshotIdentity{in.binding.Snapshots.Definition, in.binding.Snapshots.LaunchInputs} {
			if filepath.Dir(identity.RootPath) != snapshots.namespace ||
				!stage2aSnapshotName.MatchString(filepath.Base(identity.RootPath)) {
				return errStage2aReservationAuthority
			}
			dir, err := openStage2aAdminDirectory(identity.RootPath, snapshots.uid)
			if err != nil {
				return err
			}
			actual, _, err := stage2aSnapshotIdentity(int(dir.Fd()), snapshots.uid, snapshots.runnerReadGID)
			dir.Close()
			if err != nil || actual != identity {
				return errStage2aReservationAuthority
			}
		}
		payload, err = prepareStage2aReservationForOwner(req, in, time.Now(), store.uid, snapshots.runnerReadGID)
		return err
	}, func(dir *os.File) error {
		var err error
		if authority.beforeAdminSign != nil {
			if err := authority.beforeAdminSign(dir); err != nil {
				return err
			}
		}
		envelope, err = signStage2aReservation(payload, stage2aAdminReservationPurpose, in.enrolledAdminKey, authority.sign)
		if err != nil {
			return err
		}
		name := ".stage2a-admin-envelope-" + soulStartClaimName(req.start.InstallationID, req.start.StartID)
		return commitStage2aReservation(dir, name, envelope)
	})
	if err != nil {
		return stage2aReservation{}, err
	}
	if !in.expires.After(time.Now()) {
		return stage2aReservation{}, errStage2aReservationExpired
	}
	return stage2aReservation{envelope: envelope, sha256: stage2aReservationSHA256(envelope)}, nil
}
