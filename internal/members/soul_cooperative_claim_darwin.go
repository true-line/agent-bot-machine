//go:build darwin

package members

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func cooperativeActiveName(installationID string) string {
	return ".cooperative-active-" + soulEndpointInstallationSlot(installationID)
}

func cooperativeSpentName(installationID, startID string) string {
	return ".cooperative-spent-" + soulStartClaimName(installationID, startID)
}

// spendSoulCooperativeStart consumes a start in the separately installed
// A-owned claim directory. Its loader must supply the descriptor identity and
// a historical cross-profile replay check. A lost reply remains spent; a
// crash leaves the installation active until a verified containment cleanup.
func spendSoulCooperativeStart(store stage2aAdminClaimStore, q SoulCooperativeReserveRequest) error {
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	return spendSoulCooperativeStartIn(store, dir, q)
}

func spendSoulCooperativeStartIn(store stage2aAdminClaimStore, dir *os.File, q SoulCooperativeReserveRequest) error {
	if q.Profile != "managed-cooperative" || !soulInstallationID.MatchString(q.InstallationID) ||
		!soulStartID.MatchString(q.StartID) || store.legacyUnspent == nil || store.checkDirectory(dir) != nil {
		return errSoulCooperativeAuthority
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return err
	}
	defer lock.Close()
	active, spent := cooperativeActiveName(q.InstallationID), cooperativeSpentName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil || requireUnspentStage2aReservation(dir, active) != nil ||
		requireUnspentStage2aReservation(dir, spent) != nil ||
		store.legacyUnspent(q.InstallationID, q.StartID) != nil {
		return errSoulCooperativeAuthority
	}
	if err := spendStage2aAdminName(dir, spent, store.uid, store.gid); err != nil {
		return err
	}
	return createCooperativeActive(dir, active, q.StartID, store.uid, store.gid)
}

func createCooperativeActive(dir *os.File, name, startID string, uid, gid uint32) (err error) {
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_EXCL|unix.O_CREAT|unix.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if err := checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600); err != nil {
		return err
	}
	if _, err := f.WriteString(startID + "\n"); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		return err
	}
	return dir.Sync()
}

// releaseSoulCooperativeStart removes only the exact active start and only
// after Machine independently confirms the runner process group and UID are
// idle and the endpoint has closed. A failed check leaves the slot occupied.
func releaseSoulCooperativeStart(store stage2aAdminClaimStore, q SoulCooperativeReserveRequest,
	contained func() (bool, error)) error {
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	return releaseSoulCooperativeStartIn(store, dir, q, contained)
}

func releaseSoulCooperativeStartIn(store stage2aAdminClaimStore, dir *os.File, q SoulCooperativeReserveRequest,
	contained func() (bool, error)) error {
	if q.Profile != "managed-cooperative" || !soulInstallationID.MatchString(q.InstallationID) ||
		!soulStartID.MatchString(q.StartID) || contained == nil || store.checkDirectory(dir) != nil {
		return errSoulCooperativeAuthority
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return err
	}
	defer lock.Close()
	name := cooperativeActiveName(q.InstallationID)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_RDONLY, 0)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if checkStage2aReservationFile(fd, store.uid, store.gid, unix.S_IFREG|0600) != nil {
		return errSoulCooperativeAuthority
	}
	content, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil || string(content) != q.StartID+"\n" {
		return errSoulCooperativeAuthority
	}
	ok, err := contained()
	if err != nil || !ok || store.checkDirectory(dir) != nil {
		return errSoulCooperativeAuthority
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		return errors.Join(errSoulCooperativeAuthority, err)
	}
	return dir.Sync()
}
