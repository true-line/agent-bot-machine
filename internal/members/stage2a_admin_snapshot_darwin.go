package members

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// stage2aAdminSnapshots comes from authenticated local installed authority and
// exact plan verification. Snapshot observations and request data never set it.
type stage2aAdminSnapshots struct {
	uid, runnerReadGID uint32
	namespace          string
	namespaceDev       int32
	namespaceInode     uint64
	namespaceBirth     unix.Timespec

	// Check the live, stable identities and exact A/R membership of the
	// dedicated runner group against the installed plan. This is separate
	// from checking the effective group list of the current service process.
	verifyInstalledGroup func() error
}

func (a stage2aAdminSnapshots) check() error {
	if a.uid == 0 || a.runnerReadGID == 0 || a.uid != uint32(os.Getuid()) ||
		a.uid != uint32(os.Geteuid()) || a.namespaceInode == 0 || a.namespaceBirth.Sec <= 0 ||
		a.verifyInstalledGroup == nil {
		return errStage2aReservationAuthority
	}
	if err := a.verifyInstalledGroup(); err != nil {
		return err
	}
	// A owns the frozen tree and can observe it without joining R's private
	// group. R receives only group read/traverse on the published 0555 tree.
	dir, err := openStage2aAdminDirectory(a.namespace, a.uid)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd := int(dir.Fd())
	if err := stage2aPrivateSnapshotParent(fd, a.uid, a.runnerReadGID); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Dev != a.namespaceDev || st.Ino != a.namespaceInode || st.Btim != a.namespaceBirth {
		return errStage2aReservationAuthority
	}
	return nil
}

// publishStage2aAdminSnapshot stages an approved source using A's real
// credentials. Source location and owner/group are independent plan inputs.
func publishStage2aAdminSnapshot(a stage2aAdminSnapshots, source string, sourceUID, sourceGID uint32,
	name string, approved []Stage2aDefinitionRecord) (Stage2aSnapshotIdentity, string, error) {
	if err := a.check(); err != nil {
		return Stage2aSnapshotIdentity{}, "", err
	}
	if sourceUID != 0 && sourceUID != a.uid {
		return Stage2aSnapshotIdentity{}, "", errStage2aReservationAuthority
	}
	sourceDir, err := openStage2aAdminDirectory(source, a.uid)
	if err != nil {
		return Stage2aSnapshotIdentity{}, "", err
	}
	defer sourceDir.Close()
	return publishStage2aFrozenAt(source, a.namespace, name, sourceUID, sourceGID, a.uid, a.runnerReadGID, approved)
}

func observeStage2aAdminSnapshot(a stage2aAdminSnapshots, name string, expected Stage2aSnapshotIdentity,
	approved []Stage2aDefinitionRecord) (string, error) {
	if err := a.check(); err != nil {
		return "", err
	}
	if !stage2aSnapshotName.MatchString(name) || expected.RootPath != filepath.Join(a.namespace, name) ||
		expected.OwnerUID != a.uid || expected.OwnerGID != a.runnerReadGID {
		return "", errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(expected.RootPath, a.uid)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	actual, digest, err := observeStage2aFrozenAt(expected.RootPath, a.uid, a.runnerReadGID, approved)
	if err != nil {
		return "", err
	}
	if actual != expected {
		return "", errors.New("Stage 2a snapshot differs from the approved identity")
	}
	return digest, nil
}
