//go:build darwin

package members

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func stage2aHOpenSourceV3(path string, sourceUID uint32, limit int64) (*os.File, unix.Stat_t, error) {
	var empty unix.Stat_t
	if !stage2aAbsolutePath(path) || limit < 1 {
		return nil, empty, errStage2aReservationAuthority
	}
	parent, err := openStage2aAdminDirectory(filepath.Dir(path), sourceUID)
	if err != nil {
		return nil, empty, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, empty, err
	}
	file := os.NewFile(uintptr(fd), path)
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&06022 != 0 || before.Nlink != 1 ||
		(before.Uid != 0 && before.Uid != sourceUID) ||
		before.Size < 1 || before.Size > limit || checkDarwinACLs([]string{path}) != nil {
		file.Close()
		return nil, empty, errStage2aReservationAuthority
	}
	return file, before, nil
}

func stage2aHReadSmallSourceV3(path string, sourceUID uint32) ([]byte, error) {
	const limit = 2 << 20
	file, before, err := stage2aHOpenSourceV3(path, sourceUID, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	var after unix.Stat_t
	if err != nil || int64(len(raw)) != before.Size ||
		unix.Fstat(int(file.Fd()), &after) != nil || !stage2aSameNode(before, after) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}

// Only the owner-plan install path may call this root-only reader. It proves
// exact private file bytes against authenticated pins but never creates a seal,
// signs a descriptor, or grants a protected HQ start.
func stage2aVerifyHSourceFilesV3(inventoryPath, manifestPath, hqTarPath, nodePath string,
	sourceUID uint32, pins stage2aHSourceReleasePinsV3) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 ||
		inventoryPath == manifestPath || inventoryPath == hqTarPath ||
		inventoryPath == nodePath || manifestPath == hqTarPath ||
		manifestPath == nodePath || hqTarPath == nodePath {
		return errStage2aReservationAuthority
	}
	inv, err := stage2aHReadSmallSourceV3(inventoryPath, sourceUID)
	if err != nil {
		return err
	}
	manifest, err := stage2aHReadSmallSourceV3(manifestPath, sourceUID)
	if err != nil {
		return err
	}
	hq, hqBefore, err := stage2aHOpenSourceV3(hqTarPath, sourceUID, 2<<30)
	if err != nil {
		return err
	}
	defer hq.Close()
	node, nodeBefore, err := stage2aHOpenSourceV3(nodePath, sourceUID, stage2aV3MaxInventoryFileBytes)
	if err != nil {
		return err
	}
	defer node.Close()
	if stage2aVerifyHSourceBytesV3(inv, manifest, hq, hqBefore.Size,
		node, nodeBefore.Size, pins) != nil {
		return errStage2aReservationAuthority
	}
	var hqAfter, nodeAfter unix.Stat_t
	if unix.Fstat(int(hq.Fd()), &hqAfter) != nil || !stage2aSameNode(hqBefore, hqAfter) ||
		unix.Fstat(int(node.Fd()), &nodeAfter) != nil || !stage2aSameNode(nodeBefore, nodeAfter) {
		return errStage2aReservationAuthority
	}
	return nil
}
