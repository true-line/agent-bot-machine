package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// observeInstalledStage2aLaunchInputs reopens A's exact frozen runtime tree
// while the per-installation start claim is serialized. The host projection
// values are checked against separately opened descriptor bytes.
func observeInstalledStage2aLaunchInputs(a stage2aAdminSnapshots, binding Stage2aMeasurementBinding,
	input Stage2aLaunchInputRecords) error {
	invalid := errors.New("installed Stage 2a launch inputs differ from approved bytes")
	if err := a.check(); err != nil {
		return invalid
	}
	identity := binding.Snapshots.LaunchInputs
	if filepath.Dir(identity.RootPath) != a.namespace || identity.OwnerUID != a.uid ||
		identity.OwnerGID != a.runnerReadGID ||
		input.EffectiveConfig["profile"] != binding.ProfileInForce {
		return invalid
	}
	digest, _, err := Stage2aLaunchInputDigest(input)
	if err != nil || digest != binding.LaunchInputMeasurement ||
		stage2aCheckRuntimeSnapshot(identity, input.Files) != nil {
		return invalid
	}
	adapters, err := stage2aReadProjectedFile(identity, input.Files, "host/adapters.json")
	if err != nil {
		return invalid
	}
	installation, err := stage2aReadProjectedFile(identity, input.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(input, adapters, installation) != nil {
		return invalid
	}
	return nil
}

func stage2aReadProjectedFile(identity Stage2aSnapshotIdentity, records []Stage2aDefinitionRecord,
	relative string) ([]byte, error) {
	invalid := errors.New("invalid Stage 2a host projection descriptor")
	if relative != "host/adapters.json" && relative != "host/installation.json" {
		return nil, invalid
	}
	var approved *Stage2aDefinitionRecord
	for i := range records {
		if records[i].Path == relative {
			approved = &records[i]
			break
		}
	}
	if approved == nil || approved.Kind != "regular" || approved.Size == nil || *approved.Size > 64<<10 {
		return nil, invalid
	}
	root, err := openStage2aAdminDirectory(identity.RootPath, identity.OwnerUID)
	if err != nil {
		return nil, invalid
	}
	defer root.Close()
	observed, _, err := stage2aSnapshotIdentity(int(root.Fd()), identity.OwnerUID, identity.OwnerGID)
	if err != nil || observed != identity {
		return nil, invalid
	}
	host, err := unix.Openat(int(root.Fd()), "host", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, invalid
	}
	defer unix.Close(host)
	var parent unix.Stat_t
	if parent, err = stage2aCheckedNode(host, identity.OwnerUID, identity.OwnerGID); err != nil ||
		parent.Mode&unix.S_IFMT != unix.S_IFDIR || checkDarwinACLs([]string{filepath.Join(identity.RootPath, "host")}) != nil {
		return nil, invalid
	}
	fd, err := unix.Openat(host, filepath.Base(relative), stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, invalid
	}
	file := os.NewFile(uintptr(fd), relative)
	defer file.Close()
	before, err := stage2aCheckedNode(fd, identity.OwnerUID, identity.OwnerGID)
	mode, modeErr := strconv.ParseUint(approved.Mode, 8, 32)
	if err != nil || modeErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != uint16(mode) || before.Size != int64(*approved.Size) ||
		checkDarwinACLs([]string{filepath.Join(identity.RootPath, relative)}) != nil {
		return nil, invalid
	}
	body, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	var after unix.Stat_t
	if err != nil || uint64(len(body)) != *approved.Size || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || fmt.Sprintf("%x", sha256.Sum256(body)) != approved.SHA256 {
		return nil, invalid
	}
	return body, nil
}
