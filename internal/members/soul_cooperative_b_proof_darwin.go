//go:build darwin

package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func cooperativeBProofPath(installationID, startID string) (string, string, error) {
	if !soulInstallationID.MatchString(installationID) || !soulStartID.MatchString(startID) {
		return "", "", errSoulCooperativeAuthority
	}
	return filepath.Join(stage2aProofParent, soulEndpointInstallationSlot(installationID)),
		soulEndpointStartSlot(installationID, startID) + ".cooperative.proof", nil
}

// A removes the one-use B proof only after both guest accounts and their
// endpoints are independently observed idle. Recovery may lack the in-memory
// digest, but still verifies the fixed root-owned A:B proof inode before unlink.
func revokeCooperativeBProof(p SoulCooperativeLaunchPolicy, startID, wantSHA string) error {
	if p.Bridge == nil || p.MachineUID != os.Getuid() || p.MachineUID != os.Geteuid() ||
		startID != p.ReviewedStartID ||
		(wantSHA != "" && !stage2aPrefixedDigest.MatchString(wantSHA)) {
		return errSoulCooperativeAuthority
	}
	path, name, err := cooperativeBProofPath(p.Runner.InstallationID, startID)
	if err != nil {
		return err
	}
	dir, err := openStage2aAdminDirectory(path, uint32(p.MachineUID))
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|02710 ||
		parent.Uid != uint32(p.MachineUID) || parent.Gid != uint32(p.Bridge.GID) {
		return errSoulCooperativeAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0440 || st.Nlink != 1 ||
		st.Uid != uint32(p.MachineUID) || st.Gid != uint32(p.Bridge.GID) || st.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(path, name)}) != nil {
		return errSoulCooperativeAuthority
	}
	proof, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(proof) != 32 ||
		(wantSHA != "" && fmt.Sprintf("sha256:%x", sha256.Sum256(proof)) != wantSHA) {
		clear(proof)
		return errSoulCooperativeAuthority
	}
	clear(proof)
	if unix.Unlinkat(int(dir.Fd()), name, 0) != nil || dir.Sync() != nil {
		return errSoulCooperativeAuthority
	}
	return nil
}

func publishCooperativeBProof(p SoulCooperativeLaunchPolicy, startID string, proof []byte) error {
	if p.Bridge == nil || len(proof) != 32 || p.MachineUID != os.Getuid() ||
		p.MachineUID != os.Geteuid() || startID != p.ReviewedStartID {
		return errSoulCooperativeAuthority
	}
	path, name, err := cooperativeBProofPath(p.Runner.InstallationID, startID)
	if err != nil {
		return err
	}
	dir, err := openStage2aAdminDirectory(path, uint32(p.MachineUID))
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|02710 ||
		parent.Uid != uint32(p.MachineUID) || parent.Gid != uint32(p.Bridge.GID) {
		return errSoulCooperativeAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, err := f.Write(proof); err != nil || unix.Fchmod(fd, 0440) != nil {
		return errSoulCooperativeAuthority
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0440 || st.Nlink != 1 ||
		st.Uid != uint32(p.MachineUID) || st.Gid != uint32(p.Bridge.GID) || st.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(path, name)}) != nil {
		return errSoulCooperativeAuthority
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil || dir.Sync() != nil {
		return errSoulCooperativeAuthority
	}
	return nil
}

func readCooperativeBProof(installationID, startID string, uid, gid, machineUID int,
	wantSHA string) ([]byte, error) {
	path, name, err := cooperativeBProofPath(installationID, startID)
	if err != nil || os.Getuid() != uid || os.Geteuid() != uid || os.Getegid() != gid ||
		!stage2aPrefixedDigest.MatchString(wantSHA) {
		return nil, errSoulCooperativeAuthority
	}
	dir, err := openStage2aAdminDirectory(path, uint32(machineUID))
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|02710 ||
		parent.Uid != uint32(machineUID) || parent.Gid != uint32(gid) {
		return nil, errSoulCooperativeAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0440 ||
		before.Uid != uint32(machineUID) || before.Gid != uint32(gid) ||
		before.Nlink != 1 || before.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(path, name)}) != nil {
		return nil, errSoulCooperativeAuthority
	}
	proof, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(proof) != 32 || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || fmt.Sprintf("sha256:%x", sha256.Sum256(proof)) != wantSHA {
		clear(proof)
		return nil, errSoulCooperativeAuthority
	}
	return proof, nil
}
