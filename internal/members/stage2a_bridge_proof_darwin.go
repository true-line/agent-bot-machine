//go:build darwin

package members

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func stage2aBridgeProofPath(start SoulStartAssignment) (string, string) {
	dir := filepath.Join(launchRuntimeDir, "b-grants", soulEndpointInstallationSlot(start.InstallationID))
	return dir, soulEndpointStartSlot(start.InstallationID, start.StartID) + ".proof"
}

// The approved installer creates this per-installation directory as A:B
// 02710. The setgid bit gives A's exclusively created file B's private group;
// no caller may select a path or supply key bytes. An uncertain publication
// leaves the name occupied and the reservation spent.
func publishStage2aBridgeProof(start SoulStartAssignment, key []byte) error {
	invalid := errors.New("Stage 2a B proof handoff unavailable")
	if len(key) != 32 || !soulInstallationID.MatchString(start.InstallationID) ||
		!soulStartID.MatchString(start.StartID) || start.MachineUID != os.Getuid() ||
		start.MachineUID != os.Geteuid() || start.BridgeGID <= 0 {
		return invalid
	}
	path, name := stage2aBridgeProofPath(start)
	dir, err := openStage2aAdminDirectory(path, uint32(start.MachineUID))
	if err != nil {
		return invalid
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|02710 ||
		parent.Uid != uint32(start.MachineUID) || parent.Gid != uint32(start.BridgeGID) {
		return invalid
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
	if err != nil {
		return invalid
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return invalid
	}
	if unix.Fchmod(fd, 0440) != nil {
		return invalid
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0440 || st.Nlink != 1 ||
		st.Uid != uint32(start.MachineUID) || st.Gid != uint32(start.BridgeGID) || st.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(path, name)}) != nil {
		return invalid
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		return invalid
	}
	if dir.Sync() != nil {
		return invalid
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		return invalid
	}
	return nil
}
