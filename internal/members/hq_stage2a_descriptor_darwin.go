package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func provisionHQStage2aDescriptorDirectory(rec launchRecord) (stage2aInstalledDirectory, error) {
	var empty stage2aInstalledDirectory
	s, launch := rec.Service.Stage2a, rec.Stage2a
	if os.Getuid() != 0 || os.Geteuid() != 0 || s == nil || launch == nil ||
		launch.DescriptorPath != hqStage2aDescriptor || launch.PublicKeyPath != SoulAuthorityPin {
		return empty, errStage2aReservationAuthority
	}
	if _, err := stage2aInstalledDirectoryIdentity(launchRuntimeDir, 0, 0, 0755); err != nil {
		return empty, err
	}
	pub, err := readStage2aRolePin()
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(pub)) != s.AuthorityKeySHA256 {
		return empty, errStage2aReservationAuthority
	}
	dir, err := createProtectedDirectory(hqStage2aMetadataDir, s.MachineUID, s.ReaderGID, 0750)
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return empty, err
	}
	if err := syncUpgradeDir(launchRuntimeDir); err != nil {
		return empty, err
	}
	return stage2aInstalledDirectoryIdentity(hqStage2aMetadataDir, s.MachineUID, s.ReaderGID, 0750)
}

func checkHQStage2aDescriptorDirectory(s hqStage2aService, reviewed stage2aInstalledDirectory) error {
	current, err := stage2aInstalledDirectoryIdentity(hqStage2aMetadataDir, s.MachineUID, s.ReaderGID, 0750)
	if err != nil || current != reviewed {
		return errStage2aReservationAuthority
	}
	return nil
}

func removeHQStage2aDescriptorDirectory(s hqStage2aService, reviewed stage2aInstalledDirectory) error {
	if reviewed.Path != hqStage2aMetadataDir || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(reviewed.Path, uint32(s.MachineUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	var st unix.Stat_t
	inode, birth := reviewed.identity()
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0750 || st.Uid != uint32(s.MachineUID) ||
		st.Gid != uint32(s.ReaderGID) || st.Dev != reviewed.Device || st.Ino != inode || st.Btim != birth {
		return errStage2aReservationAuthority
	}
	if err := removeLaunchDirectory(dir, reviewed.Path); err != nil {
		return err
	}
	return syncUpgradeDir(launchRuntimeDir)
}

// The A-side signer passes a verified envelope and its enrolled public key to
// this fixed offline publisher. A new H generation has an unoccupied leaf.
// Once published, the exact descriptor stays in place on uncertain sync.
func publishHQStage2aDescriptorAsAdmin(s hqStage2aService, key ed25519.PublicKey, envelope []byte) (stage2aDomainSidecarRefV3, error) {
	var empty stage2aDomainSidecarRefV3
	if !hqStage2aIsOfflineAdmin(s) ||
		len(envelope) == 0 || len(envelope) > 64<<10 || stage2aStrictJSON(envelope) != nil {
		return empty, errStage2aReservationAuthority
	}
	pub, err := readStage2aRolePin()
	if err != nil || !key.Equal(pub) || fmt.Sprintf("sha256:%x", sha256.Sum256(pub)) != s.AuthorityKeySHA256 {
		return empty, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(hqStage2aMetadataDir, uint32(s.MachineUID))
	if err != nil {
		return empty, err
	}
	defer dir.Close()
	var directory unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &directory) != nil || directory.Mode != unix.S_IFDIR|0750 ||
		directory.Uid != uint32(s.MachineUID) || directory.Gid != uint32(s.ReaderGID) {
		return empty, errStage2aReservationAuthority
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	// A has no H group membership. A new file inherits the directory's group
	// on Darwin, and stage2aChownNew verifies that exact group before sealing.
	name := fmt.Sprintf(".hq-descriptor-%x", nonce)
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	if err := writeHQStage2aFile(dir, name, 0440, uint32(s.MachineUID), uint32(s.ReaderGID), func(f *os.File) error {
		_, err := f.Write(envelope)
		return err
	}); err != nil {
		return empty, err
	}
	temp, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return empty, err
	}
	_, syncErr := unix.FcntlInt(uintptr(temp), unix.F_FULLFSYNC, 0)
	closeErr := unix.Close(temp)
	if syncErr != nil || closeErr != nil {
		return empty, errStage2aReservationAuthority
	}
	if err := unix.RenameatxNp(int(dir.Fd()), name, int(dir.Fd()), filepath.Base(hqStage2aDescriptor), unix.RENAME_EXCL); err != nil {
		return empty, err
	}
	if err := dir.Sync(); err != nil {
		return empty, err
	}
	published, raw, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || !bytes.Equal(raw, envelope) {
		return empty, errStage2aReservationAuthority
	}
	return published, nil
}

// Retire only the exact published descriptor. The guarded upgrade calls this
// as A after launchd and the recorded endpoint confirm the candidate stopped.
func withdrawHQStage2aDescriptorAsAdmin(s hqStage2aService, descriptor stage2aDomainSidecarRefV3) error {
	if !hqStage2aIsOfflineAdmin(s) || descriptor.Path != hqStage2aDescriptor {
		return errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(hqStage2aMetadataDir, uint32(s.MachineUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	current, _, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || current != descriptor {
		return errStage2aReservationAuthority
	}
	var named unix.Stat_t
	name := filepath.Base(descriptor.Path)
	if err := unix.Fstatat(int(dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	observed, err := stage2aV3NodeRef(descriptor.Path, named)
	if err != nil || observed != descriptor.stage2aDomainNodeRefV3 {
		return errStage2aReservationAuthority
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		return err
	}
	return dir.Sync()
}

func hqStage2aIsOfflineAdmin(s hqStage2aService) bool {
	return s.MachineUID >= 400 && s.MachineGID > 0 && os.Getuid() == s.MachineUID && os.Geteuid() == s.MachineUID &&
		os.Getgid() == s.MachineGID && os.Getegid() == s.MachineGID && stage2aInstallSealOnlyPrimaryGroup(s.MachineGID) && stage2aInstallSealNoIP()
}

func validHQStage2aDescriptorWitness(s hqStage2aService, witness stage2aDomainSidecarRefV3) bool {
	return witness.Path == hqStage2aDescriptor && witness.OwnerUID == uint32(s.MachineUID) &&
		witness.OwnerGID == uint32(s.ReaderGID) && witness.Mode == "0440" && witness.SizeBytes > 0 &&
		witness.SizeBytes <= 64<<10 && stage2aPrefixedDigest.MatchString(witness.SHA256)
}

type hqStage2aWithdrawRequest struct {
	LauncherSHA256 string                    `json:"launcher_sha256"`
	Service        hqStage2aService          `json:"service"`
	Descriptor     stage2aDomainSidecarRefV3 `json:"descriptor"`
}

// Only a protected journal may supply a prior publication witness. Root
// cannot withdraw it itself, and the offline A command accepts a fixed leaf.
func withdrawHQStage2aDescriptorOffline(rec launchRecord, witness stage2aDomainSidecarRefV3) error {
	s := rec.Service.Stage2a
	if os.Getuid() != 0 || os.Geteuid() != 0 || s == nil || rec.Stage2a == nil || !validHQStage2aDescriptorWitness(*s, witness) {
		return errStage2aReservationAuthority
	}
	observed, _, err := stage2aV3SidecarAt(hqStage2aDescriptor, uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil || observed != witness {
		return errors.New("preserving changed protected HQ descriptor")
	}
	if err := trustedPath(OSHost{}, SoulLauncher, false); err != nil {
		return err
	}
	raw, err := json.Marshal(hqStage2aWithdrawRequest{LauncherSHA256: rec.Stage2a.LauncherSHA256, Service: *s, Descriptor: witness})
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile, SoulLauncher, "stage2a-h-withdraw")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(raw)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(s.MachineUID), Gid: uint32(s.MachineGID), Groups: []uint32{}}}
	if err := cmd.Run(); err != nil {
		return errors.New("offline A helper refused to withdraw the recorded HQ descriptor")
	}
	if _, err := os.Lstat(hqStage2aDescriptor); !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot confirm the recorded HQ descriptor was withdrawn")
	}
	return nil
}

// RunStage2aHQWithdraw is a fixed offline helper entry for the interrupted
// protected transition. It does not accept a destination, a command, or data.
func RunStage2aHQWithdraw() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (8<<10)+1))
	if err != nil || len(raw) > 8<<10 || stage2aStrictJSON(raw) != nil {
		return harnessRefused
	}
	var request hqStage2aWithdrawRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Service.validate() != nil ||
		!validHQStage2aDescriptorWitness(request.Service, request.Descriptor) {
		return harnessRefused
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return harnessRefused
	}
	binary, err := managerBytes()
	if err != nil || "sha256:"+harnessSHA(binary) != request.LauncherSHA256 ||
		withdrawHQStage2aDescriptorAsAdmin(request.Service, request.Descriptor) != nil {
		return harnessRefused
	}
	return 0
}
