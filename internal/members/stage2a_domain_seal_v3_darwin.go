//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const stage2aDomainSealSchemaV3 = "agent-bot-machine/stage2a-domain-install-seal/v3"

type stage2aDomainSealRequestV3 struct {
	Schema          string                    `json:"schema"`
	Domain          string                    `json:"domain"`
	InstallationID  string                    `json:"installation_id"`
	MachineAccount  string                    `json:"machine_account"`
	MachineUID      int                       `json:"machine_uid"`
	MachineGID      int                       `json:"machine_gid"`
	ReaderAccount   string                    `json:"reader_account"`
	ReaderUID       int                       `json:"reader_uid"`
	ReaderGID       int                       `json:"reader_gid"`
	OwnerPlanDigest string                    `json:"owner_plan_digest"`
	ReviewedDigest  string                    `json:"reviewed_source_inventory_digest"`
	Namespace       stage2aInstalledDirectory `json:"snapshot_namespace"`
	LauncherSHA256  string                    `json:"launcher_sha256"`
	Prepared        stage2aPreparedSnapshot   `json:"prepared"`
	Inventory       json.RawMessage           `json:"inventory"`
}

func (r stage2aDomainSealRequestV3) validate() error {
	namespace, _, _, err := stage2aDomainNamesV3(r.Domain, r.InstallationID)
	inv, digest, invErr := stage2aDomainInventoryDigestV3(r.Inventory)
	if err != nil || invErr != nil || r.Schema != stage2aDomainSealSchemaV3 ||
		r.Namespace.Path != namespace || r.Namespace.Device == 0 ||
		r.Namespace.Inode == "" || r.Namespace.BirthSeconds <= 0 ||
		r.Namespace.BirthNanoseconds < 0 || r.Namespace.BirthNanoseconds >= 1e9 ||
		inv.Domain != r.Domain || inv.InstallationID != r.InstallationID ||
		r.MachineUID < 400 || r.MachineGID <= 0 || r.ReaderUID <= 0 ||
		r.ReaderUID == r.MachineUID || r.ReaderGID <= 0 ||
		!accountName.MatchString(r.MachineAccount) || !accountName.MatchString(r.ReaderAccount) ||
		r.MachineAccount == r.ReaderAccount ||
		!stage2aPrefixedDigest.MatchString(r.OwnerPlanDigest) ||
		r.ReviewedDigest != digest || !soulDigest.MatchString(r.LauncherSHA256) ||
		r.Prepared.Digest != digest ||
		filepath.Dir(r.Prepared.WrapperPath) != namespace ||
		!strings.HasPrefix(filepath.Base(r.Prepared.WrapperPath), ".stage2a-") ||
		r.Prepared.Stage.RootPath != filepath.Join(r.Prepared.WrapperPath, "snapshot") ||
		r.Prepared.Wrapper.RootPath != r.Prepared.WrapperPath ||
		r.Prepared.Stage.OwnerUID != uint32(r.MachineUID) ||
		r.Prepared.Stage.OwnerGID != uint32(r.ReaderGID) ||
		r.Prepared.Wrapper.OwnerUID != uint32(r.MachineUID) ||
		r.Prepared.Wrapper.OwnerGID != uint32(r.ReaderGID) ||
		r.Prepared.Stage.Mode != "0700" || r.Prepared.Wrapper.Mode != "0700" {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aOpenPreparedV3Sidecar(wrapperFD int, path string, ownerUID, readerGID uint32,
	want []byte) (int, error) {
	fd, err := unix.Openat(wrapperFD, "inventory", stage2aFileOpenFlags, 0)
	if err != nil {
		return -1, err
	}
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 ||
		before.Uid != ownerUID || before.Gid != readerGID || before.Nlink != 1 ||
		before.Size != int64(len(want)) || checkDarwinACLs([]string{path}) != nil {
		unix.Close(fd)
		return -1, errors.New("unsafe Stage 2a v3 staged sidecar")
	}
	readFD, err := unix.Dup(fd)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	file := os.NewFile(uintptr(readFD), path)
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(want)+1)))
	file.Close()
	var after unix.Stat_t
	if err != nil || !bytes.Equal(raw, want) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		unix.Close(fd)
		return -1, errors.New("Stage 2a v3 staged sidecar differs from review")
	}
	// Keep the descriptor open across exclusive rename and final seal.
	return fd, nil
}

func stage2aSealDomainV3At(r stage2aDomainSealRequestV3) (stage2aVerifiedDomainRefV3, error) {
	var empty stage2aVerifiedDomainRefV3
	if r.validate() != nil {
		return empty, errStage2aReservationAuthority
	}
	a := stage2aAdminSnapshots{uid: uint32(r.MachineUID), runnerReadGID: uint32(r.ReaderGID),
		namespace: r.Namespace.Path, namespaceDev: r.Namespace.Device,
		verifyInstalledGroup: func() error {
			return verifyStage2aInstalledGroup(r.ReaderAccount, r.ReaderGID,
				r.MachineAccount, r.MachineUID, r.ReaderAccount, r.ReaderUID)
		}}
	a.namespaceInode, a.namespaceBirth = r.Namespace.identity()
	if err := a.check(); err != nil {
		return empty, err
	}
	parentFD, err := unix.Open(r.Namespace.Path, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, err
	}
	defer unix.Close(parentFD)
	wrapperFD, err := unix.Openat(parentFD, filepath.Base(r.Prepared.WrapperPath), stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, err
	}
	defer unix.Close(wrapperFD)
	wrapper, _, err := stage2aSnapshotIdentityForSource(wrapperFD, a.uid, a.runnerReadGID, true)
	if err != nil || wrapper != r.Prepared.Wrapper ||
		checkDarwinACLs([]string{r.Prepared.WrapperPath}) != nil {
		return empty, errStage2aReservationAuthority
	}
	childrenFD, err := unix.Dup(wrapperFD)
	if err != nil {
		return empty, err
	}
	listing := os.NewFile(uintptr(childrenFD), r.Prepared.WrapperPath)
	children, err := stage2aReadBoundedDir(listing, 2)
	listing.Close()
	if err != nil || len(children) != 2 ||
		!((children[0].Name() == "inventory" && children[1].Name() == "snapshot") ||
			(children[1].Name() == "inventory" && children[0].Name() == "snapshot")) {
		return empty, errors.New("Stage 2a v3 staging wrapper has unreviewed entries")
	}
	stageFD, err := unix.Openat(wrapperFD, "snapshot", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, err
	}
	defer unix.Close(stageFD)
	stage, _, err := stage2aSnapshotIdentityForSource(stageFD, a.uid, a.runnerReadGID, true)
	if err != nil || stage != r.Prepared.Stage {
		return empty, errStage2aReservationAuthority
	}
	observed, digest, err := stage2aObserveDomainV3AtMode(r.Prepared.Stage.RootPath,
		a.uid, a.runnerReadGID, r.Inventory, true)
	if err != nil || observed != stage || digest != r.ReviewedDigest {
		return empty, errors.New("Stage 2a v3 staged tree differs from reviewed bytes")
	}
	sideFD, err := stage2aOpenPreparedV3Sidecar(wrapperFD,
		filepath.Join(r.Prepared.WrapperPath, "inventory"), a.uid, a.runnerReadGID, r.Inventory)
	if err != nil {
		return empty, err
	}
	defer unix.Close(sideFD)
	_, snapshotName, sidecarName, _ := stage2aDomainNamesV3(r.Domain, r.InstallationID)
	if err := unix.RenameatxNp(wrapperFD, "inventory", parentFD, sidecarName, unix.RENAME_EXCL); err != nil {
		return empty, err
	}
	if err := unix.Fchmod(sideFD, 0440); err != nil || unix.Fsync(sideFD) != nil {
		return empty, errors.New("Stage 2a v3 sidecar seal uncertain")
	}
	if err := unix.RenameatxNp(wrapperFD, "snapshot", parentFD, snapshotName, unix.RENAME_EXCL); err != nil {
		return empty, err
	}
	if err := unix.Fchmod(stageFD, 0555); err != nil || unix.Fsync(stageFD) != nil ||
		unix.Fsync(wrapperFD) != nil || unix.Fsync(parentFD) != nil {
		return empty, errors.New("Stage 2a v3 A-owned seal uncertain")
	}
	finalRoot := filepath.Join(r.Namespace.Path, snapshotName)
	finalSidecar := filepath.Join(r.Namespace.Path, sidecarName)
	v, err := stage2aObserveInstalledDomainV3(finalRoot, finalSidecar,
		a.uid, uint32(r.ReaderUID), a.runnerReadGID, r.OwnerPlanDigest, r.ReviewedDigest)
	if err != nil || stage2aRecheckVerifiedDomainV3(v) != nil {
		return empty, errors.New("Stage 2a v3 A-owned published domain differs")
	}
	return v, nil
}

func runStage2aDomainSealV3(raw []byte) int {
	refuse := func() int { return harnessRefused }
	var r stage2aDomainSealRequestV3
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || r.validate() != nil ||
		!stage2aInstallSealNoIP() || os.Getuid() != r.MachineUID || os.Geteuid() != r.MachineUID ||
		os.Getgid() != r.MachineGID || os.Getegid() != r.MachineGID ||
		!stage2aInstallSealOnlyPrimaryGroup(r.MachineGID) {
		return refuse()
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return refuse()
	}
	binary, err := managerBytes()
	if err != nil || harnessSHA(binary) != r.LauncherSHA256 {
		return refuse()
	}
	v, err := stage2aSealDomainV3At(r)
	if err != nil || json.NewEncoder(os.Stdout).Encode(stage2aInstallSealReply{
		Identity: Stage2aSnapshotIdentity{RootPath: v.ref.Snapshot.Path,
			Device: v.ref.Snapshot.Device, Inode: v.ref.Snapshot.Inode,
			Generation: v.ref.Snapshot.Generation, BirthtimeNS: v.ref.Snapshot.BirthtimeNS,
			OwnerUID: v.ref.Snapshot.OwnerUID, OwnerGID: v.ref.Snapshot.OwnerGID,
			Mode: v.ref.Snapshot.Mode},
		Digest: v.ref.InventoryDigest, DomainV3: &v.ref,
	}) != nil {
		return refuse()
	}
	return 0
}

// Root may invoke this only from the owner-reviewed paired install after
// preparing fresh private nodes. A performs the final seal and remeasurement.
func stage2aSealDomainV3AsAdmin(r stage2aDomainSealRequestV3) (stage2aDomainInventoryRefV3, error) {
	var empty stage2aDomainInventoryRefV3
	if r.validate() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return empty, errStage2aReservationAuthority
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 3<<20 {
		return empty, errStage2aReservationAuthority
	}
	reply, err := stage2aRunSealHelper(r.MachineUID, r.MachineGID, raw)
	_, snapshotName, sidecarName, _ := stage2aDomainNamesV3(r.Domain, r.InstallationID)
	if err != nil || reply.DomainV3 == nil || reply.DomainV3.Snapshot.Path != filepath.Join(r.Namespace.Path, snapshotName) ||
		reply.DomainV3.Sidecar.Path != filepath.Join(r.Namespace.Path, sidecarName) ||
		reply.DomainV3.InventoryDigest != r.ReviewedDigest ||
		reply.DomainV3.OwnerPlanDigest != r.OwnerPlanDigest {
		return empty, errStage2aReservationAuthority
	}
	identity, digest, err := stage2aObserveDomainV3At(reply.DomainV3.Snapshot.Path,
		uint32(r.MachineUID), uint32(r.ReaderGID), r.Inventory)
	if err != nil || stage2aV3SnapshotRef(identity) != reply.DomainV3.Snapshot || digest != r.ReviewedDigest {
		return empty, fmt.Errorf("Stage 2a v3 root observation differs from A seal: %w", errStage2aReservationAuthority)
	}
	side, rawSide, err := stage2aV3SidecarAt(reply.DomainV3.Sidecar.Path,
		uint32(r.MachineUID), uint32(r.ReaderGID))
	if err != nil || side != reply.DomainV3.Sidecar || !bytes.Equal(rawSide, r.Inventory) {
		return empty, errors.New("Stage 2a v3 sidecar differs from A seal")
	}
	return *reply.DomainV3, nil
}
