package members

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Root creates fresh private staging only. The existing fixed offline A
// helper publishes and seals the H domain. Neither path starts the service.
func prepareHQStage2aSeal(rec launchRecord, planDigest string, raw []byte) (stage2aDomainInventoryRefV3, error) {
	var empty stage2aDomainInventoryRefV3
	s, launch := rec.Service.Stage2a, rec.Stage2a
	if os.Getuid() != 0 || os.Geteuid() != 0 || s == nil || launch == nil || !digestPattern.MatchString(planDigest) {
		return empty, errStage2aReservationAuthority
	}
	inv, err := verifyHQStage2aReleaseRows(rec.Service, raw)
	if err != nil {
		return empty, err
	}
	if err := stage2aVerifyHSourceFilesV3(s.InventorySource, s.Components[0].ManifestSource,
		s.Components[0].ArtifactSource, s.Components[1].ArtifactSource, 0,
		stage2aHSourceReleasePinsV3{
			InstallationID: s.InstallationID, InventoryDigest: s.InventoryDigest,
			Limits: s.InventoryLimits, HQCommit: s.Components[0].SourceCommit,
			HQArtifactSHA256:     s.Components[0].ArtifactSHA256,
			NodeArtifactSHA256:   s.Components[1].ArtifactSHA256,
			SourceManifestSHA256: s.Components[0].ManifestSHA256,
			ContractsTag:         s.ContractsSource.Tag, ContractsCommit: s.ContractsSource.Commit,
			ContractsFullDigest: s.ContractsSource.FullDigest, ContractsFullFiles: s.ContractsSource.FullFiles,
			ContractsRuntimeDigest: s.ContractsSource.RuntimeDigest,
			ContractsRuntimeFiles:  s.ContractsSource.RuntimeFiles, Excluded: s.ExcludedHQReleasePaths,
		}); err != nil {
		return empty, err
	}
	namespace, snapshot, sidecar, err := stage2aDomainNamesV3("H-code", s.InstallationID)
	if err != nil || launch.Namespace != namespace || launch.Root != filepath.Join(namespace, snapshot) ||
		launch.InventoryPath != filepath.Join(namespace, sidecar) {
		return empty, errStage2aReservationAuthority
	}
	parent := filepath.Dir(namespace)
	if err := trustedPath(OSHost{}, parent, true); err != nil {
		return empty, err
	}
	if _, err := stage2aInstalledDirectoryIdentity(parent, 0, 0, 0711); err != nil {
		return empty, err
	}
	created, err := createProtectedDirectory(namespace, s.MachineUID, s.ReaderGID, 0750)
	if err != nil {
		return empty, err
	}
	defer created.Close()
	nsIdentity, err := stage2aInstalledDirectoryIdentity(namespace, s.MachineUID, s.ReaderGID, 0750)
	if err != nil {
		return empty, err
	}
	ns, err := os.OpenFile(namespace, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	defer ns.Close()
	var first, reopened unix.Stat_t
	if unix.Fstat(int(created.Fd()), &first) != nil || unix.Fstat(int(ns.Fd()), &reopened) != nil || !stage2aSameNode(first, reopened) {
		return empty, errStage2aReservationAuthority
	}
	prepared, err := stageHQStage2aFiles(ns, rec.Service, inv, raw)
	if err != nil {
		return empty, err
	}
	defer stage2aCleanPrivateStage(prepared.WrapperPath)
	ownerPlan := "sha256:" + planDigest
	return stage2aSealDomainV3AsAdmin(stage2aDomainSealRequestV3{Schema: stage2aDomainSealSchemaV3,
		Domain: inv.Domain, InstallationID: inv.InstallationID, MachineAccount: s.MachineAccount,
		MachineUID: s.MachineUID, MachineGID: s.MachineGID, ReaderAccount: DarwinHQAccount,
		ReaderUID: s.ReaderUID, ReaderGID: s.ReaderGID, OwnerPlanDigest: ownerPlan,
		ReviewedDigest: s.InventoryDigest, Namespace: nsIdentity, LauncherSHA256: strings.TrimPrefix(launch.LauncherSHA256, "sha256:"),
		Prepared: prepared, Inventory: raw})
}

func stageHQStage2aFiles(namespace *os.File, service HQService, inv stage2aDomainInventoryV3, raw []byte) (stage2aPreparedSnapshot, error) {
	var empty stage2aPreparedSnapshot
	s := service.Stage2a
	uid, gid := uint32(s.MachineUID), uint32(s.ReaderGID)
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	wrapper, err := makeHQStage2aDirectory(namespace, fmt.Sprintf(".stage2a-%x", nonce), uid, gid)
	if err != nil {
		return empty, err
	}
	defer wrapper.Close()
	complete := false
	defer func() {
		if !complete {
			stage2aCleanPrivateStage(wrapper.Name())
		}
	}()
	root, err := makeHQStage2aDirectory(wrapper, "snapshot", uid, gid)
	if err != nil {
		return empty, err
	}
	dirs := map[string]*os.File{".": root}
	defer func() {
		for _, dir := range dirs {
			dir.Close()
		}
	}()
	for _, d := range inv.Directories {
		child, err := makeHQStage2aDirectory(dirs[filepath.Dir(d.Path)], filepath.Base(d.Path), uid, gid)
		if err != nil {
			return empty, err
		}
		dirs[d.Path] = child
	}
	for _, row := range inv.Files {
		if err := copyHQStage2aFile(dirs[filepath.Dir(row.Path)], service, row, uid, gid); err != nil {
			return empty, err
		}
	}
	for _, d := range inv.Directories {
		fd := int(dirs[d.Path].Fd())
		mode, _ := strconv.ParseUint(d.Mode, 8, 32)
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			return empty, err
		}
		if err := unix.Fsync(fd); err != nil {
			return empty, err
		}
	}
	if err := writeHQStage2aFile(wrapper, "inventory", 0600, uid, gid, func(f *os.File) error {
		_, err := f.Write(raw)
		return err
	}); err != nil {
		return empty, err
	}
	for _, dir := range []*os.File{root, wrapper, namespace} {
		if err := dir.Sync(); err != nil {
			return empty, err
		}
	}
	wrapperIdentity, _, err := stage2aSnapshotIdentityForSource(int(wrapper.Fd()), uid, gid, true)
	if err != nil {
		return empty, err
	}
	stageIdentity, _, err := stage2aSnapshotIdentityForSource(int(root.Fd()), uid, gid, true)
	if err != nil {
		return empty, err
	}
	complete = true
	return stage2aPreparedSnapshot{WrapperPath: wrapper.Name(), Wrapper: wrapperIdentity, Stage: stageIdentity, Digest: s.InventoryDigest}, nil
}

func makeHQStage2aDirectory(parent *os.File, name string, uid, gid uint32) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(parent.Name(), name)
	if err := stage2aChownNew(fd, uid, gid); err != nil || checkDarwinACLs([]string{path}) != nil {
		unix.Close(fd)
		return nil, errStage2aReservationAuthority
	}
	return os.NewFile(uintptr(fd), path), nil
}

func copyHQStage2aFile(parent *os.File, service HQService, row stage2aDomainFileV3, uid, gid uint32) error {
	path := filepath.Join(service.ReleaseDir, row.ReleasePath)
	if row.ComponentID == "node" {
		path = service.Node
	}
	srcParent, err := openStage2aAdminDirectory(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer srcParent.Close()
	fd, err := unix.Openat(int(srcParent.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(fd), path)
	defer src.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&06022 != 0 || before.Uid != 0 ||
		before.Nlink != 1 || before.Size != int64(row.SizeBytes) || checkDarwinACLs([]string{path}) != nil {
		return errStage2aReservationAuthority
	}
	mode, _ := strconv.ParseUint(row.Mode, 8, 32)
	return writeHQStage2aFile(parent, filepath.Base(row.Path), uint32(mode), uid, gid, func(dst *os.File) error {
		hash := sha256.New()
		copied, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(src, before.Size+1))
		var after unix.Stat_t
		if err != nil || copied != before.Size || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != row.SHA256 ||
			unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
			return errStage2aReservationAuthority
		}
		return nil
	})
}

func writeHQStage2aFile(parent *os.File, name string, mode, uid, gid uint32, write func(*os.File) error) error {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	defer f.Close()
	if err := write(f); err != nil {
		return err
	}
	if err := stage2aChownNew(fd, uid, gid); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	if err := checkDarwinACLs([]string{f.Name()}); err != nil {
		return err
	}
	return f.Sync()
}
