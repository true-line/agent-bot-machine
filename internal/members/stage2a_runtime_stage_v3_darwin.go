//go:build darwin

package members

import (
	"archive/tar"
	"archive/zip"
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

// stage2aRuntimeStageV3 is made only from a paired, owner-reviewed install.
// SourceRoots must name the root-owned extraction for every component in the
// separately authenticated release manifests. The caller verifies those
// manifests and their all-and-only mapping before invoking this copier.
type stage2aRuntimeStageV3 struct {
	InstallationID  string
	MachineAccount  string
	MachineUID      int
	MachineGID      int
	ReaderAccount   string
	ReaderUID       int
	ReaderGID       int
	PlanDigest      string
	InventoryDigest string
	LauncherSHA256  string
	Inventory       []byte
	SourceRoots     map[string]string
}

func stage2aReadReviewedRuntimeV3(spec stage2aRuntimeV3Install, installationID string) (stage2aDomainInventoryV3, []byte, error) {
	var empty stage2aDomainInventoryV3
	raw, err := stage2aReadInstallSource(spec.InventorySource, 2<<20)
	if err != nil {
		return empty, nil, err
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || inv.Domain != "R-runtime" || inv.InstallationID != installationID {
		return empty, nil, errStage2aReservationAuthority
	}
	manifests := make(map[string][]byte, len(spec.Components))
	for _, component := range spec.Components {
		manifest, err := stage2aReadInstallSource(component.ManifestSource, 2<<20)
		if err != nil {
			return empty, nil, err
		}
		manifests[component.ComponentID] = manifest
	}
	if stage2aValidateRuntimeV3Plan(spec, inv, digest, manifests) != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	return inv, raw, nil
}

func stage2aVerifyRuntimeV3Artifact(component stage2aRuntimeV3ComponentPin, ownerUID uint32,
	inv stage2aDomainInventoryV3) error {
	path, expected := component.ArtifactSource, component.ReleaseArtifactSHA256
	if !stage2aAbsolutePath(path) || !stage2aPrefixedDigest.MatchString(expected) {
		return errStage2aReservationAuthority
	}
	parent, err := openStage2aAdminDirectory(filepath.Dir(path), ownerUID)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&06022 != 0 || before.Nlink != 1 ||
		(before.Uid != 0 && before.Uid != ownerUID) || before.Size < 1 || before.Size > 2<<30 ||
		checkDarwinACLs([]string{path}) != nil {
		return errStage2aReservationAuthority
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, before.Size); err != nil {
		return err
	}
	var extra [1]byte
	n, readErr := file.Read(extra[:])
	var after unix.Stat_t
	if n != 0 || readErr != io.EOF || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != expected {
		return errStage2aReservationAuthority
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if component.ArtifactFormat == "raw" {
		var matched *stage2aDomainFileV3
		for i := range inv.Files {
			if inv.Files[i].ComponentID == component.ComponentID {
				if matched != nil {
					return errStage2aReservationAuthority
				}
				matched = &inv.Files[i]
			}
		}
		if matched == nil || matched.SHA256 != expected || matched.SizeBytes != uint64(before.Size) {
			return errStage2aReservationAuthority
		}
	} else if component.ArtifactFormat == "tar" {
		if stage2aVerifyRuntimeV3Tar(file, component.ComponentID, inv) != nil {
			return errStage2aReservationAuthority
		}
	} else if component.ArtifactFormat == "zip" {
		if stage2aVerifyRuntimeV3Zip(file, before.Size, component.ComponentID, inv) != nil {
			return errStage2aReservationAuthority
		}
	} else {
		return errStage2aReservationAuthority
	}
	if unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
		return errStage2aReservationAuthority
	}
	return nil
}

// A stock adapter ZIP is a transport for exact reviewed regular-file rows.
// Its member names are release_path values, while inventory path is the
// separately reviewed location in the sealed R snapshot. No archive member
// is copied directly into A's staging or given authority by ZIP metadata.
func stage2aVerifyRuntimeV3Zip(file *os.File, size int64, componentID string, inv stage2aDomainInventoryV3) error {
	want := make(map[string]stage2aDomainFileV3)
	for _, row := range inv.Files {
		if row.ComponentID == componentID {
			want[row.ReleasePath] = row
		}
	}
	if len(want) == 0 || len(want) > 512 {
		return errStage2aReservationAuthority
	}
	archive, err := zip.NewReader(file, size)
	if err != nil || len(archive.File) != len(want) || archive.Comment != "" {
		return errStage2aReservationAuthority
	}
	seen := make(map[string]bool, len(want))
	for _, member := range archive.File {
		row, ok := want[member.Name]
		if !ok || seen[member.Name] || !stage2aV3InventoryRecordPath(member.Name) ||
			member.Flags&1 != 0 || !member.FileInfo().Mode().IsRegular() ||
			member.UncompressedSize64 != row.SizeBytes ||
			(member.Method != zip.Store && member.Method != zip.Deflate) {
			return errStage2aReservationAuthority
		}
		opened, err := member.Open()
		if err != nil {
			return errStage2aReservationAuthority
		}
		hash := sha256.New()
		_, err = io.CopyN(hash, opened, int64(row.SizeBytes))
		var extra [1]byte
		n, readErr := opened.Read(extra[:])
		closeErr := opened.Close()
		if err != nil || n != 0 || readErr != io.EOF || closeErr != nil ||
			fmt.Sprintf("sha256:%x", hash.Sum(nil)) != row.SHA256 {
			return errStage2aReservationAuthority
		}
		seen[member.Name] = true
	}
	return nil
}

func stage2aVerifyRuntimeV3Tar(file *os.File, componentID string, inv stage2aDomainInventoryV3) error {
	wantFiles := make(map[string]stage2aDomainFileV3)
	wantDirs := make(map[string]string)
	dirModes := make(map[string]string, len(inv.Directories))
	for _, row := range inv.Directories {
		dirModes[row.Path] = row.Mode
	}
	for _, row := range inv.Files {
		if row.ComponentID != componentID {
			continue
		}
		wantFiles[row.ReleasePath] = row
		for released, installed := filepath.Dir(row.ReleasePath), filepath.Dir(row.Path); released != "."; released, installed = filepath.Dir(released), filepath.Dir(installed) {
			// A release-only ancestor is transport metadata: it is pinned by the
			// artifact digest but never copied into the installed snapshot.
			mode := ""
			if installed != "." {
				mode = dirModes[installed]
				if mode == "" {
					return errStage2aReservationAuthority
				}
			}
			if previous := wantDirs[released]; previous != "" && mode != "" && previous != mode {
				return errStage2aReservationAuthority
			}
			if mode != "" {
				wantDirs[released] = mode
			} else if _, ok := wantDirs[released]; !ok {
				wantDirs[released] = ""
			}
		}
	}
	if len(wantFiles) == 0 {
		return errStage2aReservationAuthority
	}
	seenFiles := make(map[string]bool, len(wantFiles))
	seenDirs := make(map[string]bool, len(wantDirs))
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header == nil || header.Uid != 0 || header.Gid != 0 ||
			header.Linkname != "" || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
			return errStage2aReservationAuthority
		}
		name := header.Name
		mode := fmt.Sprintf("%04o", header.Mode&07777)
		switch header.Typeflag {
		case tar.TypeDir:
			if !strings.HasSuffix(name, "/") || header.Size != 0 {
				return errStage2aReservationAuthority
			}
			name = strings.TrimSuffix(name, "/")
			wantMode, wanted := wantDirs[name]
			if !stage2aV3InventoryRecordPath(name) || seenDirs[name] || !wanted ||
				wantMode != "" && mode != wantMode || header.Mode&07000 != 0 || header.Mode&0022 != 0 {
				return errStage2aReservationAuthority
			}
			seenDirs[name] = true
		case tar.TypeReg, tar.TypeRegA:
			row, ok := wantFiles[name]
			if !ok || seenFiles[name] || !stage2aV3InventoryRecordPath(name) ||
				header.Size < 0 || uint64(header.Size) != row.SizeBytes || mode != row.Mode {
				return errStage2aReservationAuthority
			}
			hash := sha256.New()
			if _, err := io.CopyN(hash, reader, header.Size); err != nil ||
				fmt.Sprintf("sha256:%x", hash.Sum(nil)) != row.SHA256 {
				return errStage2aReservationAuthority
			}
			seenFiles[name] = true
		default:
			return errStage2aReservationAuthority
		}
	}
	if len(seenFiles) != len(wantFiles) || len(seenDirs) != len(wantDirs) {
		return errStage2aReservationAuthority
	}
	// A tar reader stops at its end marker. The pinned artifact may contain
	// standard zero padding, but no hidden second archive or trailing payload.
	var padding [32 << 10]byte
	for {
		n, err := file.Read(padding[:])
		for _, b := range padding[:n] {
			if b != 0 {
				return errStage2aReservationAuthority
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Root may copy reviewed R bytes into fresh A-private staging. Only the fixed,
// network-denied A helper may publish the final snapshot and sidecar.
func stage2aInstallRuntimeV3AsAdmin(s stage2aRuntimeStageV3) (stage2aDomainInventoryRefV3, error) {
	var empty stage2aDomainInventoryRefV3
	inv, digest, err := stage2aDomainInventoryDigestV3(s.Inventory)
	namespace, _, _, namesErr := stage2aDomainNamesV3("R-runtime", s.InstallationID)
	if os.Getuid() != 0 || os.Geteuid() != 0 || err != nil || namesErr != nil ||
		inv.Domain != "R-runtime" || inv.InstallationID != s.InstallationID ||
		digest != s.InventoryDigest || !digestPattern.MatchString(s.PlanDigest) ||
		!soulDigest.MatchString(s.LauncherSHA256) || s.MachineUID < 400 ||
		s.ReaderUID <= 0 || s.ReaderUID == s.MachineUID || s.ReaderGID <= 0 ||
		len(s.SourceRoots) == 0 || !stage2aRuntimeSourcesMatchInventory(inv, s.SourceRoots) {
		return empty, errStage2aReservationAuthority
	}
	for componentID, root := range s.SourceRoots {
		if err := stage2aRuntimeSourceClosureV3(root, componentID, inv); err != nil {
			return empty, err
		}
	}
	if err := stage2aEnsureInstallDirectory(stage2aDomainSnapshotParentV3, 0, 0, 0711); err != nil {
		return empty, err
	}
	if err := stage2aEnsureInstallDirectory(namespace, s.MachineUID, s.ReaderGID, 0750); err != nil {
		return empty, err
	}
	ns, err := stage2aInstalledDirectoryIdentity(namespace, s.MachineUID, s.ReaderGID, 0750)
	if err != nil {
		return empty, err
	}
	parent, err := openStage2aAdminDirectory(namespace, uint32(s.MachineUID))
	if err != nil {
		return empty, err
	}
	defer parent.Close()
	prepared, err := stage2aStageRuntimeV3(parent, inv, digest, s.Inventory, s.SourceRoots,
		uint32(s.MachineUID), uint32(s.ReaderGID))
	if err != nil {
		return empty, err
	}
	defer stage2aCleanPrivateStage(prepared.WrapperPath)
	request := stage2aDomainSealRequestV3{Schema: stage2aDomainSealSchemaV3,
		Domain: "R-runtime", InstallationID: s.InstallationID,
		MachineAccount: s.MachineAccount, MachineUID: s.MachineUID, MachineGID: s.MachineGID,
		ReaderAccount: s.ReaderAccount, ReaderUID: s.ReaderUID, ReaderGID: s.ReaderGID,
		OwnerPlanDigest: "sha256:" + s.PlanDigest, ReviewedDigest: digest,
		Namespace: ns, LauncherSHA256: s.LauncherSHA256,
		Prepared: prepared, Inventory: s.Inventory}
	return stage2aSealDomainV3AsAdmin(request)
}

func stage2aRuntimeSourceClosureV3(root, componentID string, inv stage2aDomainInventoryV3) error {
	dir, err := openStage2aAdminDirectory(root, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	var rootBefore, rootAfter unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &rootBefore) != nil || rootBefore.Uid != 0 ||
		rootBefore.Gid != 0 || rootBefore.Mode&06022 != 0 {
		return errStage2aReservationAuthority
	}
	wantFiles := make(map[string]stage2aDomainFileV3)
	wantDirs := make(map[string]bool)
	for _, row := range inv.Files {
		if row.ComponentID != componentID {
			continue
		}
		wantFiles[row.ReleasePath] = row
		for parent := filepath.Dir(row.ReleasePath); parent != "."; parent = filepath.Dir(parent) {
			wantDirs[parent] = true
		}
	}
	if len(wantFiles) == 0 {
		return errStage2aReservationAuthority
	}
	seenFiles, seenDirs := 0, 0
	aclPaths := make([]string, 0, len(wantFiles)+len(wantDirs))
	var walk func(int, string, int) error
	walk = func(parentFD int, relative string, depth int) error {
		if depth > 512 {
			return errStage2aReservationAuthority
		}
		listingFD, err := unix.Dup(parentFD)
		if err != nil {
			return err
		}
		listing := os.NewFile(uintptr(listingFD), filepath.Join(root, relative))
		children, err := stage2aReadBoundedDir(listing, 1536)
		listing.Close()
		if err != nil {
			return err
		}
		for _, child := range children {
			path := child.Name()
			if relative != "" {
				path = relative + "/" + path
			}
			if !stage2aV3InventoryRecordPath(path) {
				return errStage2aReservationAuthority
			}
			fd, err := unix.Openat(parentFD, child.Name(), stage2aFileOpenFlags, 0)
			if err != nil {
				return err
			}
			var before unix.Stat_t
			if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Gid != 0 ||
				before.Mode&06022 != 0 {
				unix.Close(fd)
				return errStage2aReservationAuthority
			}
			aclPaths = append(aclPaths, filepath.Join(root, filepath.FromSlash(path)))
			switch before.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if !wantDirs[path] {
					unix.Close(fd)
					return errStage2aReservationAuthority
				}
				seenDirs++
				err = walk(fd, path, depth+1)
			case unix.S_IFREG:
				want, ok := wantFiles[path]
				if !ok || before.Nlink != 1 || before.Size < 0 || uint64(before.Size) != want.SizeBytes {
					unix.Close(fd)
					return errStage2aReservationAuthority
				}
				seenFiles++
			default:
				unix.Close(fd)
				return errStage2aReservationAuthority
			}
			var after unix.Stat_t
			statErr := unix.Fstat(fd, &after)
			unix.Close(fd)
			if err != nil || statErr != nil || !stage2aSameNode(before, after) {
				return errStage2aReservationAuthority
			}
		}
		return nil
	}
	if err := walk(int(dir.Fd()), "", 0); err != nil || seenFiles != len(wantFiles) ||
		seenDirs != len(wantDirs) || checkDarwinACLs(aclPaths) != nil ||
		unix.Fstat(int(dir.Fd()), &rootAfter) != nil || !stage2aSameNode(rootBefore, rootAfter) {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aStageRuntimeV3(parent *os.File, inv stage2aDomainInventoryV3,
	digest string, raw []byte, sourceRoots map[string]string, uid, gid uint32) (stage2aPreparedSnapshot, error) {
	var empty stage2aPreparedSnapshot
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	wrapper, err := stage2aRuntimeNewDirectory(parent, fmt.Sprintf(".stage2a-%x", nonce), uid, gid)
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
	root, err := stage2aRuntimeNewDirectory(wrapper, "snapshot", uid, gid)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	for _, row := range inv.Directories {
		parentDir, err := stage2aRuntimeOpenStagedDirectory(root, filepath.Dir(row.Path), uid, gid)
		if err != nil {
			return empty, err
		}
		child, err := stage2aRuntimeNewDirectory(parentDir, filepath.Base(row.Path), uid, gid)
		closeErr := parentDir.Close()
		if err != nil {
			return empty, err
		}
		if err := child.Close(); err != nil || closeErr != nil {
			return empty, errStage2aReservationAuthority
		}
	}
	for _, row := range inv.Files {
		parentDir, err := stage2aRuntimeOpenStagedDirectory(root, filepath.Dir(row.Path), uid, gid)
		if err != nil {
			return empty, err
		}
		copyErr := stage2aCopyRuntimeV3File(parentDir, sourceRoots[row.ComponentID], row, uid, gid)
		closeErr := parentDir.Close()
		if copyErr != nil {
			return empty, copyErr
		}
		if closeErr != nil {
			return empty, closeErr
		}
	}
	for i := len(inv.Directories) - 1; i >= 0; i-- {
		row := inv.Directories[i]
		dir, err := stage2aRuntimeOpenStagedDirectory(root, row.Path, uid, gid)
		if err != nil {
			return empty, err
		}
		mode, _ := strconv.ParseUint(row.Mode, 8, 32)
		fd := int(dir.Fd())
		chmodErr := unix.Fchmod(fd, uint32(mode))
		syncErr := unix.Fsync(fd)
		closeErr := dir.Close()
		if chmodErr != nil || syncErr != nil || closeErr != nil {
			return empty, errStage2aReservationAuthority
		}
	}
	if err := stage2aRuntimeWriteFile(wrapper, "inventory", raw, 0600, uid, gid); err != nil {
		return empty, err
	}
	for _, dir := range []*os.File{root, wrapper, parent} {
		if err := dir.Sync(); err != nil {
			return empty, err
		}
	}
	stage, observedDigest, err := stage2aObserveDomainV3AtMode(root.Name(), uid, gid, raw, true)
	if err != nil || observedDigest != digest {
		return empty, errStage2aReservationAuthority
	}
	wrapperIdentity, _, err := stage2aSnapshotIdentityForSource(int(wrapper.Fd()), uid, gid, true)
	if err != nil {
		return empty, err
	}
	complete = true
	return stage2aPreparedSnapshot{WrapperPath: wrapper.Name(), Wrapper: wrapperIdentity,
		Stage: stage, Digest: digest}, nil
}

// Reopen one A-private staging directory from the trusted root descriptor.
// Never retain a descriptor for each inventory row: the validated inventory
// permits more directories than macOS's ordinary soft descriptor limit.
func stage2aRuntimeOpenStagedDirectory(root *os.File, relative string, uid, gid uint32) (*os.File, error) {
	if root == nil || relative != "." && !stage2aV3InventoryRecordPath(relative) {
		return nil, errStage2aReservationAuthority
	}
	parts := []string{"."}
	if relative != "." {
		parts = strings.Split(relative, "/")
	}
	parentFD := int(root.Fd())
	owned := false
	for _, part := range parts {
		fd, err := unix.Openat(parentFD, part, stage2aDirectoryOpenFlags, 0)
		if owned {
			unix.Close(parentFD)
		}
		if err != nil {
			return nil, errStage2aReservationAuthority
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR ||
			st.Mode&07777 != 0700 || st.Uid != uid || st.Gid != gid {
			unix.Close(fd)
			return nil, errStage2aReservationAuthority
		}
		parentFD, owned = fd, true
	}
	return os.NewFile(uintptr(parentFD), filepath.Join(root.Name(), relative)), nil
}

func stage2aRuntimeNewDirectory(parent *os.File, name string, uid, gid uint32) (*os.File, error) {
	if parent == nil || unix.Mkdirat(int(parent.Fd()), name, 0700) != nil {
		return nil, errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(parent.Fd()), name, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(parent.Name(), name)
	if stage2aChownNew(fd, uid, gid) != nil || checkDarwinACLs([]string{path}) != nil {
		unix.Close(fd)
		return nil, errStage2aReservationAuthority
	}
	return os.NewFile(uintptr(fd), path), nil
}

func stage2aCopyRuntimeV3File(parent *os.File, root string, row stage2aDomainFileV3, uid, gid uint32) error {
	path := filepath.Join(root, filepath.FromSlash(row.ReleasePath))
	sourceDir, err := openStage2aAdminDirectory(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer sourceDir.Close()
	fd, err := unix.Openat(int(sourceDir.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), path)
	defer source.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&06022 != 0 || before.Uid != 0 || before.Gid != 0 ||
		before.Nlink != 1 || before.Size < 0 || uint64(before.Size) != row.SizeBytes ||
		checkDarwinACLs([]string{path}) != nil {
		return errStage2aReservationAuthority
	}
	mode, _ := strconv.ParseUint(row.Mode, 8, 32)
	targetFD, err := unix.Openat(int(parent.Fd()), filepath.Base(row.Path),
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	target := os.NewFile(uintptr(targetFD), filepath.Join(parent.Name(), filepath.Base(row.Path)))
	defer target.Close()
	if err := stage2aChownNew(targetFD, uid, gid); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(target, hash), source, before.Size); err != nil {
		return err
	}
	var extra [1]byte
	n, readErr := source.Read(extra[:])
	var after unix.Stat_t
	if n != 0 || readErr != io.EOF || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != row.SHA256 ||
		unix.Fchmod(targetFD, uint32(mode)) != nil || unix.Fsync(targetFD) != nil ||
		checkDarwinACLs([]string{target.Name()}) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aRuntimeWriteFile(parent *os.File, name string, raw []byte, mode, uid, gid uint32) error {
	fd, err := unix.Openat(int(parent.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	defer f.Close()
	if stage2aChownNew(fd, uid, gid) != nil {
		return errStage2aReservationAuthority
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return errStage2aReservationAuthority
	}
	if unix.Fchmod(fd, mode) != nil || f.Sync() != nil || checkDarwinACLs([]string{f.Name()}) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}
