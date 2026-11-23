//go:build darwin

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

// A raw JSON reference is only a claim. This value is produced by A's local
// no-follow observation and must be rechecked before a descriptor or one-use
// reservation is signed. Its fields are deliberately private to this package.
type stage2aVerifiedDomainRefV3 struct {
	verified bool
	ref      stage2aDomainInventoryRefV3
}

func stage2aV3NodeRef(path string, st unix.Stat_t) (stage2aDomainNodeRefV3, error) {
	if st.Btim.Sec < 0 || st.Btim.Nsec < 0 || st.Btim.Nsec >= 1_000_000_000 ||
		st.Btim.Sec > (1<<63-1-st.Btim.Nsec)/1_000_000_000 {
		return stage2aDomainNodeRefV3{}, errors.New("invalid Stage 2a v3 node birthtime")
	}
	return stage2aDomainNodeRefV3{
		Path: path, Device: strconv.FormatUint(uint64(uint32(st.Dev)), 10),
		Inode: strconv.FormatUint(st.Ino, 10), Generation: strconv.FormatUint(uint64(st.Gen), 10),
		BirthtimeNS: strconv.FormatInt(st.Btim.Sec*1_000_000_000+st.Btim.Nsec, 10),
		OwnerUID:    st.Uid, OwnerGID: st.Gid, Mode: fmt.Sprintf("%04o", st.Mode&07777),
	}, nil
}

func stage2aV3SidecarAt(path string, ownerUID, readerGID uint32) (stage2aDomainSidecarRefV3, []byte, error) {
	var empty stage2aDomainSidecarRefV3
	fd, err := unix.Open(path, stage2aFileOpenFlags, 0)
	if err != nil {
		return empty, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != 0440 || before.Uid != ownerUID || before.Gid != readerGID ||
		before.Nlink != 1 || before.Size < 1 || before.Size > 2<<20 ||
		checkDarwinACLs([]string{path}) != nil {
		return empty, nil, errors.New("unsafe Stage 2a v3 inventory sidecar")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	var after unix.Stat_t
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return empty, nil, errors.New("Stage 2a v3 inventory sidecar changed")
	}
	node, err := stage2aV3NodeRef(path, after)
	if err != nil {
		return empty, nil, err
	}
	return stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: node,
		SizeBytes: uint64(len(raw)), SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}, raw, nil
}

func stage2aV3SnapshotRef(identity Stage2aSnapshotIdentity) stage2aDomainNodeRefV3 {
	return stage2aDomainNodeRefV3{Path: identity.RootPath, Device: identity.Device,
		Inode: identity.Inode, Generation: identity.Generation, BirthtimeNS: identity.BirthtimeNS,
		OwnerUID: identity.OwnerUID, OwnerGID: identity.OwnerGID, Mode: identity.Mode}
}

// stage2aObserveInstalledDomainV3 requires the already sealed A-owned tree
// and an out-of-tree A-owned sidecar in the same private A:reader namespace.
// The owner plan and reviewed source digest must come from an independently
// authenticated install plan; this function refuses a mismatch but cannot
// authenticate those input claims by itself.
func stage2aObserveInstalledDomainV3(rootPath, sidecarPath string, machineUID, readerUID, readerGID uint32,
	ownerPlanDigest, reviewedDigest string) (stage2aVerifiedDomainRefV3, error) {
	var empty stage2aVerifiedDomainRefV3
	if os.Getuid() != int(machineUID) || os.Geteuid() != int(machineUID) ||
		machineUID < 400 || readerUID == 0 || readerUID == machineUID || readerGID == 0 ||
		!stage2aPrefixedDigest.MatchString(ownerPlanDigest) ||
		!stage2aPrefixedDigest.MatchString(reviewedDigest) ||
		!stage2aAbsolutePath(rootPath) || !stage2aAbsolutePath(sidecarPath) ||
		rootPath == sidecarPath || filepath.Dir(rootPath) != filepath.Dir(sidecarPath) {
		return empty, errors.New("invalid Stage 2a v3 installed domain reference")
	}
	parentFD, err := unix.Open(filepath.Dir(rootPath), stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, err
	}
	defer unix.Close(parentFD)
	if stage2aPrivateSnapshotParent(parentFD, machineUID, readerGID) != nil ||
		checkDarwinACLs([]string{filepath.Dir(rootPath)}) != nil {
		return empty, errors.New("unsafe Stage 2a v3 domain namespace")
	}
	sidecar, raw, err := stage2aV3SidecarAt(sidecarPath, machineUID, readerGID)
	if err != nil {
		return empty, err
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != reviewedDigest {
		return empty, errors.New("Stage 2a v3 sidecar differs from reviewed source")
	}
	identity, observedDigest, err := stage2aObserveDomainV3At(rootPath, machineUID, readerGID, raw)
	if err != nil || observedDigest != digest {
		return empty, errors.New("Stage 2a v3 installed tree differs from reviewed inventory")
	}
	return stage2aVerifiedDomainRefV3{verified: true, ref: stage2aDomainInventoryRefV3{
		Contract: "machine/v3", Kind: "stage2a-inventory-ref", SchemaVersion: 3,
		Domain: inv.Domain, InstallationID: inv.InstallationID,
		OwnerPlanDigest: ownerPlanDigest, ReviewedSourceInventoryDigest: reviewedDigest,
		MachineUID: machineUID, ReaderUID: readerUID, ReaderGID: readerGID,
		Snapshot: stage2aV3SnapshotRef(identity), Sidecar: sidecar,
		FileCount: len(inv.Files), DirectoryCount: len(inv.Directories),
		TotalBytes: inv.TotalBytes, InventoryDigest: digest,
	}}, nil
}

func stage2aRecheckVerifiedDomainV3(v stage2aVerifiedDomainRefV3) error {
	if !v.verified {
		return errors.New("unverified Stage 2a v3 domain reference")
	}
	current, err := stage2aObserveInstalledDomainV3(v.ref.Snapshot.Path, v.ref.Sidecar.Path,
		v.ref.MachineUID, v.ref.ReaderUID, v.ref.ReaderGID,
		v.ref.OwnerPlanDigest, v.ref.ReviewedSourceInventoryDigest)
	if err != nil || current.ref != v.ref {
		return errors.New("Stage 2a v3 installed domain changed before use")
	}
	return nil
}
