//go:build darwin

package members

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const SoulCooperativeSandbox = launchRuntimeDir + "/soul-cooperative-egress.sb"

//go:embed darwin/soul-cooperative-egress.sb
var soulCooperativeProfile []byte

// The existing host projection reader intentionally accepts only two host
// JSON files. Reopen this one policy row through its own no-follow path so the
// cooperative sandbox cannot be replaced by a mutable source file.
func readSoulCooperativeFrozenProfile(identity Stage2aSnapshotIdentity,
	records []Stage2aDefinitionRecord) ([]byte, error) {
	const relative = "policy/soul-cooperative-egress.sb"
	var approved *Stage2aDefinitionRecord
	for i := range records {
		if records[i].Path == relative {
			approved = &records[i]
			break
		}
	}
	if approved == nil || approved.Kind != "regular" || approved.Size == nil ||
		*approved.Size == 0 || *approved.Size > 64<<10 {
		return nil, errSoulCooperativeAuthority
	}
	root, err := openStage2aAdminDirectory(identity.RootPath, identity.OwnerUID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	observed, _, err := stage2aSnapshotIdentity(int(root.Fd()), identity.OwnerUID, identity.OwnerGID)
	if err != nil || observed != identity {
		return nil, errSoulCooperativeAuthority
	}
	policy, err := unix.Openat(int(root.Fd()), "policy", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(policy)
	parent, err := stage2aCheckedNode(policy, identity.OwnerUID, identity.OwnerGID)
	if err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR ||
		checkDarwinACLs([]string{filepath.Join(identity.RootPath, "policy")}) != nil {
		return nil, errSoulCooperativeAuthority
	}
	fd, err := unix.Openat(policy, "soul-cooperative-egress.sb", stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), relative)
	defer f.Close()
	before, err := stage2aCheckedNode(fd, identity.OwnerUID, identity.OwnerGID)
	mode, modeErr := strconv.ParseUint(approved.Mode, 8, 32)
	if err != nil || modeErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != uint16(mode) || before.Size != int64(*approved.Size) ||
		checkDarwinACLs([]string{filepath.Join(identity.RootPath, relative)}) != nil {
		return nil, errSoulCooperativeAuthority
	}
	body, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	var after unix.Stat_t
	if err != nil || uint64(len(body)) != *approved.Size || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || fmt.Sprintf("%x", sha256.Sum256(body)) != approved.SHA256 {
		return nil, errSoulCooperativeAuthority
	}
	return body, nil
}
