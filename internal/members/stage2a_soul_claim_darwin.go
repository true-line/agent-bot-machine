//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The owner maps the SoulLock claim to a separately measured frozen closure.
// The two digests have different meanings and need not have equal bytes.
func stage2aCheckFrozenSoulClaim(identity Stage2aSnapshotIdentity, records []Stage2aDefinitionRecord,
	soulID, claimedDigest string) error {
	invalid := errors.New("frozen Soul identity or definition claim differs from owner review")
	for _, field := range []struct{ file, key, want string }{
		{"Contents/SoulInfo.json", "soul_id", soulID},
		{"Contents/SoulLock.json", "definition_digest", claimedDigest},
	} {
		raw, err := stage2aReadFrozenClaimFile(identity, records, field.file)
		if err != nil || stage2aStrictJSON(raw) != nil {
			return invalid
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return invalid
		}
		var value string
		if json.Unmarshal(object[field.key], &value) != nil || value != field.want {
			return invalid
		}
	}
	return nil
}

func stage2aReadFrozenClaimFile(identity Stage2aSnapshotIdentity, records []Stage2aDefinitionRecord,
	relative string) ([]byte, error) {
	invalid := errors.New("invalid frozen Soul claim descriptor")
	if relative != "Contents/SoulInfo.json" && relative != "Contents/SoulLock.json" {
		return nil, invalid
	}
	var want *Stage2aDefinitionRecord
	for i := range records {
		if records[i].Path == relative {
			want = &records[i]
			break
		}
	}
	if want == nil || want.Kind != "regular" || want.Size == nil || *want.Size > 64<<10 || !soulDigest.MatchString(want.SHA256) {
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
	contentsFD, err := unix.Openat(int(root.Fd()), "Contents", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return nil, invalid
	}
	defer unix.Close(contentsFD)
	contentsPath := filepath.Join(identity.RootPath, "Contents")
	contents, err := stage2aCheckedNode(contentsFD, identity.OwnerUID, identity.OwnerGID)
	if err != nil || contents.Mode&unix.S_IFMT != unix.S_IFDIR || checkDarwinACLs([]string{contentsPath}) != nil {
		return nil, invalid
	}
	fd, err := unix.Openat(contentsFD, filepath.Base(relative), stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, invalid
	}
	f := os.NewFile(uintptr(fd), filepath.Join(identity.RootPath, relative))
	defer f.Close()
	before, err := stage2aCheckedNode(fd, identity.OwnerUID, identity.OwnerGID)
	mode, modeErr := strconv.ParseUint(want.Mode, 8, 32)
	if err != nil || modeErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Mode&07777 != uint16(mode) || before.Size != int64(*want.Size) ||
		checkDarwinACLs([]string{f.Name()}) != nil {
		return nil, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	var after unix.Stat_t
	if err != nil || uint64(len(raw)) != *want.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
		return nil, invalid
	}
	sum := sha256.Sum256(raw)
	if strings.ToLower(want.SHA256) != fmtHex(sum[:]) {
		return nil, invalid
	}
	return raw, nil
}

func fmtHex(raw []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, v := range raw {
		out[i*2], out[i*2+1] = alphabet[v>>4], alphabet[v&15]
	}
	return string(out)
}
