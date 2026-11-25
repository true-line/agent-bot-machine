//go:build darwin || linux

package qualification

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ResolveGateObjectV3 reads exact local bytes from a private, content-addressed
// archive. It neither authenticates the writer nor validates a gate manifest;
// those checks belong to the physical gate verifier. The caller supplies a
// separately trusted root and a finite bound for the object class.
func ResolveGateObjectV3(root, uri, sha256 string, maxBytes int64) ([]byte, error) {
	name, err := gateObjectNameV3(uri, sha256)
	classLimit := int64(maxGateBlobBytesV3)
	if strings.HasPrefix(uri, gateObjectPrefixV3+"gate-manifest/") {
		classLimit = maxGateManifestBytesV3
	}
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || maxBytes < 1 || maxBytes > classLimit {
		return nil, ErrUnqualified
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnqualified
	}
	defer func() { unix.Close(fd) }()
	for _, part := range []string{"objects", "sha256", name[:2]} {
		child, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, ErrUnqualified
		}
		unix.Close(fd)
		fd = child
	}
	objectFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnqualified
	}
	object := os.NewFile(uintptr(objectFD), name)
	defer object.Close()
	var stat unix.Stat_t
	if unix.Fstat(objectFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || stat.Size < 0 || stat.Size > maxBytes {
		return nil, ErrUnqualified
	}
	contents, err := io.ReadAll(io.LimitReader(object, maxBytes+1))
	if err != nil || int64(len(contents)) != stat.Size || int64(len(contents)) > maxBytes ||
		digest(contents) != sha256 {
		return nil, ErrUnqualified
	}
	var after unix.Stat_t
	if unix.Fstat(objectFD, &after) != nil || after.Dev != stat.Dev || after.Ino != stat.Ino ||
		after.Size != stat.Size || after.Nlink != 1 {
		return nil, ErrUnqualified
	}
	return contents, nil
}
