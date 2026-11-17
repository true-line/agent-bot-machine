package members

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// GNU tar's release digest does not include filesystem capabilities.
func checkHQFileCapabilities(path string) error {
	n, err := unix.Lgetxattr(path, "security.capability", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read HQ executable capabilities: %w", err)
	}
	if n != 0 {
		return refuse(RefusedPath, "%s carries file capabilities", path)
	}
	return nil
}
