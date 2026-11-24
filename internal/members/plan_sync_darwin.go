//go:build darwin

package members

import (
	"os"

	"golang.org/x/sys/unix"
)

func syncSavedPlanFile(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	return err
}
