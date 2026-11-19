//go:build !darwin && !windows

package members

import (
	"errors"
	"os"
)

func removeStoppedLaunchSocket(*os.File, os.FileInfo, string) error {
	return errors.New("launchd socket rollback requires macOS")
}
