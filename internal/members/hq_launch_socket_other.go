//go:build !darwin && !windows

package members

import (
	"errors"
	"os"
)

func removeStoppedLaunchSocket(string, *os.File, os.FileInfo, string) error {
	return errors.New("launchd socket rollback requires macOS")
}

func prepareLaunchDirectory(*launchDirectory, string, bool) (*os.File, error) {
	return nil, errors.New("HQ LaunchDaemon directory requires macOS")
}
func rollbackLaunchDirectory(*os.File, HQService, string) error {
	return errors.New("HQ LaunchDaemon directory rollback requires macOS")
}
