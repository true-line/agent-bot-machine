//go:build !darwin

package daemon

import (
	"errors"
	"time"
)

// InstallKeyd only creates a service on Darwin.
func waitBundledKeyd(Caller, time.Duration) error {
	return errors.New("bundled keyd requires macOS")
}
