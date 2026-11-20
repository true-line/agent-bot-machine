//go:build !unix

package statedir

import (
	"errors"
	"os"
)

func LockMacPackage(string, int) (*os.File, error) {
	return nil, errors.New("macOS package lifecycle locking is unavailable")
}
