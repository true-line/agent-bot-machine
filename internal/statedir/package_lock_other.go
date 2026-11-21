//go:build !darwin

package statedir

import (
	"errors"
	"io"
)

func LockMacPackage(string, int) (io.Closer, error) {
	return nil, errors.New("macOS package lifecycle locking is unavailable")
}
