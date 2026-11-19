//go:build windows

package daemon

import (
	"errors"
	"os"
)

func lockOwnerPairing(string) (func() error, error) {
	return nil, errors.New("owner presence enrollment is macOS-only")
}

func openFirstHQProof(string) (*os.File, error) {
	return nil, errors.New("first-HQ provisioning is macOS-only")
}
