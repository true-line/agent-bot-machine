//go:build windows

package daemon

import "errors"

func lockOwnerPairing(string) (func() error, error) {
	return nil, errors.New("owner presence enrollment is macOS-only")
}
