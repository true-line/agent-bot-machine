//go:build !darwin

package daemon

import "errors"

func uninstallMacPackage(Deps) error { return errors.New("macOS Homebrew is required") }

func inspectServiceLifecycle(Caller, string, string, string, func(int, string, string) ([]byte, bool, error)) (serviceUnitReview, error) {
	return serviceUnitReview{}, errors.New("macOS launchd is required")
}
