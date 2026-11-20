//go:build !darwin

package daemon

import "errors"

func uninstallMacPackage(Deps) error { return errors.New("macOS Homebrew is required") }
