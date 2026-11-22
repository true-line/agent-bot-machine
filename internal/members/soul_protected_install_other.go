//go:build !darwin

package members

import (
	"errors"

	"github.com/qwts/managed-machine/internal/cli"
)

func planSoulProtectedLaunch(Deps, string) cli.Result {
	return failure("MEMBERS_UNSUPPORTED", "protected Soul launch installation requires macOS")
}

func buildSoulProtectedLaunch(Input, Host) (Plan, error) {
	return Plan{}, errors.New("protected Soul launch installation requires macOS")
}

func CheckDarwinSoulProtectedLaunch(Saved, string, int) error {
	return errors.New("protected Soul launch installation requires macOS")
}

func runSoulProtectedLaunchApply(Saved, Approval, string, Host, Deps, func(Approval, func() error) error) cli.Result {
	return failure("MEMBERS_UNSUPPORTED", "protected Soul launch installation requires macOS")
}
