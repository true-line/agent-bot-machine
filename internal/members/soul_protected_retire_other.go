//go:build !darwin

package members

import (
	"errors"

	"github.com/qwts/managed-machine/internal/cli"
)

func planSoulProtectedRetire(Deps, string) cli.Result {
	return failure("MM_MEMBERS_UNSUPPORTED", "protected Soul retirement requires macOS")
}

func buildSoulProtectedRetire(Input, Host) (Plan, error) {
	return Plan{}, errors.New("protected Soul retirement requires macOS")
}

func runSoulProtectedRetireApply(Saved, Approval, string, Host, Deps,
	func(Approval, func() error) error) cli.Result {
	return failure("MM_MEMBERS_UNSUPPORTED", "protected Soul retirement requires macOS")
}
