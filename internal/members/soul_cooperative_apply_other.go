//go:build !darwin

package members

import (
	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
)

func runSoulCooperativeLaunchApply(Saved, Approval, string, Host, Deps,
	func(Approval, func() error) error) cli.Result {
	return failure(diag.MembersNotApproved, "cooperative Soul launch installation requires macOS")
}
