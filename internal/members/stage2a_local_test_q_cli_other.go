//go:build !darwin

package members

import (
	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
)

func runStage2aLocalTestQPlan(_ Deps, _ cli.Context, _ []string) cli.Result {
	return cli.Result{Diagnostic: command.UsageErr("local-test Q preparation requires macOS")}
}

func runStage2aLocalTestQStage(_ Deps, _ cli.Context, _ []string) cli.Result {
	return cli.Result{Diagnostic: command.UsageErr("local-test Q staging requires macOS")}
}
