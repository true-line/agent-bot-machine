package daemon

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

// Deps is the testable surface of daemon install, uninstall, run, and status.
type Deps struct {
	command.Deps
	GOOS       string
	Executable func() (string, error)
	Caller     func() (Caller, error)
	Root       func() (string, error)
	Activate   func(path string) error
	Deactivate func(path string) error
}

// Command is `managed-machine daemon <run|install|uninstall|status|pair|unpair>`.
func Command(deps Deps) cli.Command {
	return cli.Command{
		Name:    "daemon",
		Summary: "install and run the per-user agent-machine executor",
		Usage: `managed-machine daemon run|install|uninstall|status|receipts|pair|unpair
agent-machine daemon run|install|uninstall|status|receipts|pair|unpair

install and uninstall write a per-user service unit for the prefix owner.
pair mints a Terminal thin-client key in the caller's home and prints the
prefix-owner enroll command. pair --enroll with no path reads the channel
enroll drop; a path still works. --client selects terminal or agent-daemon.
status and receipts are signed RPCs when a client key and channel exist.
They refuse root, agent accounts, agent sessions, and a foreign home.
The unit is a LaunchAgent, a systemd user unit, or a Windows service
description. Nothing is registered with a system service manager.`,
		Run: func(ctx cli.Context, args []string) cli.Result {
			return run(deps, ctx, args)
		},
	}
}

func run(deps Deps, ctx cli.Context, args []string) cli.Result {
	var verb, enroll, clientName string
	var enrollSet bool
	clientName = "terminal"
	if d := command.Parse(args, command.Spec{
		Positional:     &verb,
		PositionalName: "daemon verb",
		Values: map[string]command.Flag{
			"--enroll": {Value: &enroll, Set: &enrollSet, Optional: true},
			"--client": {Value: &clientName},
		},
	}); d != nil {
		return cli.Result{Diagnostic: d}
	}
	switch verb {
	case "run", "install", "uninstall", "status", "receipts", "pair", "unpair":
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, uninstall, status, receipts, pair, or unpair")}
	}
	if enrollSet && verb != "pair" {
		return cli.Result{Diagnostic: command.UsageErr("--enroll is only valid with pair")}
	}
	goos := deps.GOOS
	if goos == "" {
		goos = hostOS()
	}
	caller, err := deps.caller()
	if verb != "status" && verb != "receipts" {
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		switch verb {
		case "pair":
			if enrollSet {
				if msg := caller.Refuse(); msg != "" {
					d := diag.New(diag.DaemonCallerRefused, msg)
					return cli.Result{Diagnostic: &d}
				}
			} else if msg := caller.RefuseClient(); msg != "" {
				d := diag.New(diag.DaemonCallerRefused, msg)
				return cli.Result{Diagnostic: &d}
			}
		default:
			if msg := caller.Refuse(); msg != "" {
				d := diag.New(diag.DaemonCallerRefused, msg)
				return cli.Result{Diagnostic: &d}
			}
		}
	} else if err != nil {
		caller = Caller{}
	}
	root, err := deps.root()
	if err != nil {
		d := diag.New(diag.DaemonCallerRefused, err.Error())
		return cli.Result{Diagnostic: &d}
	}
	switch verb {
	case "status":
		on, err := Installed(goos, root)
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		state := "absent"
		if on {
			state = "installed"
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", state).Set("os", goos)
		key := filepath.Join(stateDir(root), "client.key")
		if handled, res, rpcErr := TryRPC(ChannelSocket(), key, "status", ""); handled && rpcErr == nil && res.OK {
			rec.Set("channel", "signed").Set("daemon", res.State)
		}
		return cli.Result{Records: []*output.Record{rec}}
	case "receipts":
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "absent")
		key := filepath.Join(stateDir(root), "client.key")
		if handled, res, rpcErr := TryRPC(ChannelSocket(), key, "receipts", ""); handled && rpcErr == nil && res.OK {
			rec.Set("channel", "signed").Set("state", res.State)
			if len(res.Body) > 0 {
				rec.Set("body", string(res.Body))
			}
		}
		return cli.Result{Records: []*output.Record{rec}}
	case "install":
		exec, err := deps.executable(ctx)
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		path, err := Install(goos, root, exec, "")
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		if deps.Activate != nil {
			if err := deps.Activate(path); err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "installed").Set("path", path)
		return cli.Result{Records: []*output.Record{rec}}
	case "uninstall":
		if path, err := unitPath(goos, root); err == nil && deps.Deactivate != nil {
			if err := deps.Deactivate(path); err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
		}
		if err := Uninstall(goos, root); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "absent")
		return cli.Result{Records: []*output.Record{rec}}
	case "run":
		if err := Run(context.Background(), root); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "stopped")
		return cli.Result{Records: []*output.Record{rec}}
	case "pair":
		if enrollSet {
			path := enroll
			if path == "" {
				path = defaultEnrollPub(clientName)
			}
			if path == "" {
				d := diag.New(diag.DaemonCallerRefused, "no enroll drop; pass a public key path")
				return cli.Result{Diagnostic: &d}
			}
			staged, err := EnrollClient(root, clientName, path)
			if err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
			rec := output.New().Set("service", "agent-machine").Set("client", clientName).Set("state", "paired").Set("path", staged)
			return cli.Result{Records: []*output.Record{rec}}
		}
		if caller.Refuse() == "" {
			path, err := PairTerminal(root)
			if err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
			rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "paired").Set("path", path)
			return cli.Result{Records: []*output.Record{rec}}
		}
		path, err := PairClient(root)
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		hint := enrollHint(path)
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "minted").Set("path", path).Set("enroll", hint)
		return cli.Result{Records: []*output.Record{rec}, Human: "As the prefix owner run:\n" + hint + "\n"}
	case "unpair":
		if err := UnpairTerminal(root); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "revoked")
		return cli.Result{Records: []*output.Record{rec}}
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, uninstall, status, receipts, pair, or unpair")}
	}
}

func enrollHint(pubPath string) string {
	cmd := "managed-machine daemon pair --enroll"
	if pubPath == "" || filepath.Base(filepath.Dir(pubPath)) == "enroll" {
		return cmd
	}
	return cmd + " " + pubPath
}

func (d Deps) caller() (Caller, error) {
	if d.Caller != nil {
		return d.Caller()
	}
	return Caller{}, fmt.Errorf("daemon caller is not configured")
}

func (d Deps) root() (string, error) {
	if d.Root != nil {
		return d.Root()
	}
	return "", fmt.Errorf("daemon service root is not configured")
}

func (d Deps) executable(ctx cli.Context) (string, error) {
	if d.Executable != nil {
		return d.Executable()
	}
	if ctx.Executable != nil {
		return ctx.Executable()
	}
	return "", fmt.Errorf("daemon executable is not configured")
}
