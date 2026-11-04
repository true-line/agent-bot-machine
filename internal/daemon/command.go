package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	GOOS        string
	Executable  func() (string, error)
	Caller      func() (Caller, error)
	Root        func() (string, error)
	Activate    func(path string) error
	Deactivate  func(path string) error
	WaitHealthy func() error
}

// Command is `managed-machine daemon <run|install|start|stop|uninstall|status|receipts|pair|unpair>`.
func Command(deps Deps) cli.Command {
	return cli.Command{
		Name:    "daemon",
		Summary: "install and run the per-user agent-machine executor",
		Usage: `managed-machine daemon run|install|start|stop|uninstall|status|receipts|pair|unpair
agent-machine daemon run|install|start|stop|uninstall|status|receipts|pair|unpair

install writes the per-user unit, loads it, and waits until the socket
accepts. start does the same when the unit already exists. stop unloads it.
install --user NAME pins the account that may auto-enroll as the terminal
client. The user does not pair: the next human status mints client.key at
home and the daemon adopts that pubkey from the unix-socket UID.
pair --enroll HEX --fingerprint HEX remains for re-key and agent-daemon.
status is running when the socket accepts, installed when only the unit
file exists, and absent otherwise. channel=signed is the RPC proof.
They refuse root, agent accounts, agent sessions, and a foreign home.
The unit is a LaunchAgent, a systemd user unit, or a Windows service
description. Nothing is registered with a system service manager.`,
		Run: func(ctx cli.Context, args []string) cli.Result {
			return run(deps, ctx, args)
		},
	}
}

func run(deps Deps, ctx cli.Context, args []string) cli.Result {
	var verb, enroll, fingerprint, clientName, userName string
	var enrollSet, fingerprintSet, userSet bool
	clientName = "terminal"
	if d := command.Parse(args, command.Spec{
		Positional:     &verb,
		PositionalName: "daemon verb",
		Values: map[string]command.Flag{
			"--enroll":      {Value: &enroll, Set: &enrollSet},
			"--fingerprint": {Value: &fingerprint, Set: &fingerprintSet},
			"--client":      {Value: &clientName},
			"--user":        {Value: &userName, Set: &userSet},
		},
	}); d != nil {
		return cli.Result{Diagnostic: d}
	}
	switch verb {
	case "run", "install", "start", "stop", "uninstall", "status", "receipts", "pair", "unpair":
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, start, stop, uninstall, status, receipts, pair, or unpair")}
	}
	if enrollSet && verb != "pair" {
		return cli.Result{Diagnostic: command.UsageErr("--enroll is only valid with pair")}
	}
	if fingerprintSet && verb != "pair" {
		return cli.Result{Diagnostic: command.UsageErr("--fingerprint is only valid with pair")}
	}
	if userSet && verb != "install" && verb != "start" {
		return cli.Result{Diagnostic: command.UsageErr("--user is only valid with install or start")}
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
		sock := ChannelSocket()
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", serviceState(on, SocketListening(sock))).Set("os", goos)
		key := filepath.Join(stateDir(root), "client.key")
		if handled, res, rpcErr := signedRPC(caller, sock, key, "status", ""); handled && rpcErr == nil && res.OK {
			rec.Set("channel", "signed").Set("daemon", res.State)
		}
		return cli.Result{Records: []*output.Record{rec}}
	case "receipts":
		sock := ChannelSocket()
		on, _ := Installed(goos, root)
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", serviceState(on, SocketListening(sock)))
		key := filepath.Join(stateDir(root), "client.key")
		handled, res, rpcErr := signedRPC(caller, sock, key, "receipts", "")
		if !handled {
			return cli.Result{Records: []*output.Record{rec}}
		}
		if rpcErr != nil {
			d := diag.New(diag.DaemonCallerRefused, rpcErr.Error())
			return cli.Result{Diagnostic: &d}
		}
		if !res.OK {
			msg := res.Message
			if msg == "" {
				msg = res.Diagnostic
			}
			if msg == "" {
				msg = "receipts refused"
			}
			d := diag.New(diag.DaemonCallerRefused, msg)
			return cli.Result{Diagnostic: &d}
		}
		rec.Set("channel", "signed").Set("state", res.State)
		if len(res.Body) > 0 {
			rec.Set("body", string(res.Body))
		}
		return cli.Result{Records: []*output.Record{rec}}
	case "install", "start":
		return ensureService(deps, ctx, goos, root, userName)
	case "stop":
		path, err := unitPath(goos, root)
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		if deps.Deactivate != nil {
			if err := deps.Deactivate(path); err != nil {
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
			if fingerprint == "" {
				return cli.Result{Diagnostic: command.UsageErr("pair --enroll needs --fingerprint")}
			}
			staged, err := EnrollClient(root, clientName, enroll, fingerprint)
			if err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
			rec := output.New().Set("service", "agent-machine").Set("client", clientName).Set("state", "paired").Set("path", staged)
			return cli.Result{Records: []*output.Record{rec}}
		}
		if fingerprintSet {
			return cli.Result{Diagnostic: command.UsageErr("--fingerprint is only valid with --enroll")}
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
		pub, err := loadPublic(path)
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		hint := enrollHint(pub, clientName)
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "minted").Set("path", path).Set("public", hex.EncodeToString(pub)).Set("fingerprint", publicFingerprint(pub)).Set("enroll", hint)
		return cli.Result{Records: []*output.Record{rec}, Human: "As the prefix owner run:\n" + hint + "\n"}
	case "unpair":
		if err := UnpairTerminal(root); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "revoked")
		return cli.Result{Records: []*output.Record{rec}}
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, start, stop, uninstall, status, receipts, pair, or unpair")}
	}
}

func ensureService(deps Deps, ctx cli.Context, goos, root, userName string) cli.Result {
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
	keydUnit, err := InstallKeyd(goos, root, exec, filepath.Join(root, ".local", "state", "agent-bot"))
	if err != nil {
		d := diag.New(diag.DaemonCallerRefused, err.Error())
		return cli.Result{Diagnostic: &d}
	}
	if keydUnit != "" && deps.Activate != nil {
		if err := deps.Activate(keydUnit); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
	}
	if userName != "" {
		if err := PinTerminalUser(root, userName); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
	}
	if deps.Activate != nil {
		if err := deps.Activate(path); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
	}
	state := "installed"
	if deps.WaitHealthy != nil {
		if err := deps.WaitHealthy(); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		state = "running"
	}
	rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", state).Set("path", path)
	return cli.Result{Records: []*output.Record{rec}}
}

func enrollHint(pub ed25519.PublicKey, client string) string {
	cmd := "managed-machine daemon pair --enroll " + hex.EncodeToString(pub) + " --fingerprint " + publicFingerprint(pub)
	if client != "" && client != "terminal" {
		return cmd + " --client " + client
	}
	return cmd
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
