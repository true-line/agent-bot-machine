package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/output"
)

type serviceUnitReview struct {
	remove     func() error
	retainKeyd bool
}

// Deps is the testable surface of daemon install, uninstall, run, and status.
type Deps struct {
	command.Deps
	MembersHost   members.Host // nil reads the running host for first-HQ plans
	GOOS          string
	Executable    func() (string, error)
	Caller        func() (Caller, error)
	Root          func() (string, error)
	LockLifecycle func(string, int) (io.Closer, error)
	ReadUserJob   func(int, string, string) ([]byte, bool, error)
	Activate      func(path string) error
	Deactivate    func(path string) error
	WaitHealthy   func() error
	// Reload makes the service manager reread units after install puts a
	// refused unit file back.
	Reload func() error
}

// Command is `managed-machine daemon <run|install|start|stop|uninstall|status|receipts|pair|unpair|revoke-hq|verify-identity>`.
func Command(deps Deps) cli.Command {
	return cli.Command{
		Name:    "daemon",
		Summary: "install and run the per-user agent-machine executor",
		Usage: `managed-machine daemon run|install|start|stop|uninstall|status|receipts|pair|unpair|revoke-hq|verify-identity
agent-machine daemon run|install|start|stop|uninstall|status|receipts|pair|unpair|revoke-hq|verify-identity

revoke-hq immediately disables the enrolled HQ on this Machine. It is a local
administrative action. The terminal pairing and the device key are preserved.

install writes the per-user unit, loads it, and waits until the socket
accepts. start does the same when the unit already exists. stop unloads it.
HQ's agent-daemon key is the intended caller: pair --enroll HEX
--fingerprint HEX --client agent-daemon enrolls it and binds it to the
dedicated HQ account when the machine has one, or to --user NAME. A bound
key is accepted only from that account; uid=any means it is not bound.
On macOS pair --pin-owner BASE64 sets the independently verified owner
public key once. Subsequent HQ enrollment requires --owner-challenge,
then --owner-proof JSON for that challenge from the owner approval client.
Protected pairing defaults to the dedicated HQ role. To select a local
non-administrator account, pass --user NAME on both steps and verify the
numeric HQ UID displayed for owner approval.
Before the dedicated HQ role exists, the prefix administrator can transfer
a saved members plan to the owner approval client using these commands:
  daemon first-hq export PLAN_ID
  daemon first-hq approve PLAN_ID --proof-file PATH
  daemon first-hq cancel PLAN_ID
Export a single JSONL record with default output. Approval records consent
for the separate human sudo members apply step. A new export supersedes
any outstanding first-HQ challenge.
Before first HQ enrollment, the prefix owner's daemon must have published its
public key on the shared channel. If the installed daemon has never started,
run managed-machine daemon start as the prefix owner, then request the challenge.
For a paired macOS Machine, verify-identity checks this executable's access
to the existing Machine signing identity without changing the key or service.
Use daemon run --require-identity FINGERPRINT for a temporary replacement
that must use that exact previously paired identity.
unpair revokes the terminal client. It accepts at most one --client terminal.
The terminal client is a debug tool and is off by default. install --debug
turns it on, and install without --debug turns it off again. While it is
on, the next human status mints client.key at home and the daemon adopts
that pubkey from the unix-socket UID. install --debug --user NAME pins the
account that may enroll.
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

func run(deps Deps, ctx cli.Context, args []string) (result cli.Result) {
	if len(args) > 0 && args[0] == "verify-identity" {
		if len(args) != 1 {
			return cli.Result{Diagnostic: command.UsageErr("verify-identity takes no arguments")}
		}
		return verifyPairedIdentity(deps)
	}
	if len(args) > 0 && args[0] == "first-hq" {
		return firstHQ(deps, args[1:])
	}
	var verb, enroll, fingerprint, clientName, userName, requiredIdentity string
	var enrollSet, fingerprintSet, userSet, debug, identitySet bool
	var clientCount int
	var owner ownerPairOptions
	clientName = "terminal"
	if d := command.Parse(args, command.Spec{
		Positional:     &verb,
		PositionalName: "daemon verb",
		Bools:          map[string]*bool{"--debug": &debug, "--owner-challenge": &owner.challenge},
		Values: map[string]command.Flag{
			"--require-identity": {Value: &requiredIdentity, Set: &identitySet},
			"--pin-owner":        {Value: &owner.pin, Set: &owner.pinSet},
			"--owner-proof":      {Value: &owner.proof, Set: &owner.proofSet},
			"--enroll":           {Value: &enroll, Set: &enrollSet},
			"--fingerprint":      {Value: &fingerprint, Set: &fingerprintSet},
			"--client":           {Value: &clientName, Count: &clientCount},
			"--user":             {Value: &userName, Set: &userSet},
		},
	}); d != nil {
		return cli.Result{Diagnostic: d}
	}
	switch verb {
	case "run", "install", "start", "stop", "uninstall", "status", "receipts", "pair", "unpair", "revoke-hq":
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, start, stop, uninstall, status, receipts, pair, unpair, or revoke-hq")}
	}
	if verb == "revoke-hq" && len(args) != 1 {
		return cli.Result{Diagnostic: command.UsageErr("revoke-hq takes no flags or arguments")}
	}
	if verb == "unpair" && (clientName != "terminal" || clientCount > 1) {
		return cli.Result{Diagnostic: command.UsageErr("unpair accepts at most one --client terminal; use revoke-hq for the enrolled HQ")}
	}
	if enrollSet && verb != "pair" {
		return cli.Result{Diagnostic: command.UsageErr("--enroll is only valid with pair")}
	}
	if fingerprintSet && verb != "pair" {
		return cli.Result{Diagnostic: command.UsageErr("--fingerprint is only valid with pair")}
	}
	if debug && verb != "install" {
		return cli.Result{Diagnostic: command.UsageErr("--debug is only valid with install")}
	}
	hqEnroll := verb == "pair" && enrollSet && clientName == "agent-daemon"
	if userSet && hqEnroll && userName == "" {
		return cli.Result{Diagnostic: command.UsageErr("--user requires a local account name")}
	}
	if userSet && !debug && !hqEnroll {
		return cli.Result{Diagnostic: command.UsageErr("--user is only valid with install --debug or pair --enroll --client agent-daemon")}
	}
	goos := deps.GOOS
	if goos == "" {
		goos = hostOS()
	}
	if identitySet && (verb != "run" || goos != "darwin" || !exactKey(requiredIdentity)) {
		return cli.Result{Diagnostic: command.UsageErr("--require-identity takes the paired Machine's lowercase SHA-256 fingerprint with daemon run on macOS")}
	}
	if owner.pinSet || owner.challenge || owner.proofSet {
		if goos != "darwin" || verb != "pair" || (owner.pinSet && (enrollSet || fingerprintSet || userSet || clientName != "terminal" || owner.challenge || owner.proofSet)) ||
			(!owner.pinSet && (!hqEnroll || (owner.challenge && owner.proofSet))) {
			return cli.Result{Diagnostic: command.UsageErr("use pair --pin-owner KEY or pair --enroll HEX --fingerprint SHA --client agent-daemon with --owner-challenge or --owner-proof JSON on macOS")}
		}
	}
	caller, err := deps.caller()
	if verb != "status" && verb != "receipts" {
		if err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
		if verb == "revoke-hq" && (caller.PrefixOwner == "" || goos == "darwin" && !caller.DarwinAdmin) {
			return ownerPairRefused("revoking HQ requires the Machine administrator")
		}
		if identitySet && (caller.PrefixOwner == "" || !caller.DarwinAdmin) {
			return ownerPairRefused("paired foreground startup requires the macOS prefix administrator")
		}
		switch verb {
		case "pair":
			if enrollSet || owner.pinSet {
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
	writesServices := verb == "install" || verb == "start" || verb == "stop" || verb == "uninstall"
	if goos == "darwin" && writesServices && deps.LockLifecycle != nil {
		lock, err := deps.LockLifecycle(caller.RegisteredHome, caller.UID)
		if err != nil {
			return serviceFailed(err)
		}
		defer func() {
			if err := lock.Close(); err != nil && result.Diagnostic == nil {
				result = serviceFailed(err)
			}
		}()
	}
	root, err := deps.root()
	if err == nil && (verb == "install" || verb == "start" || verb == "pair") {
		err = checkMachineAdmission()
	}
	if err != nil {
		return serviceFailed(err)
	}
	var reviewed serviceUnitReview
	if goos == "darwin" && writesServices && deps.ReadUserJob != nil {
		executable, err := deps.executable(ctx)
		if err != nil {
			return serviceFailed(err)
		}
		reviewed, err = inspectServiceLifecycle(caller, root, executable, verb, deps.ReadUserJob)
		if err != nil {
			return serviceFailed(err)
		}
		if reviewed.retainKeyd && deps.Deactivate != nil {
			deactivate := deps.Deactivate
			keydPath, _ := keydUnitPath(goos, root)
			deps.Deactivate = func(path string) error {
				if path == keydPath {
					return nil
				}
				return deactivate(path)
			}
		}
	}
	switch verb {
	case "status":
		on, err := Installed(goos, root)
		if err != nil {
			return serviceFailed(err)
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
			return serviceFailed(rpcErr)
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
		return ensureService(deps, ctx, caller, goos, root, userName, verb == "install", debug)
	case "stop", "uninstall":
		path, err := unitPath(goos, root)
		if err != nil {
			return serviceFailed(err)
		}
		if deps.Deactivate != nil {
			err = deps.Deactivate(path)
			if kpath, pathErr := keydUnitPath(goos, root); pathErr == nil {
				err = errors.Join(err, deps.Deactivate(kpath))
			}
			if err != nil {
				return serviceFailed(err)
			}
		}
		if verb == "stop" {
			rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "installed").Set("path", path)
			return cli.Result{Records: []*output.Record{rec}}
		}
		if reviewed.remove != nil {
			if err := reviewed.remove(); err != nil {
				return serviceFailed(err)
			}
		} else {
			if err := Uninstall(goos, root); err != nil {
				return serviceFailed(err)
			}
			if err := UninstallKeyd(goos, root); err != nil {
				return serviceFailed(err)
			}
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "absent")
		return cli.Result{Records: []*output.Record{rec}}
	case "run":
		if err := runService(context.Background(), root, requiredIdentity); err != nil {
			return serviceFailed(err)
		}
		rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", "stopped")
		return cli.Result{Records: []*output.Record{rec}}
	case "pair":
		if enrollSet || owner.pinSet {
			if err := prepareMachineLifecycle(root); err != nil {
				return serviceFailed(err)
			}
		}
		if goos == "darwin" && (owner.pinSet || hqEnroll) {
			// Serialize the first pin with legacy enrollment as well. Once a
			// pin exists every HQ enrollment on this host needs owner presence.
			if _, err := ensureStateDirAndPeers(stateDir(root)); err != nil {
				return serviceFailed(err)
			}
			unlock, err := lockOwnerPairing(stateDir(root))
			if err != nil {
				return serviceFailed(err)
			}
			defer func() {
				if err := unlock(); err != nil && result.Diagnostic == nil {
					result = serviceFailed(fmt.Errorf("close owner enrollment lock: %w", err))
				}
			}()
			existing, err := readOwnerPairState(stateDir(root))
			if err != nil {
				return serviceFailed(err)
			}
			if existing != nil || owner.pinSet || owner.challenge || owner.proofSet {
				if caller.PrefixOwner == "" || !caller.DarwinAdmin {
					return ownerPairRefused("owner presence enrollment requires the Homebrew prefix owner's macOS admin account")
				}
				return ownerPair(root, caller, existing, owner, enroll, fingerprint, userName)
			}
		}
		if enrollSet {
			if fingerprint == "" {
				return cli.Result{Diagnostic: command.UsageErr("pair --enroll needs --fingerprint")}
			}
			bound := ""
			if hqEnroll {
				uid, ok, err := PinAgentDaemonUser(root, userName)
				if err != nil {
					d := diag.New(diag.DaemonCallerRefused, err.Error())
					return cli.Result{Diagnostic: &d}
				}
				bound = "any"
				if ok {
					bound = strconv.Itoa(uid)
				}
			}
			staged, err := EnrollClient(root, clientName, enroll, fingerprint)
			if err != nil {
				d := diag.New(diag.DaemonCallerRefused, err.Error())
				return cli.Result{Diagnostic: &d}
			}
			rec := output.New().Set("service", "agent-machine").Set("client", clientName).Set("state", "paired").Set("path", staged)
			if bound != "" {
				rec.Set("uid", bound)
			}
			return cli.Result{Records: []*output.Record{rec}}
		}
		if fingerprintSet {
			return cli.Result{Diagnostic: command.UsageErr("--fingerprint is only valid with --enroll")}
		}
		if caller.Refuse() == "" {
			path, err := PairTerminal(root)
			if err != nil {
				return serviceFailed(err)
			}
			rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "paired").Set("path", path)
			return cli.Result{Records: []*output.Record{rec}}
		}
		if err := prepareMachineLifecycle(root); err != nil {
			return serviceFailed(err)
		}
		path, err := PairClient(root)
		if err != nil {
			return serviceFailed(err)
		}
		pub, err := loadPublic(path)
		if err != nil {
			return serviceFailed(err)
		}
		hint := enrollHint(pub, clientName)
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "minted").Set("path", path).Set("public", hex.EncodeToString(pub)).Set("fingerprint", publicFingerprint(pub)).Set("enroll", hint)
		return cli.Result{Records: []*output.Record{rec}, Human: "As the prefix owner run:\n" + hint + "\n"}
	case "revoke-hq":
		if err := revokeHQ(stateDir(root)); err != nil {
			return serviceFailed(err)
		}
		return cli.Result{Records: []*output.Record{output.New().Set("service", "agent-machine").Set("client", "agent-daemon").Set("state", "revoked")}}
	case "unpair":
		if err := UnpairTerminal(root); err != nil {
			return serviceFailed(err)
		}
		rec := output.New().Set("service", "agent-machine").Set("client", "terminal").Set("state", "revoked")
		return cli.Result{Records: []*output.Record{rec}}
	default:
		return cli.Result{Diagnostic: command.UsageErr("daemon verb must be run, install, start, stop, uninstall, status, receipts, pair, unpair, or revoke-hq")}
	}
}

func ensureService(deps Deps, ctx cli.Context, caller Caller, goos, root, userName string, install, debug bool) cli.Result {
	if err := checkChannelIdentity(root); err != nil {
		return serviceFailed(err)
	}
	if err := prepareMachineLifecycle(root); err != nil {
		return serviceFailed(err)
	}
	exec, err := deps.executable(ctx)
	if err != nil {
		return serviceFailed(err)
	}
	machinePath, err := unitPath(goos, root)
	if err != nil {
		return serviceFailed(err)
	}
	previous, err := readUnit(machinePath)
	if err != nil {
		return serviceFailed(err)
	}
	before := unitBackup{path: machinePath, previous: previous}
	keydPlan, err := planKeydUnit(goos, root, exec, filepath.Join(root, ".local", "state", "agent-bot"))
	if err != nil {
		return serviceFailed(err)
	}
	path, err := Install(goos, root, exec, "")
	if err != nil {
		return serviceFailed(err)
	}
	if err := keydPlan.write(); err != nil {
		return undoInstall(deps, before, keydPlan, err)
	}
	keydUnit := keydPlan.path
	if keydUnit != "" && deps.Activate != nil {
		if err := deps.Activate(keydUnit); err != nil {
			return undoInstall(deps, before, keydPlan, err)
		}
	}
	if install {
		if err := SetDebugClient(root, debug); err != nil {
			return serviceFailed(err)
		}
	}
	debugOn, err := debugClientEnabled(stateDir(root))
	if err != nil {
		return serviceFailed(err)
	}
	if userName != "" {
		if err := PinTerminalUser(root, userName); err != nil {
			d := diag.New(diag.DaemonCallerRefused, err.Error())
			return cli.Result{Diagnostic: &d}
		}
	}
	if deps.Activate != nil {
		if err := deps.Activate(path); err != nil {
			return undoInstall(deps, before, keydPlan, err)
		}
	}
	state := "installed"
	if deps.WaitHealthy != nil {
		if err := deps.WaitHealthy(); err != nil {
			return serviceFailed(err)
		}
		if keydUnit != "" {
			if err := waitBundledKeyd(caller, healthyWait); err != nil {
				return serviceFailed(fmt.Errorf("Machine is listening, but bundled keyd is not ready in the Homebrew administrator's login: %w; check its LaunchAgent and retry managed-machine daemon start", err))
			}
		}
		state = "running"
	}
	debugState := "off"
	if debugOn {
		debugState = "on"
	}
	rec := output.New().Set("service", "agent-machine").Set("scope", "user").Set("state", state).Set("path", path).Set("debug_client", debugState)
	return cli.Result{Records: []*output.Record{rec}}
}

// unitBackup is one unit file as it was before install wrote it.
type unitBackup struct {
	path     string
	previous []byte
}

// undoInstall puts every unit file back after the service manager refused
// one, then has the manager reread them, so status never reports a unit
// that is not loaded. The result always carries the activation error.
func undoInstall(deps Deps, machine unitBackup, keyd keydUnitPlan, cause error) cli.Result {
	if err := errors.Join(keyd.rollback(), restoreUnit(machine.path, machine.previous)); err != nil {
		return serviceFailed(fmt.Errorf("%v; restoring units: %w", cause, err))
	}
	if deps.Reload != nil {
		if err := deps.Reload(); err != nil {
			return serviceFailed(fmt.Errorf("%v; reloading after restoring the units: %v", cause, err))
		}
	}
	return serviceFailed(cause)
}

func serviceFailed(err error) cli.Result {
	d := diag.New(diag.DaemonServiceFailed, err.Error())
	return cli.Result{Diagnostic: &d}
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

// UninstallCommand is the local operator's package lifecycle, never a daemon RPC.
func UninstallCommand(deps Deps) cli.Command {
	return cli.Command{
		Name: "uninstall", Summary: "Remove the active macOS Homebrew Machine, keyd, and their user services",
		Usage: "managed-machine uninstall\nRun as the Homebrew prefix administrator after removing the managed HQ service. Pairing, keys, receipts and other applications are preserved.",
		Run: func(ctx cli.Context, args []string) cli.Result {
			if len(args) != 0 {
				return cli.Result{Diagnostic: command.UsageErr("uninstall takes no arguments")}
			}
			if deps.GOOS != "darwin" {
				return serviceFailed(errors.New("package uninstall is supported for macOS Homebrew installations"))
			}
			if err := uninstallMacPackage(deps); err != nil {
				return serviceFailed(err)
			}
			return cli.Result{Records: []*output.Record{output.New().Set("package", "managed-machine").Set("state", "removed")}}
		},
	}
}
