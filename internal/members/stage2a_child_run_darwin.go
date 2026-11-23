//go:build darwin

package members

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// runStage2aChild remains an unconfined, fixed Machine wrapper under R's UID.
// macOS rejects nesting sandbox-exec inside R's outer profile, so this is a
// distinct sudo rule and process group. Only its measured stock child is put
// under the pinned relay-only profile. No ACP bytes pass before A signs the
// observed child and the wrapper verifies its first challenge-bound lease.
func runStage2aChild(ctx context.Context, in Stage2aRoleInvocation, grantSHA256 string,
	pub ed25519.PublicKey, acp *bufio.Reader, control, stdout, status *os.File) int {
	child := in.ChildExec
	if child == nil || !in.Request.valid() ||
		in.Start.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		in.Start.InstallationID != in.Request.InstallationID ||
		in.Start.StartID != in.Request.StartID || in.Start.HQEpoch != in.Request.HQEpoch ||
		in.Start.RunnerUID != os.Getuid() || in.Start.RunnerGID != os.Getgid() ||
		os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() ||
		os.Getenv("SUDO_USER") != DarwinHQAccount ||
		os.Getenv("SUDO_UID") != strconv.Itoa(in.Start.HQUID) ||
		child.ReservationSHA256 == "" || !validStage2aExecDigest(grantSHA256) ||
		child.SandboxPath != SoulChildSandbox ||
		child.SandboxSHA256 != "sha256:"+harnessSHA(soulChildProfile) ||
		child.RelaySocket != in.Start.Relay.SocketPath ||
		child.ExecutableSHA256 != in.Launch.ComponentDigests["adapter"] ||
		child.RuntimeV3 == nil || !stage2aSystemImageSelected(in.Launch, "/usr/bin/sandbox-exec") {
		return harnessRefused
	}
	rInventory, err := stage2aCheckChildCodeV3(*child.RuntimeV3, child.Executable, child.ExecutableSHA256)
	if err != nil || stage2aAdapterChildEnvV3(in.Launch, nil, *child.RuntimeV3, rInventory) != nil {
		return harnessRefused
	}
	expires, err := time.Parse(time.RFC3339Nano, child.GrantExpiresAt)
	if err != nil || !time.Now().Before(expires) || time.Until(expires) > stage2aChildGrantLife ||
		stage2aCheckRuntimeSnapshot(in.Binding.Snapshots.LaunchInputs, in.Launch.Files) != nil ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return harnessRefused
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return harnessRefused
	}
	adapterID, _ := in.Launch.EffectiveConfig["adapter_id"].(string)
	adapter, _ := in.Launch.HostProjection.Adapters[adapterID].(map[string]any)
	command, _ := adapter["command"].([]any)
	if len(command) != 1 || child.Executable != command[0] {
		return harnessRefused
	}
	workdir, environment, err := stage2aChildEnvironment(in.Runner, in.Start, in.Launch)
	if err != nil || workdir != child.Workdir || len(environment) != len(child.Environment) {
		return harnessRefused
	}
	for key, value := range environment {
		if child.Environment[key] != value {
			return harnessRefused
		}
	}
	if stage2aCreateChildState(in.Runner, in.Start) != nil {
		return harnessRefused
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-D", "RELAY_SOCKET="+child.RelaySocket,
		"-f", child.SandboxPath, child.Executable)
	cmd.Dir = child.Workdir
	cmd.Env = make([]string, 0, len(environment))
	for key, value := range environment {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	slices.Sort(cmd.Env)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reporter := &harnessReporter{output: status}
	onStart := func(pid int) error {
		var observed soulKernelProcessSnapshot
		for time.Now().Before(expires) {
			observed, err = observeStage2aChildProcess(pid, os.Getpid(), in.Runner, in.Launch)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		launcher, launcherErr := observeStage2aRoleProcess(os.Getpid(), in.Runner.UID, in.Runner.GID, "child")
		if err != nil || launcherErr != nil ||
			reporter.write(struct {
				Kind             string `json:"kind"`
				ChildPID         int    `json:"child_pid"`
				ChildLauncherPID int    `json:"child_launcher_pid"`
				GrantSHA256      string `json:"grant_sha256"`
			}{"child-started", pid, os.Getpid(), grantSHA256}) != nil {
			return errors.New("protected stock child could not be observed")
		}
		if control.SetReadDeadline(expires) != nil {
			return errors.New("protected child receipt deadline unavailable")
		}
		line, readErr := acp.ReadSlice('\n')
		if readErr != nil || len(line) > stage2aExecMaxFrame || control.SetReadDeadline(time.Time{}) != nil {
			return errors.New("protected child receipt unavailable")
		}
		var receipt Stage2aChildReadyReply
		if decodeStage2aRoleJSON(line, &receipt) != nil {
			return errors.New("invalid protected child receipt frame")
		}
		signedReceipt, err := verifyStage2aChildStartReceipt(receipt, in, grantSHA256,
			launcher, observed, pub, time.Now())
		if err != nil {
			return err
		}
		first, err := requestStage2aChildLive(in, receipt.SHA256, launcher, observed,
			pub, 0, time.UnixMilli(signedReceipt.ExpiresAtMS))
		if err != nil {
			return err
		}
		// Keep renewal active during the bounded profile control. The stock
		// child's ACP stdin remains held by superviseHarnessStarted throughout.
		go watchStage2aChildLive(childCtx, cancel, in, receipt.SHA256,
			launcher, observed, pub, first)
		if spec := signedReceipt.ProtectedControlProbe; spec != nil {
			artifact, probeErr := runStage2aProtectedControlProbes(childCtx, in,
				receipt.SHA256, launcher, observed, *spec)
			if probeErr != nil || childCtx.Err() != nil ||
				time.Until(time.UnixMilli(first.ExpiresAtMS)) <= time.Second {
				return errors.New("protected child control probe refused")
			}
			if reporter.write(struct {
				Kind              string `json:"kind"`
				ReceiptSHA256     string `json:"receipt_sha256"`
				ArtifactSHA256    string `json:"artifact_sha256"`
				ArtifactBase64URL string `json:"artifact_base64url"`
			}{"child-control-probe", receipt.SHA256, stage2aReservationSHA256(artifact),
				base64.RawURLEncoding.EncodeToString(artifact)}) != nil {
				return errors.New("protected child control probe was not delivered")
			}
		}
		if reporter.write(struct {
			Kind          string `json:"kind"`
			ReceiptSHA256 string `json:"receipt_sha256"`
			LeaseSequence uint64 `json:"lease_sequence"`
		}{"child-accepted", receipt.SHA256, first.Sequence}) != nil {
			return errors.New("protected child acceptance not delivered")
		}
		return nil
	}
	return superviseHarnessStarted(childCtx, cmd, acp, control, stdout, reporter, time.Second, onStart)
}

func stage2aCreateChildState(runner SoulRunner, start SoulStartAssignment) error {
	state, err := stage2aRunnerStateRoot(runner)
	if err != nil {
		return err
	}
	parent, err := openStage2aAdminDirectory(state, uint32(runner.UID))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := "child-" + soulEndpointStartSlot(runner.InstallationID, start.StartID)
	base, err := stage2aOpenRunnerStateDir(int(parent.Fd()), name, state+"/"+name, runner)
	if err != nil {
		return err
	}
	defer unix.Close(base)
	for _, dir := range []string{"work", "home", "tmpdir", "xdg_config_home", "xdg_cache_home",
		"xdg_data_home", "xdg_state_home", "xdg_runtime_dir"} {
		fd, err := stage2aOpenRunnerStateDir(base, dir, state+"/"+name+"/"+dir, runner)
		if err != nil {
			return err
		}
		unix.Close(fd)
	}
	return nil
}

func watchStage2aChildLive(ctx context.Context, cancel context.CancelFunc, in Stage2aRoleInvocation,
	receiptSHA256 string, launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	first Stage2aLiveLeasePayload) {
	watchStage2aChildLiveWithRequest(ctx, cancel, first, func(after uint64,
		priorExpires time.Time) (Stage2aLiveLeasePayload, error) {
		return requestStage2aChildLive(in, receiptSHA256, launcher, child,
			pub, after, priorExpires)
	})
}

// The independent timer cancels the child even if the HQ renewal I/O blocks.
// A late signed response never extends a lease that already lapsed.
func watchStage2aChildLiveWithRequest(ctx context.Context, cancel context.CancelFunc,
	first Stage2aLiveLeasePayload, request func(uint64, time.Time) (Stage2aLiveLeasePayload, error)) {
	last := first
	for {
		expires := time.UnixMilli(last.ExpiresAtMS)
		remaining := time.Until(expires)
		if remaining <= 0 {
			cancel()
			return
		}
		expiryTimer := time.AfterFunc(remaining, cancel)
		wait := remaining - 2*time.Second
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			expiryTimer.Stop()
			return
		case <-time.After(wait):
		}
		for {
			if ctx.Err() != nil || !time.Now().Before(expires) {
				expiryTimer.Stop()
				cancel()
				return
			}
			next, err := request(last.Sequence, expires)
			if ctx.Err() != nil || !time.Now().Before(expires) {
				expiryTimer.Stop()
				cancel()
				return
			}
			if err == nil && next.Sequence > last.Sequence &&
				time.Now().UnixMilli() < next.ExpiresAtMS {
				if !expiryTimer.Stop() || ctx.Err() != nil || !time.Now().Before(expires) {
					cancel()
					return
				}
				last = next
				break
			}
			retry := time.Until(expires)
			if retry > 100*time.Millisecond {
				retry = 100 * time.Millisecond
			}
			select {
			case <-ctx.Done():
				expiryTimer.Stop()
				return
			case <-time.After(retry):
			}
		}
	}
}
