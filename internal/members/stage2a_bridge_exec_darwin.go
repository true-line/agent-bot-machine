package members

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aBridgeMaxAssignment = 16 * 1024

// runStage2aBridge executes the native relay from the fixed B command after
// the caller has authenticated the one-use launch and checked the installed
// grant. The assignment and proof must come from that authorization.
func runStage2aBridge(ctx context.Context, request SoulRunRequest, start SoulStartAssignment,
	runner SoulRunner, bridge SoulBridge, executable HarnessArtifact, launchInputs Stage2aLaunchInputRecords, binding Stage2aMeasurementBinding, assignment []byte,
	proof []byte, status, diagnostics *os.File) error {
	expires, err := time.Parse(time.RFC3339Nano, start.ExpiresAt)
	if err != nil || time.Until(expires) <= 0 || time.Until(expires) > 30*time.Second ||
		!request.valid() || start.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		start.PlanDigest != request.PlanDigest || start.InstallationID != request.InstallationID ||
		start.StartID != request.StartID || start.HQEpoch != request.HQEpoch ||
		runner.InstallationID != request.InstallationID || start.SoulID != runner.SoulID ||
		start.BridgeAccount != bridge.Account || start.BridgeUID != bridge.UID || start.BridgeGID != bridge.GID ||
		!harnessKernelRole(HarnessAdapter{Account: bridge.Account, UID: bridge.UID}) ||
		os.Getenv("SUDO_USER") != DarwinHQAccount || os.Getenv("SUDO_UID") != strconv.Itoa(start.HQUID) ||
		len(assignment) == 0 || len(assignment) > stage2aBridgeMaxAssignment || len(proof) != 32 ||
		status == nil || diagnostics == nil || ctx.Err() != nil {
		return errors.New("invalid authorized Soul bridge invocation")
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(launchInputs)
	if err != nil || !stage2aReservationBindingMatches(binding, start, binding.HostID,
		uint32(start.MachineUID), uint32(start.RunnerGID)) ||
		launchDigest != binding.LaunchInputMeasurement ||
		launchInputs.ComponentDigests["bridge"] != "sha256:"+executable.SHA256 {
		return errors.New("Soul bridge differs from the measured launch inputs")
	}
	endpoints, err := DeriveSoulBridgeEndpoints(runner, bridge, start.HQUID, request.StartID)
	if err != nil {
		return err
	}
	assignmentRead, err := stage2aBridgePipe(assignment)
	if err != nil {
		return err
	}
	defer assignmentRead.Close()
	proofRead, err := stage2aBridgePipe(proof)
	if err != nil {
		return err
	}
	defer proofRead.Close()
	// The native sidecar requires a pipe. The launcher copies readiness to
	// HQ's stdout and keeps child diagnostics on stderr.
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer statusRead.Close()
	defer statusWrite.Close()

	if err := verifyHarnessExecutable(executable.Path, executable.SHA256); err != nil {
		return err
	}
	if err := trustedPath(OSHost{}, SoulBridgeSandbox, false); err != nil {
		return err
	}
	if err := checkDarwinACLs(pathAncestry(SoulBridgeSandbox)); err != nil {
		return err
	}
	profile, err := openPinnedFile(SoulBridgeSandbox, harnessSHA(soulBridgeProfile))
	if err != nil {
		return err
	}
	if err := profile.Close(); err != nil {
		return err
	}
	if !time.Now().Before(expires) || ctx.Err() != nil {
		return errors.New("Soul bridge launch authorization expired")
	}

	cmd := exec.Command("/usr/bin/sandbox-exec",
		"-D", "BROKER_SOCKET="+endpoints.Broker.SocketPath,
		"-D", "MEMBER_SOCKET="+endpoints.Member.SocketPath,
		"-D", "RELAY_SOCKET="+endpoints.Relay.SocketPath,
		"-f", SoulBridgeSandbox, executable.Path,
		"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stderr = diagnostics
	cmd.ExtraFiles = []*os.File{assignmentRead, proofRead, statusWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	assignmentRead.Close()
	proofRead.Close()
	statusWrite.Close()
	pid := cmd.Process.Pid
	forwarded := make(chan error, 1)
	go func(done chan<- error) {
		done <- forwardStage2aBridgeStatus(statusRead, status, endpoints.Relay)
	}(forwarded)
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	var relayErr error
monitor:
	for {
		select {
		case <-ctx.Done():
			break monitor
		case err := <-forwarded:
			if err != nil {
				relayErr = err
				break monitor
			}
			forwarded = nil
		case <-tick.C:
			leaderExited, _, err := harnessGroupState(pid)
			if err != nil || leaderExited {
				if err != nil {
					relayErr = err
				}
				break monitor
			}
		}
	}
	if !closeHarnessGroup(pid, time.Second) {
		return errors.New("Soul bridge containment unconfirmed")
	}
	waitErr := cmd.Wait()
	if forwarded != nil && relayErr == nil && ctx.Err() == nil {
		select {
		case relayErr = <-forwarded:
		case <-time.After(time.Second):
			relayErr = errors.New("Soul bridge readiness unconfirmed")
		}
	}
	if relayErr != nil {
		return relayErr
	}
	return waitErr
}

func stage2aBridgePipe(data []byte) (*os.File, error) {
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer write.Close()
		_, _ = write.Write(data)
	}()
	return read, nil
}

type stage2aBridgeStatus struct {
	BindReceipt string `json:"bind_receipt_sha256"`
	RelaySocket struct {
		UID    uint32 `json:"uid"`
		GID    uint32 `json:"gid"`
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
		Mode   uint32 `json:"mode"`
	} `json:"relay_socket"`
}

func forwardStage2aBridgeStatus(input io.Reader, output io.Writer, relay SoulEndpoint) error {
	invalid := errors.New("invalid Soul bridge readiness record")
	raw, err := io.ReadAll(io.LimitReader(input, 1025))
	var record stage2aBridgeStatus
	if err != nil || len(raw) > 1024 || stage2aStrictJSON(raw) != nil ||
		json.Unmarshal(raw, &record) != nil || !soulDigest.MatchString(record.BindReceipt) ||
		record.RelaySocket.UID != uint32(relay.OwnerUID) ||
		record.RelaySocket.GID != uint32(relay.GroupGID) ||
		record.RelaySocket.Mode != relay.SocketMode {
		return invalid
	}
	var st unix.Stat_t
	if err := unix.Lstat(relay.SocketPath, &st); err != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		uint32(st.Mode&07777) != relay.SocketMode || st.Uid != record.RelaySocket.UID ||
		st.Gid != record.RelaySocket.GID || st.Ino == 0 || st.Ino != record.RelaySocket.Inode ||
		uint64(st.Dev) != record.RelaySocket.Device {
		return invalid
	}
	return json.NewEncoder(output).Encode(record)
}
