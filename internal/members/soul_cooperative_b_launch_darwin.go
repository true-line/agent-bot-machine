//go:build darwin

package members

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"
)

// runSoulCooperativeBridge starts the fixed native B under its separately
// signed cooperative assignment. Only the signed envelopes enter FD3; the
// 32-byte one-use proof enters FD4 and is never copied to HQ or R.
func runSoulCooperativeBridge(ctx context.Context, grant soulCooperativeBExecGrantV3,
	reservation soulCooperativeReservationPayloadV3, bridge soulCooperativeBridgeAssignmentPayloadV3,
	proof []byte, status, diagnostics *os.File) error {
	if ctx.Err() != nil || status == nil || diagnostics == nil || len(proof) != 32 ||
		len(grant.reservationEnvelope) == 0 || len(grant.bridgeEnvelope) == 0 ||
		grant.ReservationSHA256 != stage2aReservationSHA256(grant.reservationEnvelope) ||
		grant.BridgeAssignmentSHA256 != stage2aReservationSHA256(grant.bridgeEnvelope) ||
		bridge.Bridge.UID != os.Getuid() || bridge.Bridge.GID != os.Getgid() ||
		reservation.Assignment.StartID != bridge.StartID ||
		reservation.Assignment.LaunchID != bridge.LaunchID ||
		reservation.Assignment.PlanID != bridge.PlanID ||
		reservation.Assignment.PlanDigest != bridge.PlanDigest ||
		reservation.Assignment.HQEpoch != bridge.HQEpoch ||
		reservation.HostID != bridge.HostID || reservation.ExpiresAt != bridge.ExpiresAt ||
		bridge.Bridge.ExecutablePath != SoulBridgeBinary ||
		bridge.Bridge.SandboxProfilePath != SoulBridgeSandbox ||
		bridge.Bridge.SandboxProfileSHA256 != "sha256:"+harnessSHA(soulBridgeProfile) ||
		!stage2aPrefixedDigest.MatchString(bridge.Bridge.ExecutableSHA256) ||
		!cooperativeBParentReady(bridge.Endpoints.Broker) ||
		!cooperativeBParentReady(bridge.Endpoints.Member) ||
		!cooperativeBParentReady(bridge.Endpoints.Relay) {
		return errSoulCooperativeAuthority
	}
	canonical, err := marshalStage2aReservationJCS(bridge.Bridge)
	if err != nil || stage2aReservationSHA256(canonical) != bridge.BridgeLaunchSHA256 {
		return errSoulCooperativeAuthority
	}
	argv := []string{"/usr/bin/sandbox-exec", "-D", "BROKER_SOCKET=" + bridge.Endpoints.Broker.SocketPath,
		"-D", "MEMBER_SOCKET=" + bridge.Endpoints.Member.SocketPath,
		"-D", "RELAY_SOCKET=" + bridge.Endpoints.Relay.SocketPath,
		"-f", SoulBridgeSandbox, SoulBridgeBinary,
		"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"}
	if !slices.Equal(bridge.Bridge.Argv, argv) ||
		verifyHarnessExecutable(SoulBridgeBinary, bridge.Bridge.ExecutableSHA256[len("sha256:"):]) != nil ||
		trustedPath(OSHost{}, SoulBridgeSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulBridgeSandbox)) != nil {
		return errSoulCooperativeAuthority
	}
	profile, err := openPinnedFile(SoulBridgeSandbox, harnessSHA(soulBridgeProfile))
	if err != nil {
		return errSoulCooperativeAuthority
	}
	if profile.Close() != nil {
		return errSoulCooperativeAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return errSoulCooperativeAuthority
	}
	fd3, err := cooperativeBFD3(grant.reservationEnvelope, grant.bridgeEnvelope)
	if err != nil {
		return err
	}
	assignmentRead, err := stage2aBridgePipe(fd3)
	if err != nil {
		return err
	}
	defer assignmentRead.Close()
	proofRead, err := stage2aBridgePipe(proof)
	if err != nil {
		return err
	}
	defer proofRead.Close()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer statusRead.Close()
	defer statusWrite.Close()
	if ctx.Err() != nil || !time.Now().Before(expires) {
		return errSoulCooperativeAuthority
	}
	cmd := exec.Command(argv[0], argv[1:]...)
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
	relay := SoulEndpoint{SocketPath: bridge.Endpoints.Relay.SocketPath,
		OwnerUID: bridge.Endpoints.Relay.OwnerUID, GroupGID: bridge.Endpoints.Relay.GroupGID,
		SocketMode: bridge.Endpoints.Relay.SocketMode}
	go func() {
		var validated bytes.Buffer
		if err := forwardStage2aBridgeStatus(statusRead, &validated, relay); err != nil {
			forwarded <- err
			return
		}
		var native stage2aBridgeStatus
		if json.Unmarshal(validated.Bytes(), &native) != nil {
			forwarded <- errSoulCooperativeAuthority
			return
		}
		observed, err := observeSoulProcess(pid, SoulBridgeBinary,
			[]string{SoulBridgeBinary, "--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"})
		if err != nil || observed.Kernel.ParentPID != os.Getpid() ||
			observed.Kernel.ProcessGroupID != pid ||
			observed.Kernel.RealUID != uint32(grant.BridgeUID) ||
			observed.Kernel.EffectiveUID != uint32(grant.BridgeUID) ||
			observed.Kernel.PrimaryGroupGID != uint32(grant.BridgeGID) {
			forwarded <- errSoulCooperativeAuthority
			return
		}
		out := soulCooperativeBStatusV3{stage2aBridgeStatus: native,
			BridgePID: pid, BridgeStartSeconds: observed.Kernel.StartSeconds,
			BridgeStartMicros: observed.Kernel.StartMicros, GrantNonce: grant.Nonce}
		forwarded <- json.NewEncoder(status).Encode(out)
	}()
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	var forwardErr error
monitor:
	for {
		select {
		case <-ctx.Done():
			break monitor
		case err := <-forwarded:
			if err != nil {
				forwardErr = err
				break monitor
			}
			forwarded = nil
		case <-tick.C:
			leaderExited, _, err := harnessGroupState(pid)
			if err != nil || leaderExited {
				forwardErr = err
				break monitor
			}
		}
	}
	if !closeHarnessGroup(pid, time.Second) {
		return errors.New("cooperative Soul bridge containment unconfirmed")
	}
	waitErr := cmd.Wait()
	if forwarded != nil && forwardErr == nil && ctx.Err() == nil {
		select {
		case forwardErr = <-forwarded:
		case <-time.After(time.Second):
			forwardErr = errors.New("cooperative Soul bridge readiness unconfirmed")
		}
	}
	if forwardErr != nil {
		return forwardErr
	}
	return waitErr
}

type soulCooperativeBStatusV3 struct {
	stage2aBridgeStatus
	BridgePID          int    `json:"bridge_pid"`
	BridgeStartSeconds int64  `json:"bridge_start_seconds"`
	BridgeStartMicros  int32  `json:"bridge_start_micros"`
	GrantNonce         string `json:"grant_nonce"`
}
