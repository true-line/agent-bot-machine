//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	stage2aProtectedControlProbeCommand = "stage2a-protected-control-probe"
	stage2aProtectedControlProbeSchema  = "agent-bot-machine/stage2a-protected-control-probe/v1"
)

type stage2aProtectedProbeKernelIdentity struct {
	PID          int      `json:"pid"`
	ParentPID    int      `json:"parent_pid"`
	GroupPID     int      `json:"process_group_id"`
	RealUID      uint32   `json:"real_uid"`
	EffectiveUID uint32   `json:"effective_uid"`
	SavedUID     uint32   `json:"saved_uid"`
	RealGID      uint32   `json:"real_gid"`
	PrimaryGID   uint32   `json:"primary_gid"`
	SavedGID     uint32   `json:"saved_gid"`
	Groups       []uint32 `json:"groups"`
	StartSeconds int64    `json:"start_seconds"`
	StartMicros  int32    `json:"start_micros"`
}

func stage2aProtectedProbeIdentity(p soulKernelProcessSnapshot) stage2aProtectedProbeKernelIdentity {
	return stage2aProtectedProbeKernelIdentity{PID: p.PID, ParentPID: p.ParentPID,
		GroupPID: p.ProcessGroupID, RealUID: p.RealUID, EffectiveUID: p.EffectiveUID,
		SavedUID: p.SavedUID, RealGID: p.RealGID, PrimaryGID: p.PrimaryGroupGID,
		SavedGID: p.SavedGID, Groups: append([]uint32(nil), p.Groups...),
		StartSeconds: p.StartSeconds, StartMicros: p.StartMicros}
}

func stage2aProtectedProbeAccountIsR(p soulKernelProcessSnapshot, uid, gid int) bool {
	if uid < 300 || uid > 399 || gid != uid || p.RealUID != uint32(uid) ||
		p.EffectiveUID != uint32(uid) || p.SavedUID != uint32(uid) ||
		p.RealGID != uint32(gid) || p.PrimaryGroupGID != uint32(gid) ||
		p.SavedGID != uint32(gid) || len(p.Groups) != 1 {
		return false
	}
	return p.Groups[0] == uint32(gid)
}

// HQ's candidate-only local provider uses this exact start-scoped loopback
// port. The bound epoch and start avoid an HQ- or R-selected test endpoint.
func stage2aProtectedProviderPortV1(epoch, installationID, startID string) int {
	sum := sha256.Sum256([]byte("agent-bot-stage2a-local-provider-v1\x00" + epoch + "\x00" + installationID + "\x00" + startID))
	return 49152 + int(binary.BigEndian.Uint16(sum[:2])%16384)
}

type stage2aProtectedControlProbeResult struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	PID           int    `json:"pid"`
	UID           int    `json:"uid"`
	CapturedAt    string `json:"captured_at"`
	DirectIPv4    string `json:"direct_ipv4"`
	DirectIPv6    string `json:"direct_ipv6"`
	AssignedRelay string `json:"assigned_relay"`
	SiblingSocket string `json:"sibling_socket"`
	SiblingToken  string `json:"sibling_token"`
}

type stage2aProtectedControlProbeEvidence struct {
	Schema             string                              `json:"schema"`
	Kind               string                              `json:"kind"`
	Phase              string                              `json:"phase"`
	ControlOnly        bool                                `json:"control_only"`
	Spec               Stage2aProtectedControlProbeSpec    `json:"spec"`
	ChildReceiptSHA256 string                              `json:"child_receipt_sha256"`
	ReservationSHA256  string                              `json:"reservation_sha256"`
	ProfileSHA256      string                              `json:"profile_sha256"`
	Runner             Stage2aLiveRoleIdentity             `json:"runner"`
	Bridge             Stage2aLiveRoleIdentity             `json:"bridge"`
	Launcher           stage2aProtectedProbeKernelIdentity `json:"launcher"`
	Child              stage2aProtectedProbeKernelIdentity `json:"stock_child"`
	Probe              stage2aProtectedProbeKernelIdentity `json:"probe"`
	Result             stage2aProtectedControlProbeResult  `json:"result"`
}

func validStage2aProtectedControlProbeSpec(spec Stage2aProtectedControlProbeSpec, in Stage2aRoleInvocation) bool {
	return in.ChildExec != nil && stage2aProtectedControlProbeSpecMatches(spec,
		in.Start, in.Launch.ComponentDigests["test_provider"])
}

// A calls this with its installed assignment and provider digest before
// signing ChildReady. R calls it again with the verified invocation.
func stage2aProtectedControlProbeSpecMatches(spec Stage2aProtectedControlProbeSpec,
	assignment SoulStartAssignment, providerSHA string) bool {
	if spec.Schema != stage2aProtectedControlProbeSchema ||
		spec.InstallationID != assignment.InstallationID || spec.StartID != assignment.StartID ||
		spec.LaunchID != assignment.LaunchID || spec.PlanDigest != assignment.PlanDigest ||
		spec.HQEpoch != assignment.HQEpoch ||
		spec.ProviderConfigSHA256 != providerSHA ||
		!stage2aPrefixedDigest.MatchString(spec.ProviderConfigSHA256) ||
		spec.ProviderPort != stage2aProtectedProviderPortV1(assignment.HQEpoch, assignment.InstallationID, assignment.StartID) ||
		!stage2aBindingID.MatchString(spec.ProviderModel) ||
		!stage2aPrefixedDigest.MatchString(spec.ProviderRequestSHA256) ||
		!soulInstallationID.MatchString(spec.SiblingInstallationID) ||
		spec.SiblingInstallationID == spec.InstallationID ||
		!soulStartID.MatchString(spec.SiblingStartID) ||
		spec.SiblingBridgeUID < 300 || spec.SiblingBridgeUID > 399 ||
		spec.SiblingBridgeUID == assignment.BridgeUID ||
		spec.SiblingBridgeUID == assignment.RunnerUID ||
		spec.SiblingBridgeUID == assignment.HQUID ||
		spec.SiblingBridgeUID == assignment.MachineUID {
		return false
	}
	proofDir, proofName := stage2aBridgeProofPath(SoulStartAssignment{
		InstallationID: spec.SiblingInstallationID, StartID: spec.SiblingStartID})
	if spec.SiblingTokenPath != filepath.Join(proofDir, proofName) ||
		len(spec.SiblingTokenPath) > 512 {
		return false
	}
	siblingSocket := filepath.Join(launchRuntimeDir, "s", soulEndpointInstallationSlot(spec.SiblingInstallationID),
		soulEndpointStartSlot(spec.SiblingInstallationID, spec.SiblingStartID)+".sock")
	return spec.SiblingRelaySocket == siblingSocket &&
		spec.SiblingRelaySocket != assignment.Relay.SocketPath && len(siblingSocket) <= 103
}

// runStage2aProtectedControlProbes is called only by the R-UID child wrapper
// after A's signed ChildReady and first live lease, before ACP traffic. It
// starts a separate process under the exact installed child profile. Its raw
// result is a negative control, never a T01/T03 verdict or proof that the
// stock ACP PID attempted direct egress. A must independently join live
// R/B/child identities and provider zero-hit logs before signing a result.
func runStage2aProtectedControlProbes(ctx context.Context, in Stage2aRoleInvocation,
	childReceiptSHA string, launcher, child soulKernelProcessSnapshot,
	spec Stage2aProtectedControlProbeSpec) ([]byte, error) {
	if ctx == nil || !validStage2aProtectedControlProbeSpec(spec, in) ||
		!validStage2aExecDigest(childReceiptSHA) ||
		os.Getuid() != in.Start.RunnerUID || os.Geteuid() != os.Getuid() ||
		os.Getgid() != in.Start.RunnerGID || os.Getegid() != os.Getgid() ||
		launcher.PID != os.Getpid() ||
		!stage2aProtectedProbeAccountIsR(launcher, in.Start.RunnerUID, in.Start.RunnerGID) ||
		child.PID <= 1 || child.PID == launcher.PID || child.ParentPID != launcher.PID ||
		!stage2aProtectedProbeAccountIsR(child, in.Start.RunnerUID, in.Start.RunnerGID) ||
		in.ChildExec.RelaySocket != in.Start.Relay.SocketPath ||
		!stage2aPrefixedDigest.MatchString(in.Launch.ComponentDigests["machine"]) ||
		verifyHarnessExecutableLimit(SoulLauncher,
			strings.TrimPrefix(in.Launch.ComponentDigests["machine"], "sha256:"), 512<<20) != nil ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return nil, errStage2aReservationAuthority
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return nil, errStage2aReservationAuthority
	}
	startedAt := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, "/usr/bin/sandbox-exec", "-D",
		"RELAY_SOCKET="+in.Start.Relay.SocketPath, "-f", SoulChildSandbox,
		SoulLauncher, stage2aProtectedControlProbeCommand)
	command.Dir = "/"
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty"}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	stdout, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return nil, errStage2aReservationAuthority
	}
	var ready [1]byte
	if _, err := io.ReadFull(stdout, ready[:]); err != nil || ready[0] != 'R' {
		_ = command.Wait()
		return nil, errStage2aReservationAuthority
	}
	probe, err := observeSoulProcess(command.Process.Pid, SoulLauncher,
		[]string{SoulLauncher, stage2aProtectedControlProbeCommand})
	if err != nil || probe.Kernel.ParentPID != os.Getpid() ||
		!stage2aProtectedProbeAccountIsR(probe.Kernel, in.Start.RunnerUID, in.Start.RunnerGID) ||
		probe.Kernel.PID == child.PID {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errStage2aReservationAuthority
	}
	request, err := json.Marshal(struct {
		Stage2aProtectedControlProbeSpec
		RelaySocket string `json:"relay_socket"`
	}{spec, in.Start.Relay.SocketPath})
	if err != nil || len(request) > stage2aProtectedControlProbeLimit {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, errStage2aReservationAuthority
	}
	_, writeErr := stdin.Write(append(request, '\n'))
	closeErr := stdin.Close()
	raw, readErr := io.ReadAll(io.LimitReader(stdout, stage2aProtectedControlProbeLimit+1))
	waitErr := command.Wait()
	if writeErr != nil || closeErr != nil || readErr != nil || waitErr != nil ||
		len(raw) == 0 || len(raw) > stage2aProtectedControlProbeLimit ||
		stage2aStrictJSON(bytes.TrimSpace(raw)) != nil {
		return raw, errStage2aReservationAuthority
	}
	var result stage2aProtectedControlProbeResult
	if stage2aDecodeExact(bytes.TrimSpace(raw), &result) != nil ||
		result.Schema != stage2aProtectedControlProbeSchema || result.Kind != "negative-control" ||
		result.PID != probe.Kernel.PID || result.UID != in.Start.RunnerUID ||
		result.DirectIPv4 != "EPERM" && result.DirectIPv4 != "EACCES" ||
		result.DirectIPv6 != "EPERM" && result.DirectIPv6 != "EACCES" ||
		result.AssignedRelay != "connected" ||
		result.SiblingSocket != "EPERM" && result.SiblingSocket != "EACCES" ||
		result.SiblingToken != "EPERM" && result.SiblingToken != "EACCES" {
		return raw, errStage2aReservationAuthority
	}
	capturedAt, capturedErr := time.Parse(time.RFC3339Nano, result.CapturedAt)
	if capturedErr != nil || capturedAt.Before(startedAt) || capturedAt.After(time.Now()) {
		return raw, errStage2aReservationAuthority
	}
	endChild, childErr := observeSoulKernelProcess(child.PID)
	endLauncher, launcherErr := observeSoulKernelProcess(launcher.PID)
	if childErr != nil || launcherErr != nil || !sameSoulKernelProcess(child, endChild) ||
		!sameSoulKernelProcess(launcher, endLauncher) || probeCtx.Err() != nil {
		return raw, errStage2aReservationAuthority
	}
	evidence := stage2aProtectedControlProbeEvidence{
		Schema: stage2aProtectedControlProbeSchema, Kind: "negative-control", Phase: "pre-acp",
		ControlOnly: true, Spec: spec, ChildReceiptSHA256: childReceiptSHA,
		ReservationSHA256: in.ChildExec.ReservationSHA256,
		ProfileSHA256:     "sha256:" + harnessSHA(soulChildProfile),
		Runner:            in.ChildExec.Runner, Bridge: in.ChildExec.Bridge,
		Launcher: stage2aProtectedProbeIdentity(launcher),
		Child:    stage2aProtectedProbeIdentity(child), Probe: stage2aProtectedProbeIdentity(probe.Kernel),
		Result: result,
	}
	encoded, err := json.Marshal(evidence)
	if err != nil || len(encoded) > stage2aProtectedControlProbeLimit {
		return raw, errors.New("protected control evidence exceeded bound")
	}
	return encoded, nil
}
