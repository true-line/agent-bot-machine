//go:build darwin

package members

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	stage2aCooperativeReadyPurpose = "agent-bot/soul-cooperative-member-ready/v3"
	stage2aCooperativeLeasePurpose = "agent-bot/soul-cooperative-member-live-lease/v3"
)

type stage2aCooperativeReadyMember struct {
	MemberID           string                               `json:"member_id"`
	MemberLaunchID     string                               `json:"member_launch_id"`
	MemberSelector     string                               `json:"member_selector"`
	GrantSHA256        string                               `json:"grant_sha256"`
	LauncherProcess    stage2aMemberObservedLauncherProcess `json:"launcher_process"`
	ChildProcess       stage2aMemberObservedProcess         `json:"child_process"`
	HObservationSHA256 string                               `json:"h_observation_sha256"`
	BArmReceiptSHA256  string                               `json:"b_arm_receipt_sha256"`
}

// A signs this only after the two exact children, both H observations and both
// B arm acknowledgments join to the same reservation. One member cannot arm
// itself by replaying its grant.
type stage2aCooperativeReadyPayload struct {
	Contract                 string                           `json:"contract"`
	Kind                     string                           `json:"kind"`
	SchemaVersion            int                              `json:"schema_version"`
	ProfileInForce           string                           `json:"profile_in_force"`
	HostID                   string                           `json:"host_id"`
	InstallationID           string                           `json:"installation_id"`
	StartID                  string                           `json:"start_id"`
	HQEpoch                  string                           `json:"hq_epoch"`
	ReservationSHA256        string                           `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256 string                           `json:"assignment_envelope_sha256"`
	Members                  [2]stage2aCooperativeReadyMember `json:"members"`
	IssuedAt                 string                           `json:"issued_at"`
	ExpiresAt                string                           `json:"expires_at"`
}

type stage2aCooperativeLeasePayload struct {
	Contract                 string                               `json:"contract"`
	Kind                     string                               `json:"kind"`
	SchemaVersion            int                                  `json:"schema_version"`
	ProfileInForce           string                               `json:"profile_in_force"`
	ReservationSHA256        string                               `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256 string                               `json:"assignment_envelope_sha256"`
	ReadyEnvelopeSHA256      string                               `json:"ready_envelope_sha256"`
	MemberID                 string                               `json:"member_id"`
	MemberLaunchID           string                               `json:"member_launch_id"`
	MemberSelector           string                               `json:"member_selector"`
	GrantSHA256              string                               `json:"grant_sha256"`
	LauncherProcess          stage2aMemberObservedLauncherProcess `json:"launcher_process"`
	ChildProcess             stage2aMemberObservedProcess         `json:"child_process"`
	ChallengeNonceBase64URL  string                               `json:"challenge_nonce_base64url"`
	Sequence                 uint64                               `json:"sequence"`
	IssuedAt                 string                               `json:"issued_at"`
	ExpiresAt                string                               `json:"expires_at"`
}

// The integrator supplies A's private Ready and lease exchange. The callbacks
// are transport only; this wrapper verifies both A signatures and every
// kernel/selection join before ACP input is copied.
type stage2aCooperativeChildGate struct {
	Await func(stage2aMemberObservedLauncherProcess, stage2aMemberObservedProcess,
		string, string, time.Time) ([]byte, []byte, error)
	Renew func(string, string, uint64, time.Time) ([]byte, error)
}

func stage2aCooperativeFreshNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// The copy loop rechecks the current signed lease after each blocking read.
// A renewal may extend this deadline only after its A signature is verified.
type stage2aCooperativeLeasedReader struct {
	input   io.Reader
	expires *atomic.Int64
}

func (r stage2aCooperativeLeasedReader) Read(data []byte) (int, error) {
	if time.Until(time.UnixMilli(r.expires.Load())) <= time.Second {
		return 0, io.EOF
	}
	n, err := r.input.Read(data)
	if time.Until(time.UnixMilli(r.expires.Load())) <= time.Second {
		return 0, io.EOF
	}
	return n, err
}

func verifyStage2aCooperativeChildGrant(frame []byte, challenge stage2aExecChallenge,
	pub ed25519.PublicKey, now time.Time) (stage2aCooperativeChildInvocation,
	stage2aCooperativeChildGrant, string, error) {
	var empty stage2aCooperativeChildInvocation
	var grant stage2aCooperativeChildGrant
	invalid := errSoulCooperativeAuthority
	var reply Stage2aExecReply
	if len(frame) > stage2aExecMaxFrame || stage2aDecodeExact(frame, &reply) != nil ||
		challenge.Role != "child" || challenge.PID <= 1 || len(pub) != ed25519.PublicKeySize {
		return empty, grant, "", invalid
	}
	envelope, err := decodeStage2aRoleBase64(reply.EnvelopeBase64URL, 8<<10)
	if err != nil || stage2aReservationSHA256(envelope) != reply.SHA256 {
		return empty, grant, "", invalid
	}
	raw, err := verifyStage2aStoredARecordV3(envelope,
		stage2aCooperativeChildGrantPurpose, 1, pub)
	if err != nil || stage2aDecodeExact(raw, &grant) != nil ||
		grant.Contract != "machine/v3" || grant.ProfileInForce != "managed-cooperative" ||
		grant.PID != challenge.PID || grant.Nonce != challenge.Nonce ||
		!validStage2aExecDigest(grant.ReservationSHA256) ||
		!validStage2aExecDigest(grant.BridgeAssignmentSHA256) ||
		!validStage2aExecDigest(grant.AssignmentEnvelopeSHA256) ||
		!validStage2aExecDigest(grant.MemberBAuthoritySHA256) ||
		!stage2aMemberSelectorPattern.MatchString(grant.MemberSelector) ||
		!soulLaunchID.MatchString(grant.MemberLaunchID) {
		return empty, grant, "", invalid
	}
	until, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || !now.Before(until) || until.Sub(now) > stage2aMemberChildGrantLife {
		return empty, grant, "", invalid
	}
	invocationRaw, err := decodeStage2aRoleBase64(reply.InvocationBase64URL, stage2aExecMaxFrame/2)
	if err != nil || stage2aReservationSHA256(invocationRaw) != grant.InvocationSHA256 ||
		stage2aDecodeExact(invocationRaw, &empty) != nil {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	canonical, err := marshalStage2aReservationJCS(empty)
	if err != nil || !bytes.Equal(canonical, invocationRaw) ||
		empty.MemberID != grant.MemberID ||
		empty.MemberLaunchID != grant.MemberLaunchID ||
		empty.MemberSelector != grant.MemberSelector ||
		empty.SandboxPath != SoulChildSandbox ||
		empty.SandboxSHA256 != "sha256:"+harnessSHA(soulChildProfile) ||
		empty.Runner.InstallationID != grant.InstallationID ||
		empty.Runner.UID != os.Getuid() || empty.Runner.GID != os.Getgid() ||
		os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() ||
		os.Getenv("SUDO_USER") != DarwinHQAccount {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	reservation, bridge, assignment, member, rSHA, bSHA, aSHA, recordsUntil,
		err := verifyStage2aCooperativeChildSelectionFromInvocation(empty, pub, now)
	if err != nil || rSHA != grant.ReservationSHA256 ||
		bSHA != grant.BridgeAssignmentSHA256 || aSHA != grant.AssignmentEnvelopeSHA256 ||
		reservation.Assignment.InstallationID != grant.InstallationID ||
		reservation.Assignment.StartID != grant.StartID ||
		reservation.Assignment.HQEpoch != grant.HQEpoch ||
		reservation.MeasurementBinding.RInventory != empty.RuntimeV3 ||
		assignment.RunnerUID != empty.Runner.UID ||
		assignment.RunnerGID != empty.Runner.GID ||
		member.CommandPath != empty.Executable ||
		member.CommandSHA256 != empty.ExecutableSHA256 ||
		bridge.Endpoints.Relay.SocketPath != empty.RelaySocket ||
		empty.Launch.EffectiveConfig["profile"] != "managed-cooperative" ||
		!stage2aSystemImageSelected(empty.Launch, "/usr/bin/sandbox-exec") ||
		until.After(recordsUntil) {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	memberAuthorityEnvelope, err := decodeStage2aRoleBase64(
		empty.MemberBAuthorityEnvelopeBase64URL, 16<<10)
	if err != nil {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	memberAuthoritySHA, memberAuthorityExpiry, err := verifyStage2aCooperativeBAuthority(
		memberAuthorityEnvelope, reservation, bridge, assignment,
		rSHA, bSHA, aSHA, pub, now)
	if err != nil || memberAuthoritySHA != grant.MemberBAuthoritySHA256 ||
		until.After(memberAuthorityExpiry) {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	start := SoulStartAssignment{InstallationID: grant.InstallationID,
		StartID: grant.StartID, RunnerUID: empty.Runner.UID, RunnerGID: empty.Runner.GID}
	start.Relay.SocketPath = empty.RelaySocket
	workdir, env, err := stage2aMemberChildEnvironment(empty.Runner, start,
		empty.Launch, empty.MemberSelector)
	if err != nil || workdir != empty.Workdir || !reflect.DeepEqual(env, empty.Environment) ||
		os.Getenv("SUDO_UID") == "" {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	hqUID, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || hqUID != reservation.Assignment.HQUID {
		return stage2aCooperativeChildInvocation{}, grant, "", invalid
	}
	return empty, grant, reply.SHA256, nil
}

func verifyStage2aCooperativeChildSelectionFromInvocation(in stage2aCooperativeChildInvocation,
	pub ed25519.PublicKey, now time.Time) (soulCooperativeBReservationViewV3,
	soulCooperativeBridgeAssignmentPayloadV3, soulCooperativeMemberSetAssignmentV3,
	stage2aAssignedMember, string, string, string, time.Time, error) {
	r, e1 := decodeStage2aRoleBase64(in.ReservationEnvelopeBase64URL, 64<<10)
	b, e2 := decodeStage2aRoleBase64(in.BridgeEnvelopeBase64URL, 64<<10)
	a, e3 := decodeStage2aRoleBase64(in.AssignmentEnvelopeBase64URL, 16<<10)
	if e1 != nil || e2 != nil || e3 != nil {
		return soulCooperativeBReservationViewV3{}, soulCooperativeBridgeAssignmentPayloadV3{},
			soulCooperativeMemberSetAssignmentV3{}, stage2aAssignedMember{}, "", "", "",
			time.Time{}, errSoulCooperativeAuthority
	}
	return verifyStage2aCooperativeChildSelection(r, b, a, in.MemberID,
		in.MemberLaunchID, in.MemberSelector, pub, now)
}

func verifyStage2aCooperativeReadyLease(readyEnvelope, leaseEnvelope []byte,
	in stage2aCooperativeChildInvocation, grant stage2aCooperativeChildGrant,
	grantSHA string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, challenge string, priorSequence uint64, now time.Time) (string,
	stage2aCooperativeLeasePayload, error) {
	var lease stage2aCooperativeLeasePayload
	fail := func() (string, stage2aCooperativeLeasePayload, error) {
		return "", stage2aCooperativeLeasePayload{}, errSoulCooperativeAuthority
	}
	readyRaw, err := verifyStage2aStoredARecordV3(readyEnvelope,
		stage2aCooperativeReadyPurpose, 3, pub)
	var ready stage2aCooperativeReadyPayload
	if err != nil || stage2aDecodeExact(readyRaw, &ready) != nil ||
		ready.Contract != "machine/v3" || ready.Kind != "soul-cooperative-member-ready" ||
		ready.SchemaVersion != 3 || ready.ProfileInForce != "managed-cooperative" ||
		ready.InstallationID != grant.InstallationID || ready.StartID != grant.StartID ||
		ready.HQEpoch != grant.HQEpoch ||
		ready.ReservationSHA256 != grant.ReservationSHA256 ||
		ready.AssignmentEnvelopeSHA256 != grant.AssignmentEnvelopeSHA256 ||
		ready.Members[0].MemberID != "m_lead" ||
		ready.Members[1].MemberID != "m_spec" ||
		ready.Members[0].MemberSelector == ready.Members[1].MemberSelector ||
		ready.Members[0].LauncherProcess.PID == ready.Members[1].LauncherProcess.PID ||
		ready.Members[0].ChildProcess.PID == ready.Members[1].ChildProcess.PID ||
		ready.Members[0].HObservationSHA256 == ready.Members[1].HObservationSHA256 ||
		ready.Members[0].BArmReceiptSHA256 == ready.Members[1].BArmReceiptSHA256 {
		return fail()
	}
	reservation, _, assignment, _, _, _, _, _, err :=
		verifyStage2aCooperativeChildSelectionFromInvocation(in, pub, now)
	if err != nil || ready.HostID != reservation.HostID ||
		ready.Members[0].MemberID != assignment.Members[0].MemberID ||
		ready.Members[1].MemberID != assignment.Members[1].MemberID {
		return fail()
	}
	selected := -1
	for i, member := range ready.Members {
		if !validStage2aExecDigest(member.GrantSHA256) ||
			!validStage2aExecDigest(member.HObservationSHA256) ||
			!validStage2aExecDigest(member.BArmReceiptSHA256) ||
			member.MemberLaunchID != assignment.Members[i].LaunchID ||
			member.MemberSelector != assignment.Members[i].MemberSelector ||
			member.MemberSelector != stage2aMemberSelector(grant.ReservationSHA256,
				member.MemberID, member.MemberLaunchID) {
			return fail()
		}
		if member.MemberID == grant.MemberID {
			selected = i
		}
	}
	if selected < 0 || ready.Members[selected].MemberLaunchID != grant.MemberLaunchID ||
		ready.Members[selected].MemberSelector != grant.MemberSelector ||
		ready.Members[selected].GrantSHA256 != grantSHA ||
		ready.Members[selected].LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
		ready.Members[selected].ChildProcess != stage2aMemberProcessIdentity(child, in.ExecutableSHA256) {
		return fail()
	}
	readyIssued, e1 := time.Parse(time.RFC3339Nano, ready.IssuedAt)
	readyExpires, e2 := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	if e1 != nil || e2 != nil || readyIssued.After(now) ||
		!now.Before(readyExpires) || !readyExpires.After(readyIssued) ||
		readyExpires.Sub(readyIssued) > stage2aMemberChildGrantLife {
		return fail()
	}
	readySHA := stage2aReservationSHA256(readyEnvelope)
	leaseRaw, err := verifyStage2aStoredARecordV3(leaseEnvelope,
		stage2aCooperativeLeasePurpose, 3, pub)
	if err != nil || stage2aDecodeExact(leaseRaw, &lease) != nil ||
		lease.Contract != "machine/v3" || lease.Kind != "soul-cooperative-member-live-lease" ||
		lease.SchemaVersion != 3 || lease.ProfileInForce != "managed-cooperative" ||
		lease.ReservationSHA256 != grant.ReservationSHA256 ||
		lease.AssignmentEnvelopeSHA256 != grant.AssignmentEnvelopeSHA256 ||
		lease.ReadyEnvelopeSHA256 != readySHA || lease.MemberID != grant.MemberID ||
		lease.MemberLaunchID != grant.MemberLaunchID ||
		lease.MemberSelector != grant.MemberSelector || lease.GrantSHA256 != grantSHA ||
		lease.LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
		lease.ChildProcess != stage2aMemberProcessIdentity(child, in.ExecutableSHA256) ||
		lease.ChallengeNonceBase64URL != challenge ||
		lease.Sequence != priorSequence+1 {
		return fail()
	}
	issued, e3 := time.Parse(time.RFC3339Nano, lease.IssuedAt)
	expires, e4 := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	if e3 != nil || e4 != nil || issued.After(now) || !now.Before(expires) ||
		!expires.After(issued) || expires.Sub(issued) > stage2aLiveLease ||
		expires.After(readyExpires) || expires.After(timeMustParse(grant.ExpiresAt)) {
		return fail()
	}
	return readySHA, lease, nil
}

func timeMustParse(value string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, value)
	return t
}

func runStage2aCooperativeChild(ctx context.Context, frame []byte,
	challenge stage2aExecChallenge, pub ed25519.PublicKey,
	acp *bufio.Reader, control, stdout, status *os.File) int {
	in, grant, grantSHA, err := verifyStage2aCooperativeChildGrant(frame, challenge, pub, time.Now())
	if err != nil {
		return harnessRefused
	}
	gate, err := stage2aCooperativeAdmissionGate(in, grant, grantSHA, pub)
	if err != nil {
		return harnessRefused
	}
	return runStage2aCooperativeChildVerified(ctx, in, grant, grantSHA, pub,
		acp, control, stdout, status, gate)
}

func runStage2aCooperativeChildVerified(ctx context.Context,
	in stage2aCooperativeChildInvocation, grant stage2aCooperativeChildGrant,
	grantSHA string, pub ed25519.PublicKey, acp *bufio.Reader, control, stdout, status *os.File,
	gate stage2aCooperativeChildGate) int {
	if gate.Await == nil || gate.Renew == nil ||
		in.SandboxPath != SoulChildSandbox ||
		in.SandboxSHA256 != "sha256:"+harnessSHA(soulChildProfile) ||
		in.Runner.UID != os.Getuid() || in.Runner.GID != os.Getgid() ||
		os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() ||
		!time.Now().Before(timeMustParse(grant.ExpiresAt)) ||
		trustedPath(OSHost{}, SoulChildSandbox, false) != nil ||
		checkDarwinACLs(pathAncestry(SoulChildSandbox)) != nil {
		return harnessRefused
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return harnessRefused
	}
	inventory, err := stage2aCheckChildCodeV3(in.RuntimeV3, in.Executable, in.ExecutableSHA256)
	if err != nil || stage2aAdapterChildEnvV3(in.Launch, nil, in.RuntimeV3, inventory) != nil ||
		in.Launch.ComponentDigests["adapter"] != in.ExecutableSHA256 {
		return harnessRefused
	}
	start := SoulStartAssignment{InstallationID: grant.InstallationID,
		StartID: grant.StartID, RunnerUID: in.Runner.UID, RunnerGID: in.Runner.GID}
	start.Relay.SocketPath = in.RelaySocket
	workdir, env, err := stage2aMemberChildEnvironment(in.Runner, start,
		in.Launch, grant.MemberSelector)
	if err != nil || workdir != in.Workdir || !reflect.DeepEqual(env, in.Environment) ||
		stage2aCreateMemberChildState(in.Runner, start, grant.MemberSelector) != nil {
		return harnessRefused
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-D", "RELAY_SOCKET="+in.RelaySocket,
		"-f", SoulChildSandbox, in.Executable)
	cmd.Dir = workdir
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	slices.Sort(cmd.Env)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reporter := &harnessReporter{output: status}
	var leaseExpires atomic.Int64
	onStart := func(pid int) error {
		deadline := timeMustParse(grant.ExpiresAt)
		var child, launcher soulKernelProcessSnapshot
		for time.Now().Before(deadline) {
			child, err = observeStage2aChildProcess(pid, os.Getpid(), in.Runner, in.Launch)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		launcher, launcherErr := observeStage2aRoleProcess(os.Getpid(), in.Runner.UID,
			in.Runner.GID, "child")
		if err != nil || launcherErr != nil ||
			reporter.write(struct {
				Kind             string                               `json:"kind"`
				ChildPID         int                                  `json:"child_pid"`
				ChildLauncherPID int                                  `json:"child_launcher_pid"`
				GrantSHA256      string                               `json:"grant_sha256"`
				ChildProcess     stage2aMemberObservedProcess         `json:"child_process"`
				LauncherProcess  stage2aMemberObservedLauncherProcess `json:"launcher_process"`
			}{"child-started", pid, os.Getpid(), grantSHA,
				stage2aMemberProcessIdentity(child, in.ExecutableSHA256),
				stage2aMemberLauncherIdentity(launcher)}) != nil {
			return errors.New("cooperative stock child could not be observed")
		}
		challenge, err := stage2aCooperativeFreshNonce()
		if err != nil {
			return errSoulCooperativeAuthority
		}
		readyRaw, leaseRaw, err := awaitStage2aCooperativeGate(childCtx, deadline,
			gate.Await, stage2aMemberLauncherIdentity(launcher),
			stage2aMemberProcessIdentity(child, in.ExecutableSHA256), grantSHA, challenge)
		if err != nil || !time.Now().Before(deadline) {
			return errSoulCooperativeAuthority
		}
		readySHA, first, err := verifyStage2aCooperativeReadyLease(readyRaw, leaseRaw,
			in, grant, grantSHA, launcher, child, pub, challenge, 0, time.Now())
		if err != nil {
			return err
		}
		firstExpiry := timeMustParse(first.ExpiresAt)
		if time.Until(firstExpiry) <= time.Second {
			return errSoulCooperativeAuthority
		}
		leaseExpires.Store(firstExpiry.UnixMilli())
		go watchStage2aCooperativeChildLive(childCtx, cancel, readyRaw, readySHA,
			first, in, grant, grantSHA, launcher, child, pub, &leaseExpires, gate.Renew)
		if reporter.write(struct {
			Kind          string `json:"kind"`
			ReadySHA256   string `json:"ready_sha256"`
			LeaseSequence uint64 `json:"lease_sequence"`
		}{"child-accepted", readySHA, first.Sequence}) != nil {
			return errSoulCooperativeAuthority
		}
		if time.Until(time.UnixMilli(leaseExpires.Load())) <= time.Second {
			return errSoulCooperativeAuthority
		}
		return nil
	}
	return superviseHarnessStarted(childCtx, cmd,
		stage2aCooperativeLeasedReader{input: acp, expires: &leaseExpires}, control, stdout,
		reporter, time.Second, onStart)
}

func awaitStage2aCooperativeGate(ctx context.Context, deadline time.Time,
	request func(stage2aMemberObservedLauncherProcess, stage2aMemberObservedProcess,
		string, string, time.Time) ([]byte, []byte, error),
	launcher stage2aMemberObservedLauncherProcess, child stage2aMemberObservedProcess,
	grantSHA, challenge string) ([]byte, []byte, error) {
	type result struct {
		ready []byte
		lease []byte
		err   error
	}
	if request == nil || !time.Now().Before(deadline) {
		return nil, nil, errSoulCooperativeAuthority
	}
	channel := make(chan result, 1)
	go func() {
		ready, lease, err := request(launcher, child, grantSHA, challenge, deadline)
		channel <- result{ready, lease, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, nil, errSoulCooperativeAuthority
	case <-timer.C:
		return nil, nil, errSoulCooperativeAuthority
	case reply := <-channel:
		if reply.err != nil || !time.Now().Before(deadline) {
			return nil, nil, errSoulCooperativeAuthority
		}
		return reply.ready, reply.lease, nil
	}
}

func watchStage2aCooperativeChildLive(ctx context.Context, cancel context.CancelFunc,
	readyRaw []byte, readySHA string, first stage2aCooperativeLeasePayload,
	in stage2aCooperativeChildInvocation, grant stage2aCooperativeChildGrant,
	grantSHA string, launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	leaseExpires *atomic.Int64,
	renew func(string, string, uint64, time.Time) ([]byte, error)) {
	last := first
	for {
		expires := timeMustParse(last.ExpiresAt)
		remaining := time.Until(expires)
		if remaining <= 0 {
			cancel()
			return
		}
		timer := time.AfterFunc(remaining, cancel)
		wait := remaining - 2*time.Second
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-time.After(wait):
		}
		challenge, err := stage2aCooperativeFreshNonce()
		if err != nil {
			timer.Stop()
			cancel()
			return
		}
		leaseRaw, err := renew(readySHA, challenge, last.Sequence, expires)
		if ctx.Err() != nil || !time.Now().Before(expires) || err != nil {
			timer.Stop()
			cancel()
			return
		}
		_, next, err := verifyStage2aCooperativeReadyLease(readyRaw, leaseRaw,
			in, grant, grantSHA, launcher, child, pub, challenge, last.Sequence, time.Now())
		if err != nil || !timer.Stop() || ctx.Err() != nil || !time.Now().Before(expires) {
			cancel()
			return
		}
		leaseExpires.Store(timeMustParse(next.ExpiresAt).UnixMilli())
		last = next
	}
}
