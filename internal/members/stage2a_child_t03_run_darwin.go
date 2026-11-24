//go:build darwin

package members

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aT03OutputLimit = 64 << 10

type stage2aT03BoundedOutput struct {
	hash   hash.Hash
	bytes  int
	prefix []byte
}

func (w *stage2aT03BoundedOutput) Write(p []byte) (int, error) {
	if w.hash == nil {
		w.hash = sha256.New()
	}
	_, _ = w.hash.Write(p)
	w.bytes += len(p)
	if len(w.prefix) < 4096 {
		n := min(len(p), 4096-len(w.prefix))
		w.prefix = append(w.prefix, p[:n]...)
	}
	return len(p), nil
}

func (w *stage2aT03BoundedOutput) digest() string {
	if w.hash == nil {
		return "sha256:" + harnessSHA(nil)
	}
	return "sha256:" + hex.EncodeToString(w.hash.Sum(nil))
}

type stage2aT03ProbeCoordinator struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	in            Stage2aRoleInvocation
	receiptSHA256 string
	reporter      *harnessReporter
	directive     *Stage2aT03ProbeDirective
	prompt        []byte
	ready         *Stage2aT03ProbeReady
	goCh          chan Stage2aT03ProbeGo
	done          chan struct{}
	probeFailed   bool
}

func newStage2aT03ProbeCoordinator(ctx context.Context, cancel context.CancelFunc,
	in Stage2aRoleInvocation, receiptSHA256 string, reporter *harnessReporter) *stage2aT03ProbeCoordinator {
	return &stage2aT03ProbeCoordinator{ctx: ctx, cancel: cancel, in: in,
		receiptSHA256: receiptSHA256, reporter: reporter,
		goCh: make(chan Stage2aT03ProbeGo, 1), done: make(chan struct{})}
}

// Each directive and go arrives only inside a Machine-signed, independently
// checked child Live lease. The stock ACP child keeps renewing while this
// worker waits for A to observe the staged second CLI before sending input.
func (c *stage2aT03ProbeCoordinator) onLease(lease Stage2aLiveLeasePayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil || time.Now().UnixMilli() >= lease.ExpiresAtMS {
		return errStage2aReservationAuthority
	}
	if lease.T03SiblingCredentialProbe != nil {
		if lease.T03Probe != nil || lease.T03ProbeGo != nil || c.directive != nil ||
			!validStage2aT03SiblingCredentialProbe(*lease.T03SiblingCredentialProbe, lease,
				c.in, c.receiptSHA256) {
			return errStage2aReservationAuthority
		}
		probe := *lease.T03SiblingCredentialProbe
		go c.reportSiblingCredential(probe)
	}
	if lease.T03Probe != nil {
		if c.directive != nil || c.in.ChildExec == nil || c.in.ChildExec.RuntimeV3 == nil {
			return errStage2aReservationAuthority
		}
		inventory, err := stage2aCheckChildCodeV3(*c.in.ChildExec.RuntimeV3,
			c.in.ChildExec.Executable, c.in.ChildExec.ExecutableSHA256)
		if err != nil {
			return errStage2aReservationAuthority
		}
		_, cliSHA, err := stage2aT03PinnedCLI(c.in, inventory)
		if err != nil {
			return errStage2aReservationAuthority
		}
		prompt, err := validateStage2aT03ProbeDirective(lease.T03Probe, lease,
			c.in, c.receiptSHA256, cliSHA, time.Now())
		if err != nil || c.ctx.Err() != nil || time.Now().UnixMilli() >= lease.ExpiresAtMS {
			return errStage2aReservationAuthority
		}
		d := *lease.T03Probe
		c.directive, c.prompt = &d, prompt
		go c.run()
	}
	if lease.T03ProbeGo != nil {
		g := *lease.T03ProbeGo
		r := c.ready
		if r == nil || c.directive == nil || c.ctx.Err() != nil ||
			g.ChallengeBase64URL != c.directive.ChallengeBase64URL ||
			g.ChildReceiptSHA256 != c.receiptSHA256 ||
			g.ProbeLeaseSequence != c.directive.LeaseSequence ||
			g.GoLeaseSequence != lease.Sequence || g.Kind != r.Kind || g.PID != r.PID ||
			g.StartSeconds != r.StartSeconds || g.StartMicros != r.StartMicros ||
			time.Now().UnixMilli() >= c.directive.ExpiresAtMS {
			return errStage2aReservationAuthority
		}
		c.ready = nil
		select {
		case c.goCh <- g:
		default:
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func validStage2aT03SiblingCredentialProbe(p Stage2aT03SiblingCredentialProbe,
	lease Stage2aLiveLeasePayload, in Stage2aRoleInvocation, childReceipt string) bool {
	if in.ChildExec == nil || p.Schema != "agent-bot-machine/stage2a-t03-sibling-credential-probe/v1" ||
		!validStage2aLiveChallenge(p.ChallengeBase64URL) ||
		!stage2aPrefixedDigest.MatchString(p.PrimaryReservationSHA256) ||
		p.SiblingReservationSHA256 != in.ChildExec.ReservationSHA256 ||
		p.SiblingInstallationID != in.Request.InstallationID || p.SiblingStartID != in.Request.StartID ||
		p.ChildReceiptSHA256 != childReceipt || lease.ChildReceiptSHA256 != childReceipt ||
		p.LeaseSequence != lease.Sequence || p.ExpiresAtMS != lease.ExpiresAtMS ||
		!stage2aAbsolutePath(p.CredentialPath) {
		return false
	}
	childState := filepath.Dir(in.ChildExec.Workdir)
	return strings.HasPrefix(p.CredentialPath, childState+"/") && len(p.CredentialPath) <= 512
}

func (c *stage2aT03ProbeCoordinator) reportSiblingCredential(p Stage2aT03SiblingCredentialProbe) {
	if c.ctx.Err() != nil || time.Now().UnixMilli() >= p.ExpiresAtMS {
		c.cancel()
		return
	}
	meta, digest, err := observeStage2aT03Credential(darwinSoulRunnerHome(c.in.Runner.Account),
		p.CredentialPath, uint32(c.in.Runner.UID), uint32(c.in.Runner.GID))
	if err != nil || c.ctx.Err() != nil || time.Now().UnixMilli() >= p.ExpiresAtMS {
		c.cancel()
		return
	}
	witness := Stage2aT03SiblingCredentialWitness{
		Schema:                   "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1",
		ChallengeBase64URL:       p.ChallengeBase64URL,
		PrimaryReservationSHA256: p.PrimaryReservationSHA256,
		SiblingReservationSHA256: p.SiblingReservationSHA256,
		SiblingInstallationID:    p.SiblingInstallationID, SiblingStartID: p.SiblingStartID,
		ChildReceiptSHA256: p.ChildReceiptSHA256, LeaseSequence: p.LeaseSequence,
		CredentialPath: p.CredentialPath, Metadata: meta, MetadataSHA256: digest,
		ObservedAtMS: time.Now().UnixMilli(),
	}
	if sendStage2aT03DirectChildWitness(c.in, p.ExpiresAtMS,
		Stage2aT03SiblingCredentialWitnessRequest{Stage2aStopRequest: stage2aT03ChildStopSelectors(c.in), Witness: witness}) != nil {
		c.cancel()
		return
	}
	if c.reporter.write(struct {
		Kind    string                             `json:"kind"`
		Witness Stage2aT03SiblingCredentialWitness `json:"witness"`
	}{"t03-sibling-credential-witness", witness}) != nil {
		c.cancel()
	}
}

func (c *stage2aT03ProbeCoordinator) stopped(timeout time.Duration) bool {
	c.mu.Lock()
	started := c.directive != nil
	c.mu.Unlock()
	if !started {
		return true
	}
	select {
	case <-c.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (c *stage2aT03ProbeCoordinator) failed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probeFailed
}

func (c *stage2aT03ProbeCoordinator) run() {
	defer close(c.done)
	succeeded := false
	defer func() {
		if !succeeded {
			c.mu.Lock()
			c.probeFailed = true
			c.mu.Unlock()
			c.cancel()
		}
	}()
	d := c.directive
	if d == nil {
		c.cancel()
		return
	}
	cli := filepath.Join(filepath.Dir(c.in.ChildExec.Executable), "claude")
	result := Stage2aT03ProbeResult{
		Schema:             "agent-bot-machine/stage2a-t03-probe-result/v1",
		ChallengeBase64URL: d.ChallengeBase64URL, SessionID: d.SessionID,
		TestPlanSHA256: d.TestPlanSHA256, ReservationSHA256: d.ReservationSHA256,
		InstallationID: d.InstallationID, StartID: d.StartID,
		ChildReceiptSHA256: d.ChildReceiptSHA256, LeaseSequence: d.LeaseSequence,
		CLIExecutable: cli, CLIExecutableSHA256: d.CLIExecutableSHA256,
		SandboxSHA256: c.in.ChildExec.SandboxSHA256,
		Attempts:      make([]Stage2aT03ProbeAttempt, 0, 3),
	}
	for _, spec := range []struct{ kind, url, sibling, target string }{
		{"ipv4", d.ProviderIPv4URL, "", d.ProviderIPv4URL},
		{"ipv6", d.ProviderIPv6URL, "", d.ProviderIPv6URL},
		{"sibling", d.ProviderIPv4URL, d.SiblingSocket, d.SiblingSocket},
	} {
		attempt, err := c.runAttempt(*d, spec.kind, spec.url, spec.sibling, spec.target)
		if err != nil {
			c.cancel()
			return
		}
		result.Attempts = append(result.Attempts, attempt)
	}
	if c.ctx.Err() != nil || os.Getuid() != c.in.Runner.UID || os.Geteuid() != c.in.Runner.UID ||
		time.Now().UnixMilli() >= d.ExpiresAtMS {
		c.cancel()
		return
	}
	result.CredentialPath = d.SiblingCredentialPath
	result.CredentialAttemptedAtMS = time.Now().UnixMilli()
	fd, err := unix.Open(d.SiblingCredentialPath,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		c.cancel()
		return
	}
	switch {
	case errors.Is(err, unix.EACCES):
		result.CredentialDenialErrno = "EACCES"
	case errors.Is(err, unix.EPERM):
		result.CredentialDenialErrno = "EPERM"
	default:
		c.cancel()
		return
	}
	if c.ctx.Err() != nil || c.reporter.write(struct {
		Kind   string                `json:"kind"`
		Result Stage2aT03ProbeResult `json:"result"`
	}{"t03-probe-result", result}) != nil {
		return
	}
	succeeded = true
}

func (c *stage2aT03ProbeCoordinator) runAttempt(d Stage2aT03ProbeDirective,
	kind, providerURL, siblingSocket, target string) (Stage2aT03ProbeAttempt, error) {
	var empty Stage2aT03ProbeAttempt
	if c.ctx.Err() != nil || time.Now().UnixMilli() >= d.ExpiresAtMS {
		return empty, errStage2aReservationAuthority
	}
	inventory, err := stage2aCheckChildCodeV3(*c.in.ChildExec.RuntimeV3,
		c.in.ChildExec.Executable, c.in.ChildExec.ExecutableSHA256)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	cli, cliSHA, err := stage2aT03PinnedCLI(c.in, inventory)
	if err != nil || cliSHA != d.CLIExecutableSHA256 {
		return empty, errStage2aReservationAuthority
	}
	profile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || profile.Close() != nil {
		return empty, errStage2aReservationAuthority
	}
	deadline := time.UnixMilli(d.ExpiresAtMS)
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()
	cmd, err := stage2aT03ProbeCommand(ctx, c.in, providerURL, c.prompt, siblingSocket)
	if err != nil {
		return empty, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return empty, err
	}
	stdout, stderr := &stage2aT03BoundedOutput{}, &stage2aT03BoundedOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return empty, err
	}
	pid := cmd.Process.Pid
	reaped := false
	defer func() {
		_ = stdin.Close()
		if !reaped {
			_ = closeHarnessGroup(pid, time.Second)
			_ = cmd.Wait()
		}
	}()
	var observed soulProcessObservation
	expectedArgv := stage2aT03CLIArguments(cli, c.in.ChildExec.Environment["ANTHROPIC_MODEL"])
	for until := time.Now().Add(500 * time.Millisecond); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
		observed, err = observeSoulProcess(pid, cli, expectedArgv)
		if err == nil {
			break
		}
	}
	if err != nil || observed.Kernel.ParentPID != os.Getpid() ||
		observed.Kernel.EffectiveUID != uint32(c.in.Runner.UID) ||
		observed.Kernel.PrimaryGroupGID != uint32(c.in.Runner.GID) {
		return empty, errStage2aReservationAuthority
	}
	argvRaw, err := marshalStage2aReservationJCS(expectedArgv)
	if err != nil {
		return empty, err
	}
	envRaw, err := marshalStage2aReservationJCS(cmd.Env)
	if err != nil {
		return empty, err
	}
	ready := Stage2aT03ProbeReady{
		Schema:             "agent-bot-machine/stage2a-t03-probe-ready/v1",
		ChallengeBase64URL: d.ChallengeBase64URL, SessionID: d.SessionID,
		ReservationSHA256: d.ReservationSHA256, InstallationID: d.InstallationID,
		StartID: d.StartID, ChildReceiptSHA256: d.ChildReceiptSHA256,
		ProbeLeaseSequence: d.LeaseSequence, Kind: kind, Target: target,
		PID: pid, UID: observed.Kernel.EffectiveUID, GID: observed.Kernel.PrimaryGroupGID,
		StartSeconds: observed.Kernel.StartSeconds, StartMicros: observed.Kernel.StartMicros,
		CLIExecutable: cli, CLIExecutableSHA256: cliSHA,
		ArgvSHA256: stage2aReservationSHA256(argvRaw), EnvSHA256: stage2aReservationSHA256(envRaw),
		SandboxSHA256: c.in.ChildExec.SandboxSHA256,
	}
	c.mu.Lock()
	c.ready = &ready
	c.mu.Unlock()
	if err := c.reporter.write(struct {
		Kind  string               `json:"kind"`
		Ready Stage2aT03ProbeReady `json:"ready"`
	}{"t03-probe-ready", ready}); err != nil {
		return empty, err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return empty, errStage2aReservationAuthority
		case <-ticker.C:
			leader, _, e := harnessGroupState(pid)
			if e != nil || leader {
				return empty, errStage2aReservationAuthority
			}
		case <-c.goCh:
			goto released
		}
	}
released:
	if _, err := stdin.Write(append(append([]byte{}, c.prompt...), '\n')); err != nil {
		return empty, err
	}
	if err := stdin.Close(); err != nil {
		return empty, err
	}
	for {
		leader, _, e := harnessGroupState(pid)
		if e == nil && leader {
			break
		}
		select {
		case <-ctx.Done():
			return empty, errStage2aReservationAuthority
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !closeHarnessGroup(pid, time.Second) {
		return empty, errStage2aReservationAuthority
	}
	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return empty, errStage2aReservationAuthority
		}
	}
	reaped = true
	denial, targetSeen, class := stage2aT03ClassifyDenial(kind, target, stdout.prefix, stderr.prefix)
	return Stage2aT03ProbeAttempt{
		Kind: kind, Target: target, PID: ready.PID, UID: ready.UID, GID: ready.GID,
		StartSeconds: ready.StartSeconds, StartMicros: ready.StartMicros,
		ArgvSHA256: ready.ArgvSHA256, EnvSHA256: ready.EnvSHA256,
		ExitCode: cmd.ProcessState.ExitCode(), StdoutSHA256: stdout.digest(), StderrSHA256: stderr.digest(),
		StdoutBytes: stdout.bytes, StderrBytes: stderr.bytes,
		OutputCapped: stdout.bytes > stage2aT03OutputLimit || stderr.bytes > stage2aT03OutputLimit,
		DenialErrno:  denial, DenialTargetObserved: targetSeen, ErrorClass: class,
		StartedAtMS: started.UnixMilli(), FinishedAtMS: time.Now().UnixMilli(),
	}, nil
}

func stage2aT03ClassifyDenial(kind, target string, stdout, stderr []byte) (string, bool, string) {
	// One bounded output line is one denial record. A target printed elsewhere
	// (including the other stream) cannot corroborate an unrelated error.
	want := strings.ToLower(target)
	for _, stream := range [][]byte{stdout, stderr} {
		for _, raw := range strings.Split(string(stream), "\n") {
			line := strings.ToLower(strings.TrimSuffix(raw, "\r"))
			if !strings.Contains(line, want) || !strings.Contains(line, "connect") {
				continue
			}
			perm := strings.Contains(line, "eperm") || strings.Contains(line, "operation not permitted")
			access := strings.Contains(line, "eacces") || strings.Contains(line, "permission denied")
			if perm == access { // no errno, or ambiguous errno
				continue
			}
			if perm {
				return "EPERM", true, "connect_denied"
			}
			return "EACCES", true, "connect_denied"
		}
	}
	return "", false, "unclassified"
}
