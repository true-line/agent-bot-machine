package members

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	harnessClosed      = 0
	harnessUncontained = 70
	harnessRefused     = 78
)

type harnessReporter struct {
	mu     sync.Mutex
	output io.Writer
}

func (r *harnessReporter) write(record any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.NewEncoder(r.output).Encode(record)
}

// Keep stderr from the adapter distinct from the supervisor's lifecycle
// messages. A missing lifecycle receipt cannot be replaced by adapter output.
func (r *harnessReporter) relay(input *os.File) {
	buf := make([]byte, 512)
	for {
		n, err := input.Read(buf)
		if n > 0 {
			record := struct {
				Kind string `json:"kind"`
				Text string `json:"text"`
			}{"stderr", string(buf[:n])}
			if r.write(record) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Darwin sys/proc.h defines SZOMB as 5. Keep the direct child waitable while
// looking up and signalling its group. Its unreaped PID reserves that number.
func harnessGroupState(pid int) (leaderExited, groupExited bool, err error) {
	list, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pid)
	if err != nil {
		return false, false, err
	}
	found, live := false, false
	for _, proc := range list {
		if int(proc.Eproc.Pgid) != pid {
			return false, false, errors.New("unexpected process group")
		}
		if proc.Proc.P_stat != 5 {
			live = true
		}
		if int(proc.Proc.P_pid) == pid {
			found = true
			leaderExited = proc.Proc.P_stat == 5
		}
	}
	if !found {
		// Darwin can omit zombies from a process-group query. Inspect our
		// unreaped child directly before treating an empty group as closed.
		child, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if e != nil || int(child.Proc.P_pid) != pid || child.Proc.P_stat != 5 {
			return false, false, errors.New("launch leader status is unknown")
		}
		leaderExited = true
	}
	return leaderExited, !live && leaderExited, nil
}

func awaitHarnessGroup(pid int, deadline time.Time) bool {
	for {
		_, closed, err := harnessGroupState(pid)
		if err == nil && closed {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func closeHarnessGroup(pid int, grace time.Duration) bool {
	return stopHarnessGroup(pid, grace, unix.Kill, awaitHarnessGroup)
}

func stopHarnessGroup(pid int, grace time.Duration, signal func(int, unix.Signal) error, await func(int, time.Time) bool) bool {
	for _, stage := range []struct {
		sig  unix.Signal
		wait time.Duration
	}{{unix.SIGTERM, grace}, {unix.SIGKILL, 3 * time.Second}} {
		err := signal(-pid, stage.sig)
		if err != nil && err != unix.ESRCH && err != unix.EPERM {
			return false
		}
		// Darwin can return EPERM while the last process is exiting on EOF.
		// Only an independent check of this unreaped child's exact group
		// confirms closure. A live or uninspectable group remains uncontained.
		if await(pid, time.Now().Add(stage.wait)) {
			return true
		}
		if err == unix.EPERM {
			return false
		}
	}
	return false
}

// The process group belongs to this one launch. It is a separate session so
// its group cannot coincide with sudo, HQ or another launch. The caller must
// retain the shared grant lock until this function finishes.
func superviseHarness(ctx context.Context, cmd *exec.Cmd, acp io.Reader, control *os.File, stdout *os.File, reporter *harnessReporter, grace time.Duration) int {
	return superviseHarnessStarted(ctx, cmd, acp, control, stdout, reporter, grace, nil)
}

// onStart runs while the direct child remains unreaped and before any ACP
// bytes are copied to it. A protected child waits here for A's signed
// child-start receipt; refusal closes the entire process group.
func superviseHarnessStarted(ctx context.Context, cmd *exec.Cmd, acp io.Reader, control *os.File,
	stdout *os.File, reporter *harnessReporter, grace time.Duration, onStart func(int) error) int {
	read, write, err := os.Pipe()
	if err != nil {
		return harnessRefused
	}
	defer read.Close()
	defer write.Close()
	logRead, logWrite, err := os.Pipe()
	if err != nil {
		return harnessRefused
	}
	defer logRead.Close()
	defer logWrite.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = read, stdout, logWrite
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if cmd.Start() != nil {
		return harnessRefused
	}
	pid := cmd.Process.Pid
	read.Close()
	logWrite.Close()
	// The group leader is our live or unreaped direct child from here. Never
	// start Wait in parallel with a possible signal to this process group.
	ready := onStart == nil
	if onStart != nil {
		ready = onStart(pid) == nil
	}
	ready = ready && reporter.write(struct {
		Kind string `json:"kind"`
	}{"started"}) == nil
	logDone := make(chan struct{})
	go func() { reporter.relay(logRead); close(logDone) }()
	inputDone := make(chan struct{})
	if ready {
		go func() { _, _ = io.Copy(write, acp); write.Close(); close(inputDone) }()
	} else {
		// A rejected child receipt or Live lease must not consume or forward
		// buffered ACP bytes while the process group is being closed.
		write.Close()
		close(inputDone)
	}
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
monitor:
	for ready {
		select {
		case <-ctx.Done():
			break monitor
		case <-inputDone:
			break monitor
		case <-tick.C:
			leader, _, err := harnessGroupState(pid)
			if err != nil || leader {
				break monitor
			}
			// A child may stop reading ACP with a full pipe. POLLHUP still
			// observes HQ disconnecting while the forwarding goroutine waits.
			fds := []unix.PollFd{{Fd: int32(control.Fd())}}
			if _, err := unix.Poll(fds, 0); err != nil && err != unix.EINTR || fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				break monitor
			}
		}
	}
	write.Close()
	if !closeHarnessGroup(pid, grace) {
		return harnessUncontained
	}
	_ = cmd.Wait()
	if cmd.ProcessState == nil || !ready {
		return harnessUncontained
	}
	// Normally the child has closed its stderr and the relay reaches EOF.
	// A process outside the group may still have an inherited writer.
	select {
	case <-logDone:
	case <-time.After(250 * time.Millisecond):
		logRead.Close()
		select {
		case <-logDone:
		case <-time.After(time.Second):
			return harnessUncontained
		}
	}
	record := struct {
		Kind string `json:"kind"`
		Code int    `json:"exit_code"`
	}{"closed", cmd.ProcessState.ExitCode()}
	if reporter.write(record) != nil {
		return harnessUncontained
	}
	return harnessClosed
}
