//go:build darwin

package members

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type soulProcessObservation struct {
	Kernel soulKernelProcessSnapshot
}

// Bracket the expected-argument comparison with kernel identity samples. A
// PID that exits and is reused during observation cannot lend its argv to an
// earlier process. This is supporting evidence only: the exec path is not a
// vnode identity and the launcher must independently prove its execve inputs.
func observeSoulProcess(pid int, expectedPath string, expectedArgv []string) (soulProcessObservation, error) {
	first, err := observeSoulKernelProcess(pid)
	if err != nil {
		return soulProcessObservation{}, err
	}
	if err := observeSoulProcessArguments(pid, expectedPath, expectedArgv); err != nil {
		return soulProcessObservation{}, err
	}
	last, err := observeSoulKernelProcess(pid)
	if err != nil {
		return soulProcessObservation{}, err
	}
	if !sameSoulKernelProcess(first, last) {
		return soulProcessObservation{}, errors.New("Soul process changed during observation")
	}
	return soulProcessObservation{Kernel: last}, nil
}

func observeSoulProcessArguments(pid int, expectedPath string, expectedArgv []string) error {
	if pid <= 1 {
		return errors.New("invalid Soul process PID")
	}
	if err := validateSoulExpectedArguments(expectedPath, expectedArgv); err != nil {
		return err
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return fmt.Errorf("observe Soul process arguments: %w", err)
	}
	// Darwin can blur an empty argv slot with following environment bytes.
	// Compare the exact approved nonempty bytes in place and never return any
	// observed string, including on refusal. Clear even an invalid raw area.
	defer clear(raw)
	return matchSoulProcessArguments(raw, expectedPath, expectedArgv)
}

// Refuse empty approved arguments before kern.procargs2 reads the process: a
// Darwin kernel can elide an empty slot and expose environment bytes instead.
func validateSoulExpectedArguments(expectedPath string, expectedArgv []string) error {
	const maxArgs = 128
	if len(expectedPath) == 0 || expectedPath[0] != '/' ||
		len(expectedArgv) == 0 || len(expectedArgv) > maxArgs ||
		bytes.IndexByte([]byte(expectedPath), 0) >= 0 {
		return errors.New("Soul expected exec path or arguments are invalid")
	}
	for _, arg := range expectedArgv {
		if arg == "" || bytes.IndexByte([]byte(arg), 0) >= 0 {
			return errors.New("Soul expected argument is empty or invalid")
		}
	}
	return nil
}

// KERN_PROCARGS2 starts with a native int argc, then an exec path aligned to
// the target process pointer width, then exactly argc NUL-terminated argument
// strings. Current Darwin only runs 64-bit processes. Skip the exact padding,
// never arbitrary NULs. A match cannot replace measured launcher inputs.
func matchSoulProcessArguments(raw []byte, expectedPath string, expectedArgv []string) error {
	const pointerWidth = 8
	if err := validateSoulExpectedArguments(expectedPath, expectedArgv); err != nil {
		return err
	}
	if len(raw) < 6 || len(raw) > 1<<20 {
		return errors.New("Soul process arguments have invalid size")
	}
	argc := int(int32(binary.NativeEndian.Uint32(raw[:4])))
	if argc != len(expectedArgv) {
		return errors.New("Soul process argument count differs from approved launch")
	}
	remaining := raw[4:]
	end := bytes.IndexByte(remaining, 0)
	if end <= 0 || remaining[0] != '/' || !bytes.Equal(remaining[:end], []byte(expectedPath)) {
		return errors.New("Soul process exec path differs from approved launch")
	}
	remaining = remaining[end+1:]
	pad := (pointerWidth - (end+1)%pointerWidth) % pointerWidth
	if len(remaining) < pad {
		return errors.New("Soul process exec path padding is incomplete")
	}
	for _, value := range remaining[:pad] {
		if value != 0 {
			return errors.New("Soul process exec path padding is invalid")
		}
	}
	remaining = remaining[pad:]
	for i, expected := range expectedArgv {
		end = bytes.IndexByte(remaining, 0)
		if end <= 0 || !bytes.Equal(remaining[:end], []byte(expected)) {
			return fmt.Errorf("Soul process argv[%d] differs from approved launch", i)
		}
		remaining = remaining[end+1:]
	}
	return nil
}

// soulKernelProcessSnapshot is a kernel observation of one live PID. PID and
// start time must be compared together at every later observation so a reused
// PID cannot inherit an earlier start's identity. This does not observe the
// executable, argv, active Seatbelt profile, parent chain or endpoints and
// cannot qualify a run or authorize a launch on its own.
type soulKernelProcessSnapshot struct {
	PID             int
	ParentPID       int
	ProcessGroupID  int
	StartSeconds    int64
	StartMicros     int32
	RealUID         uint32
	EffectiveUID    uint32
	SavedUID        uint32
	RealGID         uint32
	PrimaryGroupGID uint32
	SavedGID        uint32
	Groups          []uint32
}

func observeSoulKernelProcess(pid int) (soulKernelProcessSnapshot, error) {
	if pid <= 1 {
		return soulKernelProcessSnapshot{}, errors.New("invalid Soul process PID")
	}
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return soulKernelProcessSnapshot{}, fmt.Errorf("observe Soul process: %w", err)
	}
	// Darwin's public sys/proc.h defines live SRUN, SSLEEP and SSTOP as 2..4.
	// SIDL is still being created; SZOMB is awaiting collection.
	if proc == nil || int(proc.Proc.P_pid) != pid || proc.Proc.P_stat < 2 || proc.Proc.P_stat > 4 ||
		proc.Eproc.Ppid <= 0 || proc.Eproc.Pgid <= 0 ||
		proc.Proc.P_starttime.Sec <= 0 || proc.Proc.P_starttime.Usec < 0 || proc.Proc.P_starttime.Usec >= 1_000_000 ||
		proc.Eproc.Ucred.Ngroups <= 0 || int(proc.Eproc.Ucred.Ngroups) > len(proc.Eproc.Ucred.Groups) {
		return soulKernelProcessSnapshot{}, errors.New("Soul process kernel identity is unavailable")
	}
	groups := append([]uint32(nil), proc.Eproc.Ucred.Groups[:proc.Eproc.Ucred.Ngroups]...)
	return soulKernelProcessSnapshot{
		PID: pid, ParentPID: int(proc.Eproc.Ppid), ProcessGroupID: int(proc.Eproc.Pgid),
		StartSeconds: proc.Proc.P_starttime.Sec, StartMicros: proc.Proc.P_starttime.Usec,
		RealUID: proc.Eproc.Pcred.P_ruid, EffectiveUID: proc.Eproc.Ucred.Uid,
		SavedUID: proc.Eproc.Pcred.P_svuid, RealGID: proc.Eproc.Pcred.P_rgid,
		PrimaryGroupGID: groups[0], SavedGID: proc.Eproc.Pcred.P_svgid, Groups: groups,
	}, nil
}

// sameSoulKernelProcess refuses PID reuse or credential drift between samples.
// A caller must still independently authenticate the HQ-started parent chain,
// executable/argv, active profile and endpoint state while the process lives.
func sameSoulKernelProcess(first, next soulKernelProcessSnapshot) bool {
	if first.PID <= 1 || first.PID != next.PID || first.StartSeconds != next.StartSeconds ||
		first.StartMicros != next.StartMicros || first.ParentPID != next.ParentPID ||
		first.ProcessGroupID != next.ProcessGroupID || first.RealUID != next.RealUID ||
		first.EffectiveUID != next.EffectiveUID || first.SavedUID != next.SavedUID ||
		first.RealGID != next.RealGID || first.PrimaryGroupGID != next.PrimaryGroupGID ||
		first.SavedGID != next.SavedGID || len(first.Groups) != len(next.Groups) {
		return false
	}
	for i := range first.Groups {
		if first.Groups[i] != next.Groups[i] {
			return false
		}
	}
	return true
}
