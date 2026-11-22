//go:build darwin

package members

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// soulProcessArguments is a bounded reading of the Darwin exec argument area.
// The path and argv are supporting observations only: the exec path is not a
// vnode identity, and argv is not an authorization or a package measurement.
type soulProcessArguments struct {
	ExecPath string
	Argv     []string
}

func observeSoulProcessArguments(pid int) (soulProcessArguments, error) {
	if pid <= 1 {
		return soulProcessArguments{}, errors.New("invalid Soul process PID")
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return soulProcessArguments{}, fmt.Errorf("observe Soul process arguments: %w", err)
	}
	return parseSoulProcessArguments(raw)
}

// KERN_PROCARGS2 starts with a native int argc, then an exec path, NUL padding,
// and exactly argc NUL-terminated argument strings. The remaining bytes are
// environment data; never record or inspect them because they may hold secrets.
func parseSoulProcessArguments(raw []byte) (soulProcessArguments, error) {
	const maxArgs = 128
	if len(raw) < 6 || len(raw) > 1<<20 {
		return soulProcessArguments{}, errors.New("Soul process arguments have invalid size")
	}
	argc := int(int32(binary.NativeEndian.Uint32(raw[:4])))
	if argc <= 0 || argc > maxArgs {
		return soulProcessArguments{}, errors.New("Soul process argument count is invalid")
	}
	remaining := raw[4:]
	end := bytes.IndexByte(remaining, 0)
	if end <= 0 || remaining[0] != '/' {
		return soulProcessArguments{}, errors.New("Soul process exec path is unavailable")
	}
	result := soulProcessArguments{ExecPath: string(remaining[:end]), Argv: make([]string, 0, argc)}
	remaining = remaining[end+1:]
	for len(remaining) != 0 && remaining[0] == 0 {
		remaining = remaining[1:]
	}
	for i := 0; i < argc; i++ {
		end = bytes.IndexByte(remaining, 0)
		if end <= 0 {
			return soulProcessArguments{}, errors.New("Soul process argv is incomplete")
		}
		result.Argv = append(result.Argv, string(remaining[:end]))
		remaining = remaining[end+1:]
	}
	return result, nil
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
	if proc == nil || int(proc.Proc.P_pid) != pid || proc.Proc.P_stat == 0 || proc.Proc.P_stat == 5 ||
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
