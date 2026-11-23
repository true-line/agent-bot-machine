package daemon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/qwts/managed-machine/internal/members"
	"golang.org/x/sys/unix"
)

const stage2aT02KeydObservationSchema = "agent-bot-machine/t02-keyd-process/v1"

// This record is made by A during a qualified enrollment-proof call. It is
// not itself a receipt or a host verdict; the live driver must join it to its
// own command, exact signed HQ wire, pair state, and Q session before signing.
type stage2aT02KeydObservation struct {
	Schema                  string                           `json:"schema"`
	RequestNonce            string                           `json:"request_nonce"`
	HQEpoch                 string                           `json:"hq_epoch"`
	HQUid                   int                              `json:"hq_uid"`
	HQPublicKeyBase64       string                           `json:"hq_public_key_base64"`
	MachinePublicKeyBase64  string                           `json:"machine_public_key_base64"`
	MachinePID              int                              `json:"machine_pid"`
	MachineStartSeconds     int64                            `json:"machine_start_seconds"`
	MachineStartMicros      int32                            `json:"machine_start_micros"`
	MachineUID              uint32                           `json:"machine_uid"`
	MachineGID              uint32                           `json:"machine_gid"`
	KeydProcess             members.Stage2aT02ProcessWitness `json:"keyd_process"`
	KeydExecutableSHA256    string                           `json:"keyd_executable_sha256"`
	MachineExecutableSHA256 string                           `json:"machine_executable_sha256"`
	OutputSHA256            string                           `json:"output_sha256"`
	ObservedAt              string                           `json:"observed_at"`
}

func observeStage2aT02KeydCommand(pid int, cwd, machinePath string, delegation deviceDelegation) (stage2aT02KeydObservation, error) {
	var empty stage2aT02KeydObservation
	if pid <= 1 || cwd == "" || machinePath == "" || !deviceNonce.MatchString(delegation.Nonce) ||
		delegation.Option != "enrollment-proof" || delegation.UID <= 0 ||
		!stage2aT02PublicKey(delegation.HQ) || !stage2aT02PublicKey(delegation.Machine) ||
		os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return empty, errHQDevice
	}
	keydPath := filepath.Join(cwd, "agent-bot-keyd")
	keyd, err := members.ObserveStage2aT02Process(pid, os.Getpid(), os.Getuid(), os.Getgid(),
		keydPath, []string{keydPath, "hq-device"})
	if err != nil {
		return empty, errHQDevice
	}
	machine, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil || machine == nil || int(machine.Proc.P_pid) != os.Getpid() ||
		machine.Eproc.Ucred.Uid != uint32(os.Getuid()) ||
		machine.Eproc.Pcred.P_ruid != uint32(os.Getuid()) || machine.Eproc.Pcred.P_svuid != uint32(os.Getuid()) ||
		machine.Eproc.Pcred.P_rgid != uint32(os.Getgid()) || machine.Eproc.Pcred.P_svgid != uint32(os.Getgid()) ||
		machine.Eproc.Ucred.Ngroups < 1 || machine.Eproc.Ucred.Groups[0] != uint32(os.Getgid()) ||
		machine.Proc.P_starttime.Sec <= 0 || machine.Proc.P_starttime.Usec < 0 ||
		machine.Proc.P_starttime.Usec >= 1_000_000 {
		return empty, errHQDevice
	}
	keydHash, err := stage2aT02ExecutableHash(keydPath)
	if err != nil {
		return empty, errHQDevice
	}
	machineHash, err := stage2aT02ExecutableHash(machinePath)
	if err != nil {
		return empty, errHQDevice
	}
	return stage2aT02KeydObservation{
		Schema: stage2aT02KeydObservationSchema, RequestNonce: delegation.Nonce,
		HQEpoch: delegation.Epoch, HQUid: delegation.UID,
		HQPublicKeyBase64: delegation.HQ, MachinePublicKeyBase64: delegation.Machine,
		MachinePID: os.Getpid(), MachineStartSeconds: machine.Proc.P_starttime.Sec,
		MachineStartMicros: machine.Proc.P_starttime.Usec,
		MachineUID:         uint32(os.Getuid()), MachineGID: uint32(os.Getgid()),
		KeydProcess: keyd, KeydExecutableSHA256: keydHash,
		MachineExecutableSHA256: machineHash,
		ObservedAt:              time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func stage2aT02PublicKey(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == value
}

func stage2aT02ExecutableHash(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errHQDevice
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Size <= 0 || before.Size > 512<<20 || before.Mode&0022 != 0 {
		return "", errHQDevice
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, before.Size+1))
	if err != nil || n != before.Size || unix.Fstat(fd, &after) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return "", errHQDevice
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func stage2aT02Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
