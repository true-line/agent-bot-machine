package daemon

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/qwts/managed-machine/internal/members"
	"golang.org/x/sys/unix"
)

const stage2aT02MonitorLimit = 64

type stage2aT02MonitorEntry struct {
	epoch, commandSHA  string
	hqUID              int
	expires            time.Time
	started, completed bool
	refusal            bool
	witness            stage2aT02KeydObservation
}

// The monitor shares A's daemon process with the paired device provider and
// the post-ChildReady qualification service. An arm is one use and expires;
// an unarmed request follows the ordinary device path without observation.
type stage2aT02KeydMonitor struct {
	mu      sync.Mutex
	entries map[string]*stage2aT02MonitorEntry
}

func newStage2aT02KeydMonitor() *stage2aT02KeydMonitor { return &stage2aT02KeydMonitor{} }

func (m *stage2aT02KeydMonitor) armCommand(commandRaw []byte, epoch string, hqUID int,
	now time.Time) (string, string, error) {
	nonce, err := members.Stage2aT02PairedOperationNonce(commandRaw)
	if err != nil {
		return "", "", errHQDevice
	}
	hash := stage2aT02Digest(commandRaw)
	if err := m.arm(nonce, hash, epoch, hqUID, now); err != nil {
		return "", "", err
	}
	return nonce, hash, nil
}

func (m *stage2aT02KeydMonitor) armRefusalCommand(commandRaw []byte, epoch string, hqUID int,
	now time.Time) (string, string, error) {
	nonce, err := members.Stage2aT02RevokedRefusalNonce(commandRaw)
	if err != nil {
		return "", "", errHQDevice
	}
	hash := stage2aT02Digest(commandRaw)
	if err := m.armMode(nonce, hash, epoch, hqUID, now, true); err != nil {
		return "", "", err
	}
	return nonce, hash, nil
}

func (m *stage2aT02KeydMonitor) provider(ctx context.Context, home string, d deviceDelegation) ([]byte, error) {
	armed, err := m.begin(d, time.Now())
	if err != nil {
		return nil, err
	}
	if !armed {
		return runDeviceKeyd(ctx, home, d)
	}
	return runDeviceKeydObserved(ctx, home, d, func(w stage2aT02KeydObservation) error {
		return m.finish(w, time.Now())
	})
}

func (m *stage2aT02KeydMonitor) arm(nonce, commandSHA, epoch string, hqUID int, now time.Time) error {
	return m.armMode(nonce, commandSHA, epoch, hqUID, now, false)
}

func (m *stage2aT02KeydMonitor) armMode(nonce, commandSHA, epoch string, hqUID int, now time.Time,
	refusal bool) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != nonce ||
		!strings.HasPrefix(commandSHA, "sha256:") || !exactKey(strings.TrimPrefix(commandSHA, "sha256:")) || !exactKey(epoch) ||
		hqUID <= 0 || now.IsZero() {
		return errHQDevice
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]*stage2aT02MonitorEntry)
	}
	for key, item := range m.entries {
		if !now.Before(item.expires) {
			delete(m.entries, key)
		}
	}
	if m.entries[nonce] != nil || len(m.entries) >= stage2aT02MonitorLimit {
		return errHQDevice
	}
	m.entries[nonce] = &stage2aT02MonitorEntry{epoch: epoch, commandSHA: commandSHA,
		hqUID: hqUID, refusal: refusal, expires: now.Add(30 * time.Second)}
	return nil
}

// begin returns false only for an unarmed ordinary request. A mismatched or
// replayed armed nonce is refused before any keyd process can start.
func (m *stage2aT02KeydMonitor) begin(d deviceDelegation, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.entries[d.Nonce]
	if item == nil {
		return false, nil
	}
	if !now.Before(item.expires) || item.started || item.refusal || d.Option != "enrollment-proof" ||
		item.epoch != d.Epoch || item.hqUID != d.UID {
		return true, errHQDevice
	}
	item.started = true
	return true, nil
}

const stage2aT02NoCallObservationSchema = "agent-bot-machine/t02-no-keyd-call/v1"

// This process-local negative observation is only meaningful when joined to
// the exact signed refusal and the live pair state by the qualification driver.
type stage2aT02NoCallObservation struct {
	Schema              string `json:"schema"`
	RequestNonce        string `json:"request_nonce"`
	CommandSHA256       string `json:"command_sha256"`
	HQEpoch             string `json:"hq_epoch"`
	HQUid               int    `json:"hq_uid"`
	MachinePID          int    `json:"machine_pid"`
	MachineStartSeconds int64  `json:"machine_start_seconds"`
	MachineStartMicros  int32  `json:"machine_start_micros"`
	MachineUID          uint32 `json:"machine_uid"`
	MachineGID          uint32 `json:"machine_gid"`
	KeydStarts          int    `json:"keyd_starts"`
	ObservedAt          string `json:"observed_at"`
}

func (m *stage2aT02KeydMonitor) takeNoCall(nonce, commandSHA string, now time.Time) (stage2aT02NoCallObservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.entries[nonce]
	if item == nil || item.commandSHA != commandSHA || !item.refusal || item.started ||
		!now.Before(item.expires) || os.Getuid() <= 0 || os.Getuid() != os.Geteuid() ||
		os.Getgid() != os.Getegid() {
		return stage2aT02NoCallObservation{}, errHQDevice
	}
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil || proc == nil || int(proc.Proc.P_pid) != os.Getpid() ||
		proc.Eproc.Ucred.Uid != uint32(os.Getuid()) ||
		proc.Eproc.Pcred.P_ruid != uint32(os.Getuid()) ||
		proc.Eproc.Pcred.P_rgid != uint32(os.Getgid()) ||
		proc.Proc.P_starttime.Sec <= 0 || proc.Proc.P_starttime.Usec < 0 ||
		proc.Proc.P_starttime.Usec >= 1_000_000 {
		return stage2aT02NoCallObservation{}, errHQDevice
	}
	delete(m.entries, nonce)
	return stage2aT02NoCallObservation{Schema: stage2aT02NoCallObservationSchema,
		RequestNonce: nonce, CommandSHA256: commandSHA, HQEpoch: item.epoch, HQUid: item.hqUID,
		MachinePID: os.Getpid(), MachineStartSeconds: proc.Proc.P_starttime.Sec,
		MachineStartMicros: proc.Proc.P_starttime.Usec, MachineUID: uint32(os.Getuid()),
		MachineGID: uint32(os.Getgid()), KeydStarts: 0,
		ObservedAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

func (m *stage2aT02KeydMonitor) finish(w stage2aT02KeydObservation, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.entries[w.RequestNonce]
	if item == nil || !item.started || item.completed || !now.Before(item.expires) ||
		item.epoch != w.HQEpoch || item.hqUID != w.HQUid ||
		w.Schema != stage2aT02KeydObservationSchema || w.KeydProcess.PID <= 1 ||
		!stage2aT02PublicKey(w.HQPublicKeyBase64) || !stage2aT02PublicKey(w.MachinePublicKeyBase64) ||
		w.KeydProcess.ParentPID != w.MachinePID || w.MachineUID == 0 ||
		w.KeydProcess.UID != w.MachineUID || w.KeydProcess.GID != w.MachineGID ||
		!strings.HasPrefix(w.OutputSHA256, "sha256:") || !exactKey(strings.TrimPrefix(w.OutputSHA256, "sha256:")) {
		return errHQDevice
	}
	item.witness, item.completed = w, true
	return nil
}

func (m *stage2aT02KeydMonitor) take(nonce, commandSHA string, now time.Time) (stage2aT02KeydObservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.entries[nonce]
	if item == nil || item.commandSHA != commandSHA || !now.Before(item.expires) ||
		!item.started || !item.completed {
		return stage2aT02KeydObservation{}, errHQDevice
	}
	delete(m.entries, nonce)
	return item.witness, nil
}

func (m *stage2aT02KeydMonitor) cancel(nonce, commandSHA string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item := m.entries[nonce]
	if item == nil || item.commandSHA != commandSHA {
		return errHQDevice
	}
	delete(m.entries, nonce)
	return nil
}
