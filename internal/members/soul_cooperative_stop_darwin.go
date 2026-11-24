//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeStopPurposeV3 = "agent-bot/soul-cooperative-stop/v3"

type soulCooperativeStopPayloadV3 struct {
	Contract                 string `json:"contract"`
	Kind                     string `json:"kind"`
	SchemaVersion            int    `json:"schema_version"`
	ReservationSHA256        string `json:"reservation_sha256"`
	AttachSHA256             string `json:"attach_sha256"`
	CancelSHA256             string `json:"cancel_sha256"`
	HDescriptorDigest        string `json:"h_service_descriptor_digest"`
	InstallationID           string `json:"installation_id"`
	StartID                  string `json:"start_id"`
	LaunchID                 string `json:"launch_id"`
	PlanID                   string `json:"plan_id"`
	PlanDigest               string `json:"plan_digest"`
	HQEpoch                  string `json:"hq_epoch"`
	RunnerUID                int    `json:"runner_uid"`
	DispatcherPID            int    `json:"dispatcher_pid"`
	RunnerPID                int    `json:"runner_pid"`
	DispatchCompletionSHA256 string `json:"dispatch_completion_sha256"`
	ReportedExitCode         int    `json:"reported_exit_code"`
	RunnerUIDIdle            bool   `json:"runner_uid_idle"`
	StoppedAt                string `json:"stopped_at"`
}

// StopCooperativeVerified signs a cutoff, not a successful provider response.
// The R completion report is untrusted; A separately requires the dedicated
// R UID to have no live process and rechecks H/R custody before clearing the
// active slot. A completed-run commitment needs independent HQ evidence.
func (s *Stage2aService) StopCooperativeVerified(hqUID int, epoch string,
	q Stage2aStopRequest, paired func(string, func() error) error) (Stage2aStopReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aStopReply
	if paired == nil || !validStage2aStopRequest(q) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || live.digest != q.ReservationSHA256 ||
		live.request.InstallationID != q.InstallationID || live.request.StartID != q.StartID ||
		live.request.LaunchID != q.LaunchID || live.request.PlanDigest != q.PlanDigest ||
		live.request.HQEpoch != epoch || live.installed.Policy.HQUID != hqUID {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		p := live.installed.Policy
		if stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		installed, _, e := loadSoulCooperativeInstalledV3(s.key.Public().(ed25519.PublicKey),
			hqUID, epoch, q.InstallationID)
		if e != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) {
			return errSoulCooperativeAuthority
		}
		var receipt Receipt
		if json.Unmarshal(installed.RootReceipt, &receipt) != nil || receipt.PlanID != q.PlanID ||
			receipt.PlanDigest != q.PlanDigest {
			return errSoulCooperativeAuthority
		}
		paths, e := cooperativeLaunchPaths(q.InstallationID)
		if e != nil {
			return e
		}
		cancelSHA, e := publishSoulCooperativeCancel(paths, live,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil {
			return e
		}
		var completion soulCooperativeDispatchCompletion
		var raw []byte
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			completion, raw, e = readSoulCooperativeDispatchCompletion(paths, p.Runner.UID, p.Runner.GID)
			if e == nil && requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account,
				UID: p.Runner.UID}}, unix.SysctlKinfoProcSlice) == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if e != nil || completion.ReservationSHA256 != q.ReservationSHA256 ||
			completion.StartID != q.StartID || completion.LaunchID != q.LaunchID ||
			completion.DispatcherPID != live.dispatcherPID || completion.RunnerPID != live.runnerPID ||
			!completion.DescendantsStopped ||
			(completion.CancelSHA256 != "" && completion.CancelSHA256 != cancelSHA) {
			return errSoulCooperativeAuthority
		}
		if requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account, UID: p.Runner.UID}},
			unix.SysctlKinfoProcSlice) != nil {
			return errSoulCooperativeAuthority
		}
		time.Sleep(100 * time.Millisecond)
		if requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account, UID: p.Runner.UID}},
			unix.SysctlKinfoProcSlice) != nil {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeStopPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-stop",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256, AttachSHA256: live.attachSHA256,
			CancelSHA256:      cancelSHA,
			HDescriptorDigest: live.hDescriptorDigest, InstallationID: q.InstallationID, StartID: q.StartID,
			LaunchID: q.LaunchID, PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch,
			RunnerUID: p.Runner.UID, DispatcherPID: live.dispatcherPID, RunnerPID: live.runnerPID,
			DispatchCompletionSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)),
			ReportedExitCode:         completion.ExitCode, RunnerUIDIdle: true,
			StoppedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeStopPurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil {
			return e
		}
		store := installed.claimStore()
		dir, e := store.open()
		if e != nil {
			return e
		}
		defer dir.Close()
		name := ".cooperative-stop-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
		if e := commitStage2aReservation(dir, name, envelope); e != nil {
			return e
		}
		// Persist the signed cutoff before releasing the one-use active claim.
		// If claim release fails, the record remains for explicit reconciliation.
		if e := releaseSoulCooperativeStart(store, live.request, func() (bool, error) {
			return requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account, UID: p.Runner.UID}},
				unix.SysctlKinfoProcSlice) == nil, nil
		}); e != nil {
			return e
		}
		// Removing the exact leaves prevents stale WatchPaths starts and permits
		// another owner-approved start only after the durable cutoff exists.
		if e := os.Remove(paths.activeRequest); e != nil {
			return e
		}
		if e := os.Remove(paths.cancel); e != nil {
			return e
		}
		if e := os.Remove(filepath.Join(paths.completionDir, "completion.json")); e != nil {
			return e
		}
		if e := unix.Unlinkat(int(dir.Fd()), cooperativePendingName(q.InstallationID, q.StartID), 0); e != nil {
			return e
		}
		if e := syncUpgradeDir(paths.requestDir); e != nil {
			return e
		}
		if e := dir.Sync(); e != nil {
			return e
		}
		if e := syncUpgradeDir(paths.completionDir); e != nil {
			return e
		}
		reply = Stage2aStopReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		return nil
	})
	if err != nil {
		return Stage2aStopReply{}, err
	}
	if !ran || reply.SHA256 == "" {
		return Stage2aStopReply{}, errSoulCooperativeAuthority
	}
	s.closeDirectQualificationV3(live)
	delete(s.cooperativeActive, q.ReservationSHA256)
	return reply, nil
}

func readSoulCooperativeDispatchCompletion(paths soulCooperativeLaunchPaths,
	runnerUID, runnerGID int) (soulCooperativeDispatchCompletion, []byte, error) {
	var empty soulCooperativeDispatchCompletion
	parent, e := openStage2aAdminDirectory(filepath.Dir(paths.completionDir), uint32(os.Getuid()))
	if e != nil {
		return empty, nil, e
	}
	defer parent.Close()
	dirFD, e := unix.Openat(int(parent.Fd()), filepath.Base(paths.completionDir), stage2aDirectoryOpenFlags, 0)
	if e != nil {
		return empty, nil, e
	}
	dir := os.NewFile(uintptr(dirFD), paths.completionDir)
	defer dir.Close()
	var dirStat unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &dirStat) != nil || dirStat.Mode != unix.S_IFDIR|02770 ||
		dirStat.Uid != uint32(os.Getuid()) || dirStat.Gid != uint32(runnerGID) ||
		checkDarwinACLs([]string{paths.completionDir}) != nil {
		return empty, nil, errSoulCooperativeAuthority
	}
	fd, e := unix.Openat(int(dir.Fd()), "completion.json", stage2aFileOpenFlags, 0)
	if e != nil {
		return empty, nil, e
	}
	f := os.NewFile(uintptr(fd), paths.completionDir)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0444 ||
		before.Uid != uint32(runnerUID) || before.Gid != uint32(runnerGID) || before.Nlink != 1 ||
		before.Size < 1 || before.Size > 4096 || checkDarwinACLs([]string{filepath.Join(paths.completionDir, "completion.json")}) != nil {
		return empty, nil, errSoulCooperativeAuthority
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || stage2aStrictJSON(raw) != nil {
		return empty, nil, errSoulCooperativeAuthority
	}
	var completion soulCooperativeDispatchCompletion
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&completion) != nil || decoder.Decode(new(any)) != io.EOF ||
		completion.Schema != "agent-bot-machine/cooperative-dispatch-completion/v1" ||
		completion.DispatcherPID <= 1 || completion.RunnerPID <= 1 ||
		completion.ExitCode < 0 || completion.ExitCode > 255 {
		return empty, nil, errSoulCooperativeAuthority
	}
	started, e1 := time.Parse(time.RFC3339Nano, completion.StartedAt)
	ended, e2 := time.Parse(time.RFC3339Nano, completion.FinishedAt)
	if e1 != nil || e2 != nil || ended.Before(started) {
		return empty, nil, errSoulCooperativeAuthority
	}
	return completion, raw, nil
}
