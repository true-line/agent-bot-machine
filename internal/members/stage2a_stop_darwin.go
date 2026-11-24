//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Stop closes a spent start only after the kernel reports both dedicated
// role UIDs idle. The short launch lease alone never clears active occupancy.
// This receipt proves cutoff; it is not a T03 or host-report completion.
func (s *Stage2aService) Stop(hqUID int, epoch string, q Stage2aStopRequest) (Stage2aStopReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aStopReply
	if !validStage2aStopRequest(q) || q.HQEpoch != epoch || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if r == nil || r.digest != stage2aReservationSHA256(r.envelope) {
		return reply, errStage2aReservationAuthority
	}
	a := r.payload.Assignment
	if a.InstallationID != q.InstallationID || a.StartID != q.StartID || a.LaunchID != q.LaunchID ||
		a.PlanID != q.PlanID || a.PlanDigest != q.PlanDigest || a.HQEpoch != q.HQEpoch ||
		a.HQUID != hqUID {
		return reply, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aInstalledPolicyForStop(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest {
		return reply, errStage2aReservationAuthority
	}
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil || p.verifyRunnerGroup() != nil ||
		requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account, UID: p.Runner.UID},
			{Account: p.Bridge.Account, UID: p.Bridge.UID}}, unix.SysctlKinfoProcSlice) != nil {
		return reply, errStage2aReservationAuthority
	}
	if err := stage2aRevokeBridgeProof(a.SoulStartAssignment, r.bridgeProof[:]); err != nil {
		return reply, err
	}
	if requireIdleHarnessRoles([]HarnessAdapter{{Account: p.Runner.Account, UID: p.Runner.UID},
		{Account: p.Bridge.Account, UID: p.Bridge.UID}}, unix.SysctlKinfoProcSlice) != nil {
		return reply, errStage2aReservationAuthority
	}
	if err := stage2aRetireActiveClaim(dir, q, store.uid, store.gid); err != nil {
		return reply, err
	}
	payload := Stage2aStopPayload{Schema: "agent-bot-machine/stage2a-stop/v1",
		ReservationSHA256: q.ReservationSHA256, InstallationID: q.InstallationID, StartID: q.StartID,
		LaunchID: q.LaunchID, PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch,
		RunnerUID: p.Runner.UID, BridgeUID: p.Bridge.UID, RunnerPID: r.runnerPID, BridgePID: r.bridgePID,
		ChildLauncherPID: r.childLauncherPID, ChildPID: r.childPID,
		BothUIDsIdle: true, StoppedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if len(r.childReceiptEnvelope) > 0 {
		payload.ChildReceiptSHA256 = stage2aReservationSHA256(r.childReceiptEnvelope)
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aStopPurpose, s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil {
		return reply, err
	}
	// A signed stop is evidence of completed cutoff. Publish it only after
	// revocation, a second kernel idle check, and durable active-claim retirement.
	name := ".stage2a-stop-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if err := stage2aStoreStopEnvelope(dir, name, store.uid, store.gid, envelope); err != nil {
		return reply, err
	}
	if r.qT03 != nil {
		r.qT03.cancel()
	}
	clear(r.bridgeProof[:])
	delete(s.active, q.ReservationSHA256)
	return Stage2aStopReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope), SHA256: stage2aReservationSHA256(envelope)}, nil
}

func stage2aStoreStopEnvelope(dir *os.File, name string, uid, gid uint32, body []byte) error {
	if uid != uint32(os.Getuid()) || gid != uint32(os.Getgid()) || len(body) == 0 {
		return errStage2aReservationAuthority
	}
	return commitStage2aReservation(dir, name, body)
}

func stage2aRetireActiveClaim(dir *os.File, q Stage2aStopRequest, uid, gid uint32) error {
	active := stage2aActiveClaimName(q.InstallationID)
	closed := ".stage2a-closed-" + soulStartClaimName(q.InstallationID, q.StartID)
	fd, err := unix.Openat(int(dir.Fd()), active, stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		// A retry after a failed sync may find the claim already renamed.
		if err := requireUnspentStage2aReservation(dir, active); err != nil {
			return err
		}
		return stage2aCheckSpentClaim(dir, closed, uid, gid)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), active)
	defer f.Close()
	if err := requireUnspentStage2aReservation(dir, closed); err != nil {
		return err
	}
	if stage2aCheckSpentClaimFile(f, uid, gid) != nil {
		return errStage2aReservationAuthority
	}
	if err := unix.RenameatxNp(int(dir.Fd()), active, int(dir.Fd()), closed, unix.RENAME_EXCL); err != nil {
		return err
	}
	return dir.Sync()
}

func stage2aCheckSpentClaim(dir *os.File, name string, uid, gid uint32) error {
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return stage2aCheckSpentClaimFile(f, uid, gid)
}

func stage2aCheckSpentClaimFile(f *os.File, uid, gid uint32) error {
	if checkStage2aReservationFile(int(f.Fd()), uid, gid, unix.S_IFREG|0600) != nil {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil || !bytes.Equal(raw, []byte("stage2a-admin-spent/v1\n")) {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aRevokeBridgeProof(start SoulStartAssignment, key []byte) error {
	path, name := stage2aBridgeProofPath(start)
	dir, err := openStage2aAdminDirectory(path, uint32(start.MachineUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(path, name))
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0440 || st.Uid != uint32(start.MachineUID) ||
		st.Gid != uint32(start.BridgeGID) || st.Size != int64(len(key)) || st.Nlink != 1 {
		return errStage2aReservationAuthority
	}
	data, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || !bytes.Equal(data, key) {
		return errStage2aReservationAuthority
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		return err
	}
	return dir.Sync()
}
