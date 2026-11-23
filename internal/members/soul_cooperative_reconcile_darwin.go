//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeRecoveryPurposeV3 = "agent-bot/soul-cooperative-recovery-cutoff/v3"

type soulCooperativeRecoveryPayloadV3 struct {
	Contract          string `json:"contract"`
	Kind              string `json:"kind"`
	SchemaVersion     int    `json:"schema_version"`
	ReservationSHA256 string `json:"reservation_sha256"`
	HDescriptorDigest string `json:"h_service_descriptor_digest"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	PlanID            string `json:"plan_id"`
	PlanDigest        string `json:"plan_digest"`
	HQEpoch           string `json:"hq_epoch"`
	RunnerUID         int    `json:"runner_uid"`
	CancelSHA256      string `json:"cancel_sha256,omitempty"`
	ClaimSpent        bool   `json:"claim_spent"`
	AttachedClaim     bool   `json:"attached_claim"`
	RunnerUIDIdle     bool   `json:"runner_uid_idle"`
	HQEndpointsAbsent bool   `json:"hq_endpoints_absent"`
	RecoveredAt       string `json:"recovered_at"`
}

// ReconcileCooperativeAfterRestart is only for a fresh owner-signed recovery
// challenge after HQ has retired the exact C and broker endpoints. The daemon
// holds the current pair while this method signs a cutoff. It never restores
// attach/provider authority or labels task completion.
func (s *Stage2aService) ReconcileCooperativeAfterRestart(hqUID int, epoch string,
	q Stage2aStopRequest, withOwnerRevokedPair func(string, func() error) error,
) (Stage2aStopReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aStopReply
	if withOwnerRevokedPair == nil || len(s.key) != ed25519.PrivateKeySize ||
		!validStage2aStopRequest(q) || q.HQEpoch != epoch ||
		s.cooperativeActive[q.ReservationSHA256] != nil {
		return reply, errSoulCooperativeAuthority
	}
	for _, live := range s.cooperativeActive {
		if live.request.InstallationID == q.InstallationID {
			return reply, errSoulCooperativeAuthority
		}
	}
	pub := s.key.Public().(ed25519.PublicKey)
	installed, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
	if err != nil || stage2aRecheckVerifiedDomainV3(r) != nil {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err = withOwnerRevokedPair(installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		return s.reconcileCooperativeInstalled(installed, q, pub, &reply)
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aStopReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}

func (s *Stage2aService) reconcileCooperativeInstalled(installed soulCooperativeInstalledV3,
	q Stage2aStopRequest, pub ed25519.PublicKey, reply *Stage2aStopReply) error {
	p := installed.Policy
	var receipt Receipt
	if json.Unmarshal(installed.RootReceipt, &receipt) != nil ||
		receipt.PlanID != q.PlanID || receipt.PlanDigest != q.PlanDigest ||
		p.HQEpoch != q.HQEpoch || p.Runner.InstallationID != q.InstallationID {
		return errSoulCooperativeAuthority
	}
	paths, err := cooperativeLaunchPaths(q.InstallationID)
	if err != nil || installed.RequestDirectory.Path != paths.requestDir {
		return errSoulCooperativeAuthority
	}
	staging, err := stage2aInstalledDirectoryIdentity(paths.stagingDir,
		p.MachineUID, p.Runner.GID, 02700)
	if err != nil || staging != installed.StagingDirectory {
		return errSoulCooperativeAuthority
	}
	temps, err := soulCooperativeRecoveryTemps(paths, p)
	if err != nil {
		return err
	}
	// The A-only claims journal is committed before a start is spent. Exactly
	// one staged or launchd-visible selector may survive beside it.
	selected := ""
	for _, leaf := range []string{paths.stagedRequest, paths.request, paths.activeRequest} {
		if _, err := os.Lstat(leaf); err == nil {
			if selected != "" {
				return errSoulCooperativeAuthority
			}
			selected = leaf
		} else if !errors.Is(err, os.ErrNotExist) {
			return errSoulCooperativeAuthority
		}
	}
	// Remove the sole launchd-visible selector before looking for idle R.
	if selected == paths.request {
		if err := unix.RenamexNp(paths.request, paths.activeRequest, unix.RENAME_EXCL); err != nil ||
			syncUpgradeDir(paths.requestDir) != nil {
			return errSoulCooperativeAuthority
		}
		selected = paths.activeRequest
	}
	store := installed.claimStore()
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	if store.checkDirectory(dir) != nil {
		return errSoulCooperativeAuthority
	}
	journal, request, reservation, err := readSoulCooperativeRecoveryRequest(dir, store,
		q.InstallationID, q.StartID, p, pub)
	if err != nil && soulCooperativeLeafAbsent(filepath.Join(store.path,
		cooperativePendingName(q.InstallationID, q.StartID))) {
		return finishCompletedCooperativeRecovery(dir, store, paths, p, q, pub, selected, temps, reply)
	}
	if err != nil || request.ReservationSHA256 != q.ReservationSHA256 ||
		reservation.Assignment.StartID != q.StartID || reservation.Assignment.LaunchID != q.LaunchID ||
		reservation.Assignment.PlanID != q.PlanID || reservation.Assignment.PlanDigest != q.PlanDigest ||
		reservation.Assignment.HQEpoch != q.HQEpoch || reservation.Assignment.RunnerUID != p.Runner.UID ||
		reservation.Assignment.RunnerGID != p.Runner.GID ||
		reservation.MeasurementBinding.RInventory != installed.RuntimeV3 ||
		reservation.MeasurementBinding.HDescriptorDigest == "" {
		return errSoulCooperativeAuthority
	}
	if selected != "" {
		if err := checkSoulCooperativeRecoveryLeaf(selected, paths, p, journal); err != nil {
			return err
		}
	}
	endpointsAbsent := func() bool { return soulCooperativeGuestEndpointsAbsent(p, q.StartID) }
	if !endpointsAbsent() {
		return errSoulCooperativeAuthority
	}
	spent, err := soulCooperativeClaimState(dir, cooperativeSpentName(q.InstallationID, q.StartID), store)
	if err != nil {
		return err
	}
	activeName := cooperativeActiveName(q.InstallationID)
	active := requireUnspentStage2aReservation(dir, activeName) != nil
	if active && cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil {
		return errSoulCooperativeAuthority
	}
	if active && !spent {
		return errSoulCooperativeAuthority
	}
	if spent && len(temps) != 0 {
		return errSoulCooperativeAuthority
	}
	attached, err := soulCooperativeClaimState(dir, cooperativeAttachedName(q.InstallationID, q.StartID), store)
	if err != nil {
		return err
	}
	name := ".cooperative-recovery-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	existingCutoff, existingPayload, err := readSoulCooperativeRecoveryCutoff(dir, store, name, pub, q,
		reservation.MeasurementBinding.HDescriptorDigest, p.Runner.UID)
	if err != nil || len(existingCutoff) > 0 &&
		(existingPayload.ClaimSpent != spent || existingPayload.AttachedClaim != attached) {
		return errSoulCooperativeAuthority
	}
	terminal, err := soulCooperativeExistingTerminal(dir, store, pub, q,
		reservation.MeasurementBinding.HDescriptorDigest)
	if err != nil || (terminal != "" && !spent) ||
		(terminal == "stop" && !attached) || (terminal == "abort" && attached) ||
		(active && selected == "") ||
		(!active && attached && terminal != "stop" && len(existingCutoff) == 0) ||
		(!active && spent && selected != paths.stagedRequest && terminal == "" && len(existingCutoff) == 0) {
		return errSoulCooperativeAuthority
	}
	if !spent && selected != "" && selected != paths.stagedRequest {
		// A signed request became launchd-visible only after a spent claim.
		return errSoulCooperativeAuthority
	}
	// If Machine restarted while R was live, A can still publish a selector
	// derived only from the durable signed reservation. The no-attach form is
	// deliberately accepted by R even if the old H attach was consumed; it
	// grants no new authority and only terminates this exact child group.
	var cancelSHA string
	if selected == paths.activeRequest && terminal == "" {
		live := &soulCooperativeLiveV3{request: SoulCooperativeReserveRequest{
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID},
			installed: installed, digest: q.ReservationSHA256}
		cancelSHA, err = publishSoulCooperativeCancel(paths, live, pub, s.sign)
		if err != nil {
			return errSoulCooperativeAuthority
		}
	}
	if !soulCooperativeLeafAbsent(paths.cancel) {
		requestDir, err := unix.Open(paths.requestDir, stage2aDirectoryOpenFlags, 0)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		want := soulCooperativeCancelPayloadV3{ReservationSHA256: q.ReservationSHA256,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			RunnerPID: -1}
		found, digest, readErr := readSoulCooperativeCancelWithExpiry(requestDir, paths, pub,
			want, time.Now().UTC(), true)
		unix.Close(requestDir)
		if readErr != nil || !found {
			return errSoulCooperativeAuthority
		}
		if cancelSHA != "" && cancelSHA != digest {
			return errSoulCooperativeAuthority
		}
		cancelSHA = digest
	}
	idle := func() bool { return soulCooperativeGuestRolesIdle(p) }
	deadline := time.Now().Add(5 * time.Second)
	for !idle() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !idle() {
		return errSoulCooperativeAuthority
	}
	time.Sleep(100 * time.Millisecond)
	if !idle() || !endpointsAbsent() {
		return errSoulCooperativeAuthority
	}
	completionPath := filepath.Join(paths.completionDir, "completion.json")
	if _, err := os.Lstat(completionPath); err == nil {
		completion, _, readErr := readSoulCooperativeDispatchCompletion(paths, p.Runner.UID, p.Runner.GID)
		if readErr != nil || completion.ReservationSHA256 != q.ReservationSHA256 ||
			completion.StartID != q.StartID || completion.LaunchID != q.LaunchID {
			return errSoulCooperativeAuthority
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errSoulCooperativeAuthority
	}
	envelope := existingCutoff
	if len(envelope) == 0 {
		payload := soulCooperativeRecoveryPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-recovery-cutoff",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			HDescriptorDigest: reservation.MeasurementBinding.HDescriptorDigest,
			InstallationID:    q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch,
			RunnerUID: p.Runner.UID, CancelSHA256: cancelSHA, ClaimSpent: spent, AttachedClaim: attached,
			RunnerUIDIdle: true, HQEndpointsAbsent: true,
			RecoveredAt: time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, err = signStage2aEnvelope(payload, 3, soulCooperativeRecoveryPurposeV3, pub, s.sign)
		if err != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		if err := commitStage2aReservation(dir, name, envelope); err != nil {
			return err
		}
	}
	// The signed cutoff is durable before the occupied slot is released.
	if active {
		request := SoulCooperativeReserveRequest{Profile: "managed-cooperative", HostID: p.HostID,
			PlanDigest: q.PlanDigest, InstallationID: q.InstallationID, StartID: q.StartID,
			LaunchID: q.LaunchID, HQEpoch: q.HQEpoch, PackagePath: p.SourcePackagePath}
		if err := releaseSoulCooperativeStart(store, request, func() (bool, error) {
			return idle() && endpointsAbsent(), nil
		}); err != nil {
			return err
		}
	}
	if err := revokeCooperativeBProof(p, q.StartID, ""); err != nil {
		return err
	}
	if err := completeCooperativeRecoveryCleanup(dir, paths, selected, temps,
		completionPath, cooperativePendingName(q.InstallationID, q.StartID), os.Remove); err != nil {
		return err
	}
	*reply = Stage2aStopReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
	return nil
}

// Remove and durably sync every launch/completion leaf before unlinking the
// A-only journal. If cleanup fails, a fresh owner proof can still recover the
// exact signed cutoff and retry. After the journal is gone, no work remains.
func completeCooperativeRecoveryCleanup(dir *os.File, paths soulCooperativeLaunchPaths,
	selected string, temps []string, completionPath, pending string,
	remove func(string) error) error {
	if dir == nil || remove == nil {
		return errSoulCooperativeAuthority
	}
	if selected != "" {
		if err := remove(selected); err != nil {
			return err
		}
	}
	if !soulCooperativeLeafAbsent(paths.cancel) {
		if err := remove(paths.cancel); err != nil {
			return err
		}
	}
	if !soulCooperativeLeafAbsent(paths.outcome) {
		if err := remove(paths.outcome); err != nil {
			return err
		}
	}
	for _, name := range temps {
		if err := remove(filepath.Join(paths.stagingDir, name)); err != nil {
			return err
		}
	}
	if !soulCooperativeLeafAbsent(completionPath) {
		if err := remove(completionPath); err != nil {
			return err
		}
	}
	for _, path := range []string{paths.requestDir, paths.stagingDir, paths.completionDir} {
		if err := syncUpgradeDir(path); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(int(dir.Fd()), pending, 0); err != nil {
		return err
	}
	return dir.Sync()
}

func soulCooperativeLeafAbsent(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// A lost reply after cleanup returns the same previously signed cutoff. A
// second owner proof is still required, and no R/H authority is recreated.
func finishCompletedCooperativeRecovery(dir *os.File, store stage2aAdminClaimStore,
	paths soulCooperativeLaunchPaths, p SoulCooperativeLaunchPolicy, q Stage2aStopRequest,
	pub ed25519.PublicKey, selected string, temps []string, reply *Stage2aStopReply) error {
	if selected != "" || len(temps) != 0 || !soulCooperativeLeafAbsent(paths.cancel) ||
		!soulCooperativeLeafAbsent(paths.outcome) ||
		!soulCooperativeLeafAbsent(filepath.Join(paths.completionDir, "completion.json")) ||
		requireUnspentStage2aReservation(dir, cooperativeActiveName(q.InstallationID)) != nil {
		return errSoulCooperativeAuthority
	}
	spent, err := soulCooperativeClaimState(dir, cooperativeSpentName(q.InstallationID, q.StartID), store)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	attached, err := soulCooperativeClaimState(dir, cooperativeAttachedName(q.InstallationID, q.StartID), store)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	name := ".cooperative-recovery-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	envelope, payload, err := readSoulCooperativeRecoveryCutoff(dir, store, name, pub, q, "", p.Runner.UID)
	if err != nil || len(envelope) == 0 || payload.ClaimSpent != spent || payload.AttachedClaim != attached {
		return errSoulCooperativeAuthority
	}
	if !soulCooperativeGuestEndpointsAbsent(p, q.StartID) {
		return errSoulCooperativeAuthority
	}
	idle := func() bool { return soulCooperativeGuestRolesIdle(p) }
	if !idle() {
		return errSoulCooperativeAuthority
	}
	time.Sleep(100 * time.Millisecond)
	if !idle() || !soulCooperativeGuestEndpointsAbsent(p, q.StartID) {
		return errSoulCooperativeAuthority
	}
	if err := revokeCooperativeBProof(p, q.StartID, ""); err != nil {
		return err
	}
	*reply = Stage2aStopReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
	return nil
}

func readSoulCooperativeRecoveryCutoff(dir *os.File, store stage2aAdminClaimStore,
	name string, pub ed25519.PublicKey, q Stage2aStopRequest, hDigest string,
	runnerUID int) ([]byte, soulCooperativeRecoveryPayloadV3, error) {
	var empty soulCooperativeRecoveryPayloadV3
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, empty, nil
	}
	if err != nil {
		return nil, empty, errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 ||
		before.Uid != store.uid || before.Gid != store.gid || before.Nlink != 1 ||
		before.Size < 1 || before.Size > 8192 ||
		checkDarwinACLs([]string{filepath.Join(store.path, name)}) != nil {
		return nil, empty, errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return nil, empty, errSoulCooperativeAuthority
	}
	payloadRaw, _, err := verifySoulCooperativePurposeV3(raw, pub, soulCooperativeRecoveryPurposeV3)
	if err != nil || len(payloadRaw) > 4096 {
		return nil, empty, errSoulCooperativeAuthority
	}
	dec := json.NewDecoder(bytes.NewReader(payloadRaw))
	dec.DisallowUnknownFields()
	var got soulCooperativeRecoveryPayloadV3
	if dec.Decode(&got) != nil || dec.Decode(new(any)) != io.EOF ||
		got.Contract != "machine/v3" || got.Kind != "soul-cooperative-recovery-cutoff" ||
		got.SchemaVersion != 3 || got.ReservationSHA256 != q.ReservationSHA256 ||
		got.InstallationID != q.InstallationID || got.StartID != q.StartID ||
		got.LaunchID != q.LaunchID || got.PlanID != q.PlanID ||
		got.PlanDigest != q.PlanDigest || got.HQEpoch != q.HQEpoch ||
		!stage2aPrefixedDigest.MatchString(got.HDescriptorDigest) ||
		(hDigest != "" && got.HDescriptorDigest != hDigest) ||
		(got.CancelSHA256 != "" && !stage2aPrefixedDigest.MatchString(got.CancelSHA256)) ||
		got.RunnerUID != runnerUID || !got.RunnerUIDIdle || !got.HQEndpointsAbsent {
		return nil, empty, errSoulCooperativeAuthority
	}
	if _, err := time.Parse(time.RFC3339Nano, got.RecoveredAt); err != nil {
		return nil, empty, errSoulCooperativeAuthority
	}
	return raw, got, nil
}

func soulCooperativeRecoveryTemps(paths soulCooperativeLaunchPaths,
	p SoulCooperativeLaunchPolicy) ([]string, error) {
	dir, err := os.Open(paths.stagingDir)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	defer dir.Close()
	names, err := dir.Readdirnames(17)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > 16 {
		return nil, errSoulCooperativeAuthority
	}
	var temps []string
	for _, name := range names {
		if name == filepath.Base(paths.stagedRequest) {
			continue
		}
		if !(strings.HasPrefix(name, ".request-") || strings.HasPrefix(name, ".outcome-")) || len(name) > 80 {
			return nil, errSoulCooperativeAuthority
		}
		var stat unix.Stat_t
		if unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			(stat.Mode != unix.S_IFREG|0600 && stat.Mode != unix.S_IFREG|0640 && stat.Mode != unix.S_IFREG|0440) ||
			stat.Uid != uint32(p.MachineUID) || stat.Gid != uint32(p.Runner.GID) ||
			stat.Nlink != 1 || stat.Size < 0 || stat.Size > 64<<10 ||
			checkDarwinACLs([]string{filepath.Join(paths.stagingDir, name)}) != nil {
			return nil, errSoulCooperativeAuthority
		}
		temps = append(temps, name)
	}
	return temps, nil
}

func soulCooperativeClaimState(dir *os.File, name string, store stage2aAdminClaimStore) (bool, error) {
	if requireUnspentStage2aReservation(dir, name) == nil {
		return false, nil
	}
	if stage2aCheckSpentClaim(dir, name, store.uid, store.gid) != nil {
		return false, errSoulCooperativeAuthority
	}
	return true, nil
}

func soulCooperativeExistingTerminal(dir *os.File, store stage2aAdminClaimStore,
	key ed25519.PublicKey, q Stage2aStopRequest, hDigest string) (string, error) {
	stopName := ".cooperative-stop-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	abortName := ".cooperative-abort-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	stopExists := requireUnspentStage2aReservation(dir, stopName) != nil
	abortExists := requireUnspentStage2aReservation(dir, abortName) != nil
	if stopExists && abortExists {
		return "", errSoulCooperativeAuthority
	}
	if !stopExists && !abortExists {
		return "", nil
	}
	name, purpose := stopName, soulCooperativeStopPurposeV3
	if abortExists {
		name, purpose = abortName, soulCooperativeAbortPurposeV3
	}
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return "", errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 ||
		before.Uid != store.uid || before.Gid != store.gid || before.Nlink != 1 ||
		before.Size < 1 || before.Size > 8192 ||
		checkDarwinACLs([]string{filepath.Join(store.path, name)}) != nil {
		return "", errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return "", errSoulCooperativeAuthority
	}
	payload, _, err := verifySoulCooperativePurposeV3(raw, key, purpose)
	if err != nil {
		return "", errSoulCooperativeAuthority
	}
	if stopExists {
		var stop soulCooperativeStopPayloadV3
		if json.Unmarshal(payload, &stop) != nil || stop.Contract != "machine/v3" ||
			stop.Kind != "soul-cooperative-stop" || stop.SchemaVersion != 3 ||
			stop.ReservationSHA256 != q.ReservationSHA256 || stop.HDescriptorDigest != hDigest ||
			stop.InstallationID != q.InstallationID || stop.StartID != q.StartID ||
			stop.LaunchID != q.LaunchID || stop.PlanID != q.PlanID ||
			stop.PlanDigest != q.PlanDigest || stop.HQEpoch != q.HQEpoch || !stop.RunnerUIDIdle {
			return "", errSoulCooperativeAuthority
		}
		return "stop", nil
	}
	var abort soulCooperativeAbortPayloadV3
	if json.Unmarshal(payload, &abort) != nil || abort.Contract != "machine/v3" ||
		abort.Kind != "soul-cooperative-abort" || abort.SchemaVersion != 3 ||
		abort.ReservationSHA256 != q.ReservationSHA256 || abort.HDescriptorDigest != hDigest ||
		abort.InstallationID != q.InstallationID || abort.StartID != q.StartID ||
		abort.LaunchID != q.LaunchID || abort.PlanID != q.PlanID ||
		abort.PlanDigest != q.PlanDigest || abort.HQEpoch != q.HQEpoch || !abort.RunnerUIDIdle {
		return "", errSoulCooperativeAuthority
	}
	return "abort", nil
}

func readSoulCooperativeRecoveryRequest(dir *os.File, store stage2aAdminClaimStore,
	installationID, startID string, p SoulCooperativeLaunchPolicy, key ed25519.PublicKey,
) ([]byte, soulCooperativeDispatchRequest, soulCooperativeReservationPayloadV3, error) {
	var emptyRequest soulCooperativeDispatchRequest
	var emptyReservation soulCooperativeReservationPayloadV3
	name := cooperativePendingName(installationID, startID)
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, emptyRequest, emptyReservation, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0600 ||
		before.Uid != store.uid || before.Gid != store.gid ||
		before.Nlink != 1 || before.Size < 1 || before.Size > 64<<10 ||
		checkDarwinACLs([]string{filepath.Join(store.path, name)}) != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || stage2aStrictJSONBounded(raw, 64<<10, stage2aV3MaxJSONNodes) != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	var header soulCooperativeDispatchRequest
	if json.Unmarshal(raw, &header) != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(header.ReservationEnvelopeBase64URL)
	if err != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	canonical, _, err := verifySoulCooperativeEnvelopeV3(envelope, key)
	var historical soulCooperativeReservationPayloadV3
	if err != nil || json.Unmarshal(canonical, &historical) != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, historical.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, historical.ExpiresAt)
	if e1 != nil || e2 != nil || expires.Sub(issued) != 30*time.Second {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	// The ordinary dispatcher rejects expired starts. Recovery intentionally
	// checks historical signed bytes at the last instant of their valid lease.
	request, reservation, err := decodeSoulCooperativeDispatchRequest(raw, key,
		p.Runner.InstallationID, p.Runner.UID, p.Runner.GID, expires.Add(-time.Nanosecond))
	if err != nil {
		return nil, emptyRequest, emptyReservation, errSoulCooperativeAuthority
	}
	return raw, request, reservation, nil
}

func checkSoulCooperativeRecoveryLeaf(path string, paths soulCooperativeLaunchPaths,
	p SoulCooperativeLaunchPolicy, journal []byte) error {
	directory, mode := paths.requestDir, uint16(02750)
	if path == paths.stagedRequest {
		directory, mode = paths.stagingDir, 02700
	}
	if path != paths.stagedRequest && path != paths.activeRequest {
		return errSoulCooperativeAuthority
	}
	if _, err := stage2aInstalledDirectoryIdentity(directory, p.MachineUID, p.Runner.GID, mode); err != nil {
		return errSoulCooperativeAuthority
	}
	dir, err := openStage2aAdminDirectory(directory, uint32(p.MachineUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0640 ||
		before.Uid != uint32(p.MachineUID) || before.Gid != uint32(p.Runner.GID) ||
		before.Nlink != 1 || before.Size != int64(len(journal)) ||
		checkDarwinACLs([]string{path}) != nil {
		return errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || !bytes.Equal(raw, journal) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return errSoulCooperativeAuthority
	}
	return nil
}
