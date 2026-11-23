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
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeAbortPurposeV3 = "agent-bot/soul-cooperative-abort/v3"

type soulCooperativeAbortPayloadV3 struct {
	Contract              string `json:"contract"`
	Kind                  string `json:"kind"`
	SchemaVersion         int    `json:"schema_version"`
	ReservationSHA256     string `json:"reservation_sha256"`
	CancelSHA256          string `json:"cancel_sha256"`
	HDescriptorDigest     string `json:"h_service_descriptor_digest"`
	InstallationID        string `json:"installation_id"`
	StartID               string `json:"start_id"`
	LaunchID              string `json:"launch_id"`
	PlanID                string `json:"plan_id"`
	PlanDigest            string `json:"plan_digest"`
	HQEpoch               string `json:"hq_epoch"`
	RunnerUID             int    `json:"runner_uid"`
	RunnerUIDIdle         bool   `json:"runner_uid_idle"`
	BridgeUID             int    `json:"bridge_uid"`
	BridgeLauncherPID     int    `json:"bridge_launcher_pid"`
	BridgeNativePID       int    `json:"bridge_native_pid"`
	BridgeUIDIdle         bool   `json:"bridge_uid_idle"`
	BridgeEndpointsAbsent bool   `json:"bridge_endpoints_absent"`
	AbortedAt             string `json:"aborted_at"`
}

// AbortCooperativePreAttach contains a failed start before H has attached R.
// It cannot produce a completed-run claim or replay the spent start ID.
func (s *Stage2aService) AbortCooperativePreAttach(hqUID int, epoch string,
	q Stage2aStopRequest, paired func(string, func() error) error) (Stage2aStopReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aStopReply
	if paired == nil || len(s.key) != ed25519.PrivateKeySize ||
		!validStage2aStopRequest(q) || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || live.attached || live.installed.Policy.HQUID != hqUID ||
		live.request.InstallationID != q.InstallationID || live.request.StartID != q.StartID ||
		live.request.LaunchID != q.LaunchID || live.request.PlanDigest != q.PlanDigest ||
		live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, _, e := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if e != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil {
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
		// Remove the only WatchPaths entry before publishing cancel. The
		// dispatcher already holds FD3; a later launchd wake sees no request.
		if _, e := os.Lstat(paths.activeRequest); errors.Is(e, os.ErrNotExist) {
			if e := unix.RenamexNp(paths.request, paths.activeRequest, unix.RENAME_EXCL); e != nil {
				return errSoulCooperativeAuthority
			}
			if e := syncUpgradeDir(paths.requestDir); e != nil {
				return e
			}
		} else if e != nil {
			return errSoulCooperativeAuthority
		}
		cancelSHA, e := publishSoulCooperativeCancel(paths, live, pub, s.sign)
		if e != nil {
			return e
		}
		p := installed.Policy
		idle := func() bool {
			return soulCooperativeGuestRolesIdle(p) && soulCooperativeGuestEndpointsAbsent(p, q.StartID)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && !idle() {
			time.Sleep(100 * time.Millisecond)
		}
		if !idle() {
			return errSoulCooperativeAuthority
		}
		time.Sleep(100 * time.Millisecond)
		if !idle() {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeAbortPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-abort",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256, CancelSHA256: cancelSHA,
			HDescriptorDigest: live.hDescriptorDigest, InstallationID: q.InstallationID,
			StartID: q.StartID, LaunchID: q.LaunchID, PlanID: q.PlanID,
			PlanDigest: q.PlanDigest, HQEpoch: epoch, RunnerUID: p.Runner.UID,
			RunnerUIDIdle: true, BridgeUID: p.Bridge.UID,
			BridgeLauncherPID: live.bridgePID, BridgeNativePID: live.bridgeNativePID,
			BridgeUIDIdle: true, BridgeEndpointsAbsent: true, AbortedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeAbortPurposeV3, pub, s.sign)
		if e != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, e := store.open()
		if e != nil {
			return e
		}
		defer dir.Close()
		name := ".cooperative-abort-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
		if e := commitStage2aReservation(dir, name, envelope); e != nil {
			return e
		}
		if e := releaseSoulCooperativeStart(store, live.request, func() (bool, error) {
			return idle(), nil
		}); e != nil {
			return e
		}
		if e := revokeCooperativeBProof(p, q.StartID, live.bridgeProofSHA); e != nil {
			return e
		}
		if e := os.Remove(paths.activeRequest); e != nil {
			return e
		}
		if e := os.Remove(paths.outcome); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e := os.Remove(paths.cancel); e != nil {
			return e
		}
		completion := filepath.Join(paths.completionDir, "completion.json")
		if _, e := os.Lstat(completion); e == nil {
			if e := os.Remove(completion); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
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
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aStopReply{}, errSoulCooperativeAuthority
	}
	delete(s.cooperativeActive, q.ReservationSHA256)
	return reply, nil
}
