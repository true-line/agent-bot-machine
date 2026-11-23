//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const soulCooperativeLivePurposeV3 = "agent-bot/soul-cooperative-live/v3"

type soulCooperativeLivePayloadV3 struct {
	Contract          string `json:"contract"`
	Kind              string `json:"kind"`
	SchemaVersion     int    `json:"schema_version"`
	ReservationSHA256 string `json:"reservation_sha256"`
	AttachSHA256      string `json:"attach_sha256"`
	HDescriptorDigest string `json:"h_service_descriptor_digest"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	HQEpoch           string `json:"hq_epoch"`
	RunnerPID         int    `json:"runner_pid"`
	ObservedAt        string `json:"observed_at"`
	ExpiresAt         string `json:"expires_at"`
}

func (s *Stage2aService) CooperativeLiveV3(hqUID int, epoch string,
	q SoulCooperativeLiveRequestV3,
	paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	if paired == nil || len(s.key) != ed25519.PrivateKeySize ||
		!validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || live.attachSHA256 != q.AttachSHA256 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, e := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if e != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil ||
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
			return errSoulCooperativeAuthority
		}
		dispatchPID, e := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
		if e != nil || dispatchPID != live.dispatcherPID {
			return errSoulCooperativeAuthority
		}
		dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
		runner, e2 := observeSoulKernelProcess(live.runnerPID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
			!sameSoulKernelProcess(live.runner, runner) ||
			!cooperativeProcessPair(installed.Policy, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, e := store.open()
		if e != nil {
			return e
		}
		defer dir.Close()
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
				store.uid, store.gid) != nil {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		payload := soulCooperativeLivePayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-live",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			AttachSHA256: q.AttachSHA256, HDescriptorDigest: live.hDescriptorDigest,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			HQEpoch: epoch, RunnerPID: live.runnerPID,
			ObservedAt: now.Format(time.RFC3339Nano),
			ExpiresAt:  now.Add(5 * time.Second).Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeLivePurposeV3, pub, s.sign)
		if e != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
