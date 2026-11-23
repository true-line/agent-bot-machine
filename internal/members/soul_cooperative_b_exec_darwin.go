//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const soulCooperativeBExecPurposeV3 = "agent-bot/soul-cooperative-b-exec/v3"

type soulCooperativeBExecGrantV3 struct {
	Contract               string `json:"contract"`
	Kind                   string `json:"kind"`
	SchemaVersion          int    `json:"schema_version"`
	ReservationSHA256      string `json:"reservation_sha256"`
	BridgeAssignmentSHA256 string `json:"bridge_assignment_sha256"`
	InstallationID         string `json:"installation_id"`
	StartID                string `json:"start_id"`
	LaunchID               string `json:"launch_id"`
	HQEpoch                string `json:"hq_epoch"`
	BridgeUID              int    `json:"bridge_uid"`
	BridgeGID              int    `json:"bridge_gid"`
	MachineUID             int    `json:"machine_uid"`
	PID                    int    `json:"pid"`
	PIDStartSec            int64  `json:"pid_start_sec"`
	PIDStartUsec           int32  `json:"pid_start_usec"`
	Nonce                  string `json:"nonce"`
	ProofSHA256            string `json:"proof_sha256"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	reservationEnvelope    []byte
	bridgeEnvelope         []byte
}

func cooperativeBRoleProcess(pid int, p SoulCooperativeLaunchPolicy) (soulKernelProcessSnapshot, error) {
	if p.Bridge == nil {
		return soulKernelProcessSnapshot{}, errSoulCooperativeAuthority
	}
	observed, err := observeSoulProcess(pid, SoulLauncher,
		[]string{SoulLauncher, "cooperative-soul-bridge"})
	uid, gid := uint32(p.Bridge.UID), uint32(p.Bridge.GID)
	if err != nil || observed.Kernel.RealUID != uid || observed.Kernel.EffectiveUID != uid ||
		observed.Kernel.SavedUID != uid || observed.Kernel.RealGID != gid ||
		observed.Kernel.PrimaryGroupGID != gid || observed.Kernel.SavedGID != gid {
		return soulKernelProcessSnapshot{}, errSoulCooperativeAuthority
	}
	return observed.Kernel, nil
}

// HQ relays a challenge from the fixed B role. A checks that exact live
// process, spends an A-only B launch claim, and leaves the proof in A:B
// custody. HQ receives no proof bytes and cannot select an executable.
func (s *Stage2aService) CooperativeBExec(hqUID int, epoch string,
	q SoulCooperativeBExecRequestV3, paired func(string, func() error) error,
) (SoulCooperativeBExecReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeBExecReplyV3
	rawQ, _ := json.Marshal(q)
	if _, err := ParseSoulCooperativeBExecRequestV3(rawQ); err != nil || paired == nil ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || live.bridgePID != 0 || live.installed.Policy.HQUID != hqUID ||
		live.request.InstallationID != q.InstallationID || live.request.StartID != q.StartID ||
		live.request.LaunchID != q.LaunchID || live.request.HQEpoch != epoch ||
		live.digest != q.ReservationSHA256 || len(live.bridgeEnvelope) == 0 ||
		stage2aReservationSHA256(live.bridgeEnvelope) != live.bridgeSHA {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		p := live.installed.Policy
		if time.Since(live.issuedAt) > 30*time.Second ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		current, _, err := loadSoulCooperativeInstalledV3(s.key.Public().(ed25519.PublicKey),
			hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(current.RootReceipt, live.installed.RootReceipt) {
			return errSoulCooperativeAuthority
		}
		process, err := cooperativeBRoleProcess(q.PID, p)
		if err != nil {
			return err
		}
		store := current.claimStore()
		dir, err := store.open()
		if err != nil {
			return err
		}
		defer dir.Close()
		lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
		if err != nil {
			return err
		}
		defer lock.Close()
		name := ".cooperative-b-exec-" + soulStartClaimName(q.InstallationID, q.StartID)
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil {
			return errSoulCooperativeAuthority
		}
		var proof [32]byte
		if _, err := rand.Read(proof[:]); err != nil {
			return errSoulCooperativeAuthority
		}
		defer clear(proof[:])
		if publishCooperativeBProof(p, q.StartID, proof[:]) != nil {
			return errSoulCooperativeAuthority
		}
		if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
			return errSoulCooperativeAuthority
		}
		issued := time.Now().UTC()
		expires := live.issuedAt.Add(30 * time.Second)
		if !issued.Before(expires) {
			return errSoulCooperativeAuthority
		}
		grant := soulCooperativeBExecGrantV3{Contract: "machine/v3", Kind: "soul-cooperative-b-exec",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			BridgeAssignmentSHA256: live.bridgeSHA, InstallationID: q.InstallationID,
			StartID: q.StartID, LaunchID: q.LaunchID, HQEpoch: epoch,
			BridgeUID: p.Bridge.UID, BridgeGID: p.Bridge.GID, MachineUID: p.MachineUID,
			PID: q.PID, PIDStartSec: process.StartSeconds, PIDStartUsec: process.StartMicros,
			Nonce: q.Nonce, ProofSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(proof[:])),
			IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
		envelope, err := signStage2aEnvelope(grant, 3, soulCooperativeBExecPurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if err != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		observedAgain, err := cooperativeBRoleProcess(q.PID, p)
		if err != nil || !sameSoulKernelProcess(process, observedAgain) || !time.Now().Before(expires) {
			return errSoulCooperativeAuthority
		}
		live.bridgePID, live.bridgeProcess = q.PID, process
		live.bridgeProof = proof
		live.bridgeProofSHA = grant.ProofSHA256
		live.bridgeGrantNonce = grant.Nonce
		reply = SoulCooperativeBExecReplyV3{
			EnvelopeBase64URL:                 base64.RawURLEncoding.EncodeToString(envelope),
			SHA256:                            stage2aReservationSHA256(envelope),
			ReservationEnvelopeBase64URL:      base64.RawURLEncoding.EncodeToString(live.envelope),
			BridgeAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(live.bridgeEnvelope)}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return SoulCooperativeBExecReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
