package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aCandidateGrantPurposeV3 = "agent-bot/stage2a-candidate-live-grant/v3\x00"

type stage2aCandidateGrantV3 struct {
	HQUID       int                                    `json:"hq_uid"`
	Selector    Stage2aReserveRequest                  `json:"selector"`
	Attempt     stage2aQualificationCandidateAttemptV3 `json:"attempt"`
	RDigest     string                                 `json:"r_inventory_digest"`
	PackageSHA  string                                 `json:"candidate_package_sha256"`
	ManifestSHA string                                 `json:"candidate_manifest_sha256"`
	Nonce       [32]byte                               `json:"nonce"`
	DaemonPID   int                                    `json:"daemon_pid"`
	StartedSec  int64                                  `json:"daemon_start_seconds"`
	StartedUsec int32                                  `json:"daemon_start_microseconds"`
	ExpiresAt   time.Time                              `json:"expires_at"`
}

type stage2aSignedCandidateGrantV3 struct {
	Grant     stage2aCandidateGrantV3 `json:"grant"`
	Signature []byte                  `json:"signature"`
}

func stage2aCandidateGrantPreimageV3(grant stage2aCandidateGrantV3) []byte {
	raw, _ := json.Marshal(grant)
	return append([]byte(stage2aCandidateGrantPurposeV3), raw...)
}

func verifyStage2aCandidateLiveGrantV3(signed *stage2aSignedCandidateGrantV3, uid int, selector Stage2aReserveRequest,
	parent soulKernelProcessSnapshot, key ed25519.PublicKey, now time.Time) error {
	if signed == nil || len(key) != ed25519.PublicKeySize {
		return errStage2aReservationAuthority
	}
	g := signed.Grant
	if g.HQUID != uid || g.Selector != selector || g.Nonce == [32]byte{} ||
		g.DaemonPID <= 1 || g.DaemonPID != parent.PID || g.StartedSec <= 0 ||
		g.StartedSec != parent.StartSeconds || g.StartedUsec != parent.StartMicros ||
		parent.RealUID != uint32(os.Getuid()) || parent.EffectiveUID != uint32(os.Geteuid()) ||
		!now.Before(g.ExpiresAt) || !ed25519.Verify(key, stage2aCandidateGrantPreimageV3(g), signed.Signature) {
		return errStage2aReservationAuthority
	}
	return nil
}

type stage2aCandidateGrantSlotV3 struct {
	grant stage2aCandidateGrantV3
	spent bool
}

// Admit a locally reviewed candidate once before installing its ephemeral
// start grant. The callers are A-owned activation plumbing, never HQ.
func (s *Stage2aService) beginStage2aCandidateRunV3(uid int, selector Stage2aReserveRequest,
	saved Saved, approval Approval, owner, state string, base stage2aReservationEvidenceV3, guard upgradePairGuard,
	checkDesignatedHost, checkInstalledQ func(QualificationRequest) error) error {
	raw, err := json.Marshal(selector)
	if err != nil {
		return err
	}
	if _, err := ParseStage2aReserveRequest(raw); err != nil || uid != base.base.hqUID ||
		selector.HQEpoch != base.base.binding.HQEpoch || selector.InstallationID != base.base.binding.InstallationID ||
		selector.PlanDigest != base.base.binding.InstalledPlanDigest {
		return errStage2aReservationAuthority
	}
	preparedStart, err := stage2aQualificationPreparedStart(selector.InstallationID,
		base.base.binding.InstalledPlanDigest)
	if err != nil || preparedStart != "" && selector.StartID != preparedStart {
		return errStage2aReservationAuthority
	}
	authority, spent, err := beginStage2aApprovedCandidateV3(saved, approval, owner, state, uid, base, guard, checkDesignatedHost, checkInstalledQ)
	if err != nil {
		return err
	}
	return s.registerStage2aCandidateRunV3(uid, selector, authority, stage2aReservationSHA256(spent))
}

// The local Q begin path calls this only after successfully creating a new
// immutable spent attempt. It has no paired HQ RPC entry point.
func (s *Stage2aService) registerStage2aCandidateRunV3(uid int, selector Stage2aReserveRequest,
	a stage2aQualificationCandidateAuthorityV3, spentDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	selectorRaw, err := json.Marshal(selector)
	if err != nil {
		return err
	}
	if _, err := ParseStage2aReserveRequest(selectorRaw); err != nil || len(s.key) != ed25519.PrivateKeySize ||
		!s.key.Public().(ed25519.PublicKey).Equal(a.base.base.enrolledAdminKey) ||
		uid != a.base.base.hqUID || selector.HQEpoch != a.base.base.binding.HQEpoch ||
		selector.InstallationID != a.approvedInstallationID || selector.PlanDigest != a.approvedInstalledPlanDigest {
		return errStage2aReservationAuthority
	}
	attempt, err := stage2aCandidateAttemptV3(a, now)
	if err != nil || attempt.AttemptReceiptSHA256 != spentDigest || !a.base.r.verified || stage2aRecheckVerifiedDomainV3(a.base.r) != nil {
		return errStage2aReservationAuthority
	}
	adapter, err := stage2aCandidateAdapterV3(a)
	if err != nil {
		return err
	}
	parent, err := observeSoulKernelProcess(os.Getpid())
	if err != nil {
		return err
	}
	expires, err := time.Parse(approvalTime, attempt.ApprovalExpiresAt)
	if err != nil {
		return err
	}
	g := stage2aCandidateGrantV3{HQUID: uid, Selector: selector, Attempt: attempt,
		RDigest: a.base.r.ref.InventoryDigest, PackageSHA: adapter.PackageSHA256, ManifestSHA: adapter.CandidateManifestSHA256, DaemonPID: parent.PID, StartedSec: parent.StartSeconds,
		StartedUsec: parent.StartMicros, ExpiresAt: expires}
	if _, err := rand.Read(g.Nonce[:]); err != nil {
		return err
	}
	// Fence activation separately from signing. Even if a future caller
	// presents the old spent attempt after restart, it cannot rearm.
	dir, err := openStage2aAdminDirectory(filepath.Join(a.stateDirectory, "qualification-attempts"), uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer dir.Close()
	if checkStage2aReservationFile(int(dir.Fd()), uint32(os.Getuid()), uint32(os.Getgid()), unix.S_IFDIR|0700) != nil {
		return errStage2aReservationAuthority
	}
	if err := spendStage2aAdminName(dir, ".stage2a-live-grant-"+attempt.ApprovalPlanDigest, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		return err
	}
	return s.candidateGrantsV3.add(g, now)
}

type stage2aCandidateGrantRegistryV3 map[string]stage2aCandidateGrantSlotV3

func (r stage2aCandidateGrantRegistryV3) add(g stage2aCandidateGrantV3, now time.Time) error {
	for k, old := range r {
		if !now.Before(old.grant.ExpiresAt) {
			delete(r, k)
		}
	}
	id := g.Attempt.ApprovalPlanDigest
	if _, seen := r[id]; seen || r == nil || len(r) >= 128 || !now.Before(g.ExpiresAt) {
		return errStage2aReservationAuthority
	}
	r[id] = stage2aCandidateGrantSlotV3{grant: g}
	return nil
}

// The service holds its mutex over consume and worker dispatch. Mark spent
// before sending the signed capability, including when the worker fails.
func (r stage2aCandidateGrantRegistryV3) consume(uid int, selector Stage2aReserveRequest,
	key ed25519.PrivateKey, now time.Time) (*stage2aSignedCandidateGrantV3, error) {
	var id string
	for k, slot := range r {
		if slot.grant.HQUID == uid && slot.grant.Selector == selector && now.Before(slot.grant.ExpiresAt) {
			if id != "" || slot.spent {
				return nil, errStage2aReservationAuthority
			}
			id = k
		}
	}
	if id == "" {
		return nil, nil
	}
	slot := r[id]
	slot.spent = true
	r[id] = slot
	g := slot.grant
	return &stage2aSignedCandidateGrantV3{Grant: g, Signature: ed25519.Sign(key, stage2aCandidateGrantPreimageV3(g))}, nil
}
