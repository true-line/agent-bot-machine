//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

// Provider consumes exactly one owner-reviewed local qualification response.
// It is a fixture result, not physical provider traffic or T03 evidence.
func (s *Stage2aService) Provider(hqUID int, epoch string, q Stage2aProviderRequest) (Stage2aProviderReply, error) {
	var reply Stage2aProviderReply
	live, err := s.Live(hqUID, epoch, q.Stage2aStopRequest)
	if err != nil || live.Phase != "finalized" || live.BindReceiptSHA256 != q.BindReceiptSHA256 ||
		live.FinalizedLiveExpiresAt <= time.Now().UnixMilli() || live.RunnerPID <= 1 {
		return reply, errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch ||
		!validStage2aStopRequest(q.Stage2aStopRequest) || !stage2aMatchesStopSelectors(s.active[q.ReservationSHA256], q.Stage2aStopRequest, hqUID) {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	p, raw, err := loadStage2aInstalledPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest ||
		q.Model != p.BridgeQualification.Model || q.PromptSHA256 != p.BridgeQualification.RequestSHA256 ||
		q.BindReceiptSHA256 != r.bindReceiptSHA256 || len(r.finalizationEnvelope) == 0 ||
		!stage2aProviderRunnerLive(live, r.runnerPID, func(pid int) error {
			return checkStage2aGrantedRoleProcess(pid, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess)
		}) ||
		r.bridgePID <= 1 || checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	config, digest, err := stage2aProviderConfig(p.BridgeQualification)
	if err != nil {
		return reply, err
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
	name := ".stage2a-provider-" + soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil ||
		stage2aCheckFinalizationFile(dir, ".stage2a-b-final-"+soulStartClaimName(q.InstallationID, q.StartID)+".json", store.uid, store.gid, r.finalizationEnvelope) != nil ||
		requireUnspentStage2aReservation(dir, name) != nil ||
		time.Now().UnixMilli() >= live.FinalizedLiveExpiresAt {
		return reply, errStage2aReservationAuthority
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return reply, err
	}
	return Stage2aProviderReply{Model: q.Model, RequestSHA256: q.PromptSHA256,
		ResponseText: p.BridgeQualification.ResponseText, ProviderConfigSHA256: digest,
		ConfigBase64URL: base64.RawURLEncoding.EncodeToString(config), ExpiresAtMS: live.FinalizedLiveExpiresAt}, nil
}

// The qualification fixture cannot be spent while B is finalized but the
// assigned Soul runner has not reached its own live, kernel-observed grant.
func stage2aProviderRunnerLive(live Stage2aLiveReply, runnerPID int, checkRunner func(int) error) bool {
	return live.Phase == "finalized" && live.RunnerPID > 1 &&
		runnerPID == live.RunnerPID && checkRunner(runnerPID) == nil
}
