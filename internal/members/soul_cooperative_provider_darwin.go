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

const soulCooperativeProviderPurposeV3 = "agent-bot/soul-cooperative-provider/v3"

type SoulCooperativeProviderReplyV3 struct {
	Model                    string `json:"model"`
	RequestSHA256            string `json:"request_sha256"`
	ResponseText             string `json:"response_text"`
	ProviderConfigSHA256     string `json:"provider_config_sha256"`
	ConfigBase64URL          string `json:"config_base64url"`
	ExpiresAtMS              int64  `json:"expires_at_ms"`
	ReceiptEnvelopeBase64URL string `json:"receipt_envelope_base64url"`
	ReceiptSHA256            string `json:"receipt_sha256"`
}

type soulCooperativeProviderPayloadV3 struct {
	Contract             string `json:"contract"`
	Kind                 string `json:"kind"`
	SchemaVersion        int    `json:"schema_version"`
	ReservationSHA256    string `json:"reservation_sha256"`
	AttachSHA256         string `json:"attach_sha256"`
	HDescriptorDigest    string `json:"h_service_descriptor_digest"`
	InstallationID       string `json:"installation_id"`
	StartID              string `json:"start_id"`
	LaunchID             string `json:"launch_id"`
	PlanID               string `json:"plan_id"`
	PlanDigest           string `json:"plan_digest"`
	HQEpoch              string `json:"hq_epoch"`
	RunnerPID            int    `json:"runner_pid"`
	Model                string `json:"model"`
	RequestSHA256        string `json:"request_sha256"`
	ResponseSHA256       string `json:"response_sha256"`
	ProviderConfigSHA256 string `json:"provider_config_sha256"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
}

// CooperativeProviderV3 serves one fixed owner-reviewed response to paired
// HQ. HQ hosts the broker and provider connection; R gets no direct provider
// credentials or network permission. This authority has no protected B bind.
func (s *Stage2aService) CooperativeProviderV3(hqUID int, epoch string,
	q SoulCooperativeProviderRequestV3,
	paired func(string, func() error) error) (SoulCooperativeProviderReplyV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply SoulCooperativeProviderReplyV3
	if paired == nil || len(s.key) != ed25519.PrivateKeySize ||
		!validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		!stage2aPrefixedDigest.MatchString(q.AttachSHA256) {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || live.attachSHA256 != q.AttachSHA256 ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch ||
		live.installed.Policy.QualificationProvider == nil {
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
		p := installed.Policy
		if p.QualificationProvider == nil || q.Model != p.QualificationProvider.Model ||
			q.PromptSHA256 != p.QualificationProvider.RequestSHA256 {
			return errSoulCooperativeAuthority
		}
		config, hexDigest, e := stage2aProviderConfig(*p.QualificationProvider)
		if e != nil {
			return errSoulCooperativeAuthority
		}
		configDigest := "sha256:" + hexDigest
		reservationRaw, observedDigest, e := verifySoulCooperativeEnvelopeV3(live.envelope, pub)
		if e != nil || observedDigest != q.ReservationSHA256 {
			return errSoulCooperativeAuthority
		}
		var reservation soulCooperativeReservationPayloadV3
		if json.Unmarshal(reservationRaw, &reservation) != nil ||
			reservation.QualificationProvider == nil ||
			reservation.QualificationProvider.ConfigSHA256 != configDigest ||
			reservation.QualificationProvider.ConfigBase64URL != base64.RawURLEncoding.EncodeToString(config) ||
			reservation.MeasurementBinding.HDescriptorDigest != live.hDescriptorDigest ||
			reservation.Assignment.InstallationID != q.InstallationID ||
			reservation.Assignment.StartID != q.StartID || reservation.Assignment.LaunchID != q.LaunchID {
			return errSoulCooperativeAuthority
		}
		dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
		runner, e2 := observeSoulKernelProcess(live.runnerPID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
			!sameSoulKernelProcess(live.runner, runner) || !cooperativeProcessPair(p, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		store := installed.claimStore()
		dir, e := store.open()
		if e != nil {
			return e
		}
		defer dir.Close()
		lock, e := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
		if e != nil {
			return e
		}
		defer lock.Close()
		name := ".cooperative-provider-" + soulStartClaimName(q.InstallationID, q.StartID)
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			stage2aCheckSpentClaim(dir, cooperativeAttachedName(q.InstallationID, q.StartID),
				store.uid, store.gid) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil {
			return errSoulCooperativeAuthority
		}
		now := time.Now().UTC()
		expires := now.Add(15 * time.Second)
		payload := soulCooperativeProviderPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-provider",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			AttachSHA256: q.AttachSHA256, HDescriptorDigest: live.hDescriptorDigest,
			InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
			PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: epoch,
			RunnerPID: live.runnerPID, Model: q.Model, RequestSHA256: q.PromptSHA256,
			ResponseSHA256:       fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(p.QualificationProvider.ResponseText))),
			ProviderConfigSHA256: configDigest,
			IssuedAt:             now.Format(time.RFC3339Nano), ExpiresAt: expires.Format(time.RFC3339Nano)}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeProviderPurposeV3, pub, s.sign)
		if e != nil || len(envelope) > 8192 {
			return errSoulCooperativeAuthority
		}
		if e := spendStage2aAdminName(dir, name, store.uid, store.gid); e != nil {
			return e
		}
		if runner2, e := observeSoulKernelProcess(live.runnerPID); e != nil ||
			!sameSoulKernelProcess(runner, runner2) {
			return errSoulCooperativeAuthority
		}
		reply = SoulCooperativeProviderReplyV3{Model: q.Model, RequestSHA256: q.PromptSHA256,
			ResponseText:             p.QualificationProvider.ResponseText,
			ProviderConfigSHA256:     configDigest,
			ConfigBase64URL:          base64.RawURLEncoding.EncodeToString(config),
			ExpiresAtMS:              expires.UnixMilli(),
			ReceiptEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			ReceiptSHA256:            fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		return nil
	})
	if err != nil || !ran || reply.ReceiptSHA256 == "" {
		return SoulCooperativeProviderReplyV3{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
