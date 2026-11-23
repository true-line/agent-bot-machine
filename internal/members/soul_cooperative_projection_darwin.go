//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const soulCooperativeProjectionPurposeV3 = "agent-bot/soul-cooperative-launch-projection/v3"

type soulCooperativeProjectionPayloadV3 struct {
	Contract               string                `json:"contract"`
	Kind                   string                `json:"kind"`
	SchemaVersion          int                   `json:"schema_version"`
	ReservationSHA256      string                `json:"reservation_sha256"`
	HDescriptorDigest      string                `json:"h_service_descriptor_digest"`
	InstallationID         string                `json:"installation_id"`
	StartID                string                `json:"start_id"`
	LaunchID               string                `json:"launch_id"`
	LaunchInputMeasurement string                `json:"launch_input_measurement"`
	HostProjection         Stage2aHostProjection `json:"host_projection"`
	SelectedCommand        string                `json:"selected_command"`
	Argv                   []string              `json:"argv"`
	Environment            map[string]string     `json:"environment"`
	EffectiveConfig        map[string]any        `json:"effective_config"`
	ComponentDigests       map[string]string     `json:"component_digests"`
}

// CooperativeLaunchProjection gives HQ A-authenticated selected launch
// inputs; it never accepts the R FD3 object's self-reported projection.
func (s *Stage2aService) CooperativeLaunchProjection(hqUID int, epoch string,
	q Stage2aStopRequest, paired func(string, func() error) error) (Stage2aReserveReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aReserveReply
	if paired == nil || !validStage2aStopRequest(q) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.installed.Policy.HQUID != hqUID {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		installed, r, e := loadSoulCooperativeInstalledV3(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
		if e != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil || stage2aRecheckVerifiedDomainV3(live.h) != nil {
			return errSoulCooperativeAuthority
		}
		var receipt Receipt
		if json.Unmarshal(installed.RootReceipt, &receipt) != nil || receipt.PlanID != q.PlanID ||
			receipt.PlanDigest != q.PlanDigest {
			return errSoulCooperativeAuthority
		}
		input := installed.Policy.LaunchInputs
		if input == nil {
			return errSoulCooperativeAuthority
		}
		digest, _, e := Stage2aLaunchInputDigest(*input)
		if e != nil || digest != installed.Policy.LaunchInputMeasurement {
			return errSoulCooperativeAuthority
		}
		payload := soulCooperativeProjectionPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-launch-projection",
			SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256,
			HDescriptorDigest: live.hDescriptorDigest, InstallationID: q.InstallationID, StartID: q.StartID,
			LaunchID: q.LaunchID, LaunchInputMeasurement: digest,
			HostProjection: input.HostProjection, SelectedCommand: input.SelectedCommand,
			Argv: input.Argv, Environment: input.Environment, EffectiveConfig: input.EffectiveConfig,
			ComponentDigests: input.ComponentDigests}
		envelope, e := signStage2aEnvelope(payload, 3, soulCooperativeProjectionPurposeV3,
			s.key.Public().(ed25519.PublicKey), s.sign)
		if e != nil || len(envelope) > 40<<10 {
			return errSoulCooperativeAuthority
		}
		reply = Stage2aReserveReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(envelope))}
		return nil
	})
	if err != nil {
		return Stage2aReserveReply{}, err
	}
	if !ran || reply.SHA256 == "" {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
