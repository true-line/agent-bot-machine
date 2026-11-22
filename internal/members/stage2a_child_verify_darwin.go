//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

func verifyStage2aSignedChildPayload(envelopeBase64URL, digest, purpose string,
	pub ed25519.PublicKey) ([]byte, error) {
	invalid := errors.New("invalid Machine-signed protected child envelope")
	raw, err := decodeStage2aRoleBase64(envelopeBase64URL, 8192)
	if err != nil || stage2aReservationSHA256(raw) != digest {
		return nil, invalid
	}
	var envelope stage2aSignedReservation
	if decodeStage2aRoleJSON(raw, &envelope) != nil || envelope.SchemaVersion != 1 ||
		envelope.Purpose != purpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(pub) {
		return nil, invalid
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, invalid
	}
	payload, err := decodeStage2aRoleBase64(envelope.PayloadBase64URL, 4096)
	if err != nil || stage2aReservationSHA256(payload) != envelope.PayloadSHA256 {
		return nil, invalid
	}
	signature, err := decodeStage2aRoleBase64(envelope.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(pub) != ed25519.PublicKeySize ||
		!ed25519.Verify(pub, append([]byte(purpose+"\x00"), payload...), signature) {
		return nil, invalid
	}
	return payload, nil
}

func verifyStage2aChildStartReceipt(reply Stage2aChildReadyReply, in Stage2aRoleInvocation,
	grantSHA256 string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, now time.Time) (Stage2aChildStartPayload, error) {
	var payload Stage2aChildStartPayload
	invalid := errors.New("invalid Machine protected child start receipt")
	raw, err := verifyStage2aSignedChildPayload(reply.EnvelopeBase64URL, reply.SHA256,
		Stage2aChildStartPurpose, pub)
	if err != nil || decodeStage2aRoleJSON(raw, &payload) != nil {
		return Stage2aChildStartPayload{}, invalid
	}
	canonical, err := marshalStage2aReservationJCS(payload)
	if err != nil || !bytes.Equal(raw, canonical) || in.ChildExec == nil {
		return Stage2aChildStartPayload{}, invalid
	}
	environmentRaw, err := marshalStage2aReservationJCS(in.ChildExec.Environment)
	if err != nil || payload.Schema != "agent-bot-machine/stage2a-child-start/v1" ||
		payload.ReservationSHA256 != in.ChildExec.ReservationSHA256 ||
		payload.FinalizationSHA256 != in.ChildExec.FinalizationSHA256 ||
		payload.BindReceiptSHA256 != in.ChildExec.BindReceiptSHA256 ||
		payload.Runner != in.ChildExec.Runner || payload.Bridge != in.ChildExec.Bridge ||
		payload.GrantSHA256 != grantSHA256 ||
		payload.InstallationID != in.Request.InstallationID ||
		payload.StartID != in.Request.StartID || payload.LaunchID != in.Start.LaunchID ||
		payload.PlanID != in.Start.PlanID || payload.PlanDigest != in.Start.PlanDigest ||
		payload.HQEpoch != in.Request.HQEpoch ||
		payload.ChildLauncher != stage2aLiveRoleIdentity(launcher) ||
		payload.Child != stage2aLiveRoleIdentity(child) ||
		payload.Executable != in.ChildExec.Executable ||
		payload.ExecutableSHA256 != in.ChildExec.ExecutableSHA256 ||
		payload.SandboxPath != in.ChildExec.SandboxPath ||
		payload.SandboxSHA256 != in.ChildExec.SandboxSHA256 ||
		payload.RelaySocket != in.ChildExec.RelaySocket ||
		payload.EnvironmentSHA256 != stage2aReservationSHA256(environmentRaw) ||
		payload.ExpiresAtMS != reply.ExpiresAtMS ||
		payload.ExpiresAtMS <= now.UnixMilli() || payload.StartedAtMS > now.UnixMilli() ||
		payload.ExpiresAtMS-payload.StartedAtMS > stage2aLiveLease.Milliseconds() {
		return Stage2aChildStartPayload{}, invalid
	}
	return payload, nil
}

func verifyStage2aChildLiveLease(reply Stage2aLiveReply, challenge string,
	in Stage2aRoleInvocation, receiptSHA256 string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, after uint64, now time.Time) (Stage2aLiveLeasePayload, error) {
	var payload Stage2aLiveLeasePayload
	invalid := errors.New("invalid Machine protected child Live lease")
	raw, err := verifyStage2aSignedChildPayload(reply.LeaseEnvelopeBase64URL,
		reply.LeaseSHA256, Stage2aLiveLeasePurpose, pub)
	if err != nil || decodeStage2aRoleJSON(raw, &payload) != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	canonical, err := marshalStage2aReservationJCS(payload)
	if err != nil || !bytes.Equal(raw, canonical) || in.ChildExec == nil ||
		payload.Schema != "agent-bot-machine/stage2a-live-lease/v1" ||
		payload.InstallationID != in.Request.InstallationID ||
		payload.StartID != in.Request.StartID || payload.LaunchID != in.Start.LaunchID ||
		payload.PlanID != in.Start.PlanID || payload.PlanDigest != in.Start.PlanDigest ||
		payload.HQEpoch != in.Request.HQEpoch || payload.Challenge != challenge ||
		payload.ReservationSHA256 != in.ChildExec.ReservationSHA256 ||
		payload.FinalizationSHA256 != in.ChildExec.FinalizationSHA256 ||
		payload.BindReceiptSHA256 != in.ChildExec.BindReceiptSHA256 ||
		payload.Runner != in.ChildExec.Runner || payload.Bridge != in.ChildExec.Bridge ||
		payload.ChildLauncher == nil || payload.Child == nil ||
		*payload.ChildLauncher != stage2aLiveRoleIdentity(launcher) ||
		*payload.Child != stage2aLiveRoleIdentity(child) ||
		payload.ChildReceiptSHA256 != receiptSHA256 ||
		payload.Sequence <= after || payload.Sequence != reply.LeaseSequence ||
		payload.ExpiresAtMS <= now.UnixMilli() || payload.IssuedAtMS > now.UnixMilli() ||
		payload.ExpiresAtMS-payload.IssuedAtMS > stage2aLiveLease.Milliseconds() {
		return Stage2aLiveLeasePayload{}, invalid
	}
	return payload, nil
}
