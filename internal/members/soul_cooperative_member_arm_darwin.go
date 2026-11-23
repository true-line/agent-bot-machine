//go:build darwin

package members

import (
	"bytes"
	"time"
)

type soulCooperativeBridgeArmV3 struct {
	MemberID                       string `json:"member_id"`
	MemberSelector                 string `json:"member_selector"`
	RuntimeID                      string `json:"runtime_id"`
	ChildObservationEnvelopeSHA256 string `json:"child_observation_envelope_sha256"`
	BridgeUID                      int    `json:"bridge_uid"`
	AdapterPID                     int    `json:"adapter_pid"`
	AdapterUID                     int    `json:"adapter_uid"`
	AdapterGID                     int    `json:"adapter_gid"`
	AdapterStartSeconds            int64  `json:"adapter_start_seconds"`
	AdapterStartMicros             int32  `json:"adapter_start_micros"`
	RelayPeerRule                  string `json:"relay_peer_rule"`
	RelayPeerState                 string `json:"relay_peer_state"`
	ProviderIngress                string `json:"provider_ingress"`
	State                          string `json:"state"`
	ArmedAt                        string `json:"armed_at"`
}

type soulCooperativeArmWireRequestV3 struct {
	Kind                           string                       `json:"kind"`
	Selectors                      stage2aNativeMemberSelectors `json:"selectors"`
	MemberID                       string                       `json:"member_id"`
	MemberSelector                 string                       `json:"member_selector"`
	ObserveNonce                   string                       `json:"observe_nonce"`
	ArmNonce                       string                       `json:"arm_nonce"`
	ChildObservationEnvelopeSHA256 string                       `json:"child_observation_envelope_sha256"`
	BridgeArm                      soulCooperativeBridgeArmV3   `json:"bridge_arm"`
	BridgeArmReceiptSHA256         string                       `json:"bridge_arm_receipt_sha256"`
}

type soulCooperativeArmWireResultV3 struct {
	Kind                   string `json:"kind"`
	MemberID               string `json:"member_id"`
	MemberSelector         string `json:"member_selector"`
	ArmNonce               string `json:"arm_nonce"`
	BridgeArmReceiptSHA256 string `json:"bridge_arm_receipt_sha256"`
	State                  string `json:"state"`
	ExpiresAt              string `json:"expires_at"`
}

func verifySoulCooperativeArmExchangeV3(pair SoulCooperativeArmExchangeV3,
	selectors stage2aNativeMemberSelectors, memberID, memberSelector, runtimeID,
	observationSHA string, child soulKernelProcessSnapshot,
	bridgeUID, runnerUID, runnerGID int, observedAt, now time.Time,
) (string, time.Time, error) {
	var request soulCooperativeArmWireRequestV3
	var result soulCooperativeArmWireResultV3
	if stage2aDecodeExact(pair.ArmRequest, &request) != nil ||
		stage2aDecodeExact(pair.ArmResult, &result) != nil ||
		request.Kind != "bridge.member.arm.cooperative.v3.request" ||
		result.Kind != "bridge.member.arm.cooperative.v3.result" ||
		request.Selectors != selectors || request.MemberID != memberID ||
		request.MemberSelector != memberSelector ||
		request.ChildObservationEnvelopeSHA256 != observationSHA ||
		!stage2aLowerHex64(request.ObserveNonce) || !stage2aLowerHex64(request.ArmNonce) ||
		result.MemberID != memberID || result.MemberSelector != memberSelector ||
		result.ArmNonce != request.ArmNonce ||
		result.BridgeArmReceiptSHA256 != request.BridgeArmReceiptSHA256 ||
		result.State != "recorded-pending-aggregate-ready" {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	arm := request.BridgeArm
	if arm.MemberID != memberID || arm.MemberSelector != memberSelector ||
		arm.RuntimeID != runtimeID || arm.ChildObservationEnvelopeSHA256 != observationSHA ||
		arm.BridgeUID != bridgeUID || arm.AdapterPID != child.PID ||
		arm.AdapterUID != runnerUID || arm.AdapterGID != runnerGID ||
		arm.AdapterStartSeconds != child.StartSeconds ||
		arm.AdapterStartMicros != child.StartMicros ||
		arm.RelayPeerRule != "a-attested-live-direct-child-of-adapter-v1" ||
		arm.RelayPeerState != "unobserved" ||
		arm.ProviderIngress != "withheld-pending-per-peer-attestation" ||
		arm.State != "armed" {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	armRaw, err := marshalStage2aReservationJCS(arm)
	armAt, e1 := time.Parse(time.RFC3339Nano, arm.ArmedAt)
	ackExpires, e2 := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || stage2aReservationSHA256(armRaw) != request.BridgeArmReceiptSHA256 ||
		e1 != nil || e2 != nil || armAt.After(now) || armAt.Before(observedAt) ||
		!now.Before(ackExpires) {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	canonicalRequest, err := marshalStage2aReservationJCS(request)
	if err != nil || !bytes.Equal(canonicalRequest, pair.ArmRequest) {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	canonicalResult, err := marshalStage2aReservationJCS(result)
	if err != nil || !bytes.Equal(canonicalResult, pair.ArmResult) {
		return "", time.Time{}, errSoulCooperativeAuthority
	}
	return request.BridgeArmReceiptSHA256, ackExpires, nil
}
