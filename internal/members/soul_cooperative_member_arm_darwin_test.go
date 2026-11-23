//go:build darwin

package members

import (
	"strings"
	"testing"
	"time"
)

func TestSoulCooperativeArmExchangeHashesInnerBRow(t *testing.T) {
	now := time.Now().UTC()
	selector := "mb_" + strings.Repeat("a", 64)
	observation := "sha256:" + strings.Repeat("b", 64)
	selectors := stage2aNativeMemberSelectors{InstallationID: "install_1",
		StartID: "st_" + strings.Repeat("c", 24), PlanID: "plan_1",
		PlanDigest:               "sha256:" + strings.Repeat("d", 64),
		ReservationDigest:        "sha256:" + strings.Repeat("e", 64),
		AssignmentEnvelopeSHA256: "sha256:" + strings.Repeat("f", 64),
		AuthorityEnvelopeSHA256:  "sha256:" + strings.Repeat("1", 64),
		MemberSelectorsSHA256:    "sha256:" + strings.Repeat("2", 64)}
	child := soulKernelProcessSnapshot{PID: 411, StartSeconds: now.Unix(),
		StartMicros: 3, EffectiveUID: 309, PrimaryGroupGID: 309}
	arm := soulCooperativeBridgeArmV3{MemberID: "m_lead", MemberSelector: selector,
		RuntimeID: "runtime_1", ChildObservationEnvelopeSHA256: observation,
		BridgeUID: 310, AdapterPID: child.PID, AdapterUID: 309, AdapterGID: 309,
		AdapterStartSeconds: child.StartSeconds, AdapterStartMicros: child.StartMicros,
		RelayPeerRule:  "a-attested-live-direct-child-of-adapter-v1",
		RelayPeerState: "unobserved", ProviderIngress: "withheld-pending-per-peer-attestation",
		State: "armed", ArmedAt: now.Add(-time.Second).Format(time.RFC3339Nano)}
	armRaw, err := marshalStage2aReservationJCS(arm)
	if err != nil {
		t.Fatal(err)
	}
	request := soulCooperativeArmWireRequestV3{Kind: "bridge.member.arm.cooperative.v3.request",
		Selectors: selectors, MemberID: "m_lead", MemberSelector: selector,
		ObserveNonce: strings.Repeat("3", 64), ArmNonce: strings.Repeat("4", 64),
		ChildObservationEnvelopeSHA256: observation, BridgeArm: arm,
		BridgeArmReceiptSHA256: stage2aReservationSHA256(armRaw)}
	result := soulCooperativeArmWireResultV3{Kind: "bridge.member.arm.cooperative.v3.result",
		MemberID: "m_lead", MemberSelector: selector, ArmNonce: request.ArmNonce,
		BridgeArmReceiptSHA256: request.BridgeArmReceiptSHA256,
		State:                  "recorded-pending-aggregate-ready",
		ExpiresAt:              now.Add(5 * time.Second).Format(time.RFC3339Nano)}
	requestRaw, err := marshalStage2aReservationJCS(request)
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, err := marshalStage2aReservationJCS(result)
	if err != nil {
		t.Fatal(err)
	}
	pair := SoulCooperativeArmExchangeV3{ArmRequest: requestRaw, ArmResult: resultRaw}
	if _, _, err := verifySoulCooperativeArmExchangeV3(pair, selectors, "m_lead",
		selector, "runtime_1", observation, child, 310, 309, 309,
		now.Add(-2*time.Second), now); err != nil {
		t.Fatalf("exact B inner arm row refused: %v", err)
	}
	request.BridgeArmReceiptSHA256 = stage2aReservationSHA256(requestRaw)
	pair.ArmRequest, _ = marshalStage2aReservationJCS(request)
	if _, _, err := verifySoulCooperativeArmExchangeV3(pair, selectors, "m_lead",
		selector, "runtime_1", observation, child, 310, 309, 309,
		now.Add(-2*time.Second), now); err == nil {
		t.Fatal("hash of outer arm request accepted as inner arm receipt")
	}
}
