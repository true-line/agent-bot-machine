//go:build darwin

package members

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemberReadyRequiresExactBArmAndPendingAck(t *testing.T) {
	now := time.Now().UTC()
	memberID := "m_lead"
	selector := "mb_" + strings.Repeat("a", 64)
	observation := "sha256:" + strings.Repeat("b", 64)
	child := soulKernelProcessSnapshot{PID: 402, EffectiveUID: 320,
		PrimaryGroupGID: 320, StartSeconds: 1000, StartMicros: 2}
	selectors := stage2aNativeMemberSelectors{InstallationID: "inst_0123456789abcdef",
		StartID: "st_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("c", 64), ReservationDigest: "sha256:" + strings.Repeat("d", 64),
		AssignmentEnvelopeSHA256: "sha256:" + strings.Repeat("e", 64),
		AuthorityEnvelopeSHA256:  "sha256:" + strings.Repeat("f", 64),
		MemberSelectorsSHA256:    "sha256:" + strings.Repeat("1", 64)}
	arm := stage2aMemberBridgeArm{MemberID: memberID, MemberSelector: selector,
		RuntimeID: "runtime_lead", ChildObservationEnvelopeSHA256: observation,
		BridgeUID: 321, AdapterPID: child.PID, AdapterUID: 320, AdapterGID: 320,
		AdapterStartSeconds: child.StartSeconds, AdapterStartMicros: child.StartMicros,
		RelayPeerRule: "a-attested-live-direct-child-of-adapter-v1", RelayPeerState: "unobserved",
		ProviderIngress: "withheld-pending-per-peer-attestation", State: "armed",
		ArmedAt: now.Format(time.RFC3339Nano)}
	armRaw, err := marshalStage2aReservationJCS(arm)
	if err != nil {
		t.Fatal(err)
	}
	request := stage2aMemberArmWireRequest{Kind: "bridge.member.arm.v3.request",
		Selectors: selectors, MemberID: memberID, MemberSelector: selector,
		ObserveNonce: strings.Repeat("2", 64), ArmNonce: strings.Repeat("3", 64),
		ChildObservationEnvelopeSHA256: observation, BridgeArm: arm,
		BridgeArmReceiptSHA256: stage2aReservationSHA256(armRaw)}
	result := stage2aMemberArmWireResult{Kind: "bridge.member.arm.v3.result",
		MemberID: memberID, MemberSelector: selector, ArmNonce: request.ArmNonce,
		BridgeArmReceiptSHA256: request.BridgeArmReceiptSHA256,
		State:                  "recorded-pending-aggregate-ready",
		ExpiresAt:              now.Add(4 * time.Second).Format(time.RFC3339Nano)}
	check := func() error {
		t.Helper()
		requestRaw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		resultRaw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = stage2aVerifyMemberArmExchange(Stage2aMemberArmExchange{
			ArmRequest: requestRaw, ArmResult: resultRaw}, selectors,
			memberID, selector, "runtime_lead", observation, child,
			321, 320, 320, now, now.Add(time.Second))
		return err
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	request.BridgeArm.AdapterStartMicros++
	if err := check(); err == nil {
		t.Fatal("B arm for different ACP kernel start accepted")
	}
	request.BridgeArm.AdapterStartMicros--
	request.BridgeArmReceiptSHA256 = "sha256:" + strings.Repeat("0", 64)
	result.BridgeArmReceiptSHA256 = request.BridgeArmReceiptSHA256
	if err := check(); err == nil {
		t.Fatal("wrong B arm JCS digest accepted")
	}
	request.BridgeArmReceiptSHA256 = stage2aReservationSHA256(armRaw)
	result.BridgeArmReceiptSHA256 = request.BridgeArmReceiptSHA256
	result.ArmNonce = strings.Repeat("4", 64)
	if err := check(); err == nil {
		t.Fatal("ack for another arm nonce accepted")
	}
}
