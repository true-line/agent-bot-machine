//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestStage2aLiveLaunchJoinRejectsSplicedChildAndFinalization(t *testing.T) {
	q := Stage2aStopRequest{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID: "installation", StartID: "st_" + strings.Repeat("b", 24),
		LaunchID: "ln_" + strings.Repeat("c", 24), PlanID: "plan",
		PlanDigest: strings.Repeat("d", 64), HQEpoch: strings.Repeat("e", 64)}
	r := &stage2aLiveReservation{finalizationEnvelope: []byte("finalized"),
		bindReceiptSHA256:    "sha256:" + strings.Repeat("f", 64),
		childGrantSHA256:     "sha256:" + strings.Repeat("1", 64),
		hello:                &stage2aHelloState{finalizationEnvelope: []byte("hello")},
		bridgePID:            412,
		runnerProcess:        soulKernelProcessSnapshot{PID: 411},
		bridgeProcess:        soulKernelProcessSnapshot{PID: 412},
		childLauncherProcess: soulKernelProcessSnapshot{PID: 413},
		childProcess:         soulKernelProcessSnapshot{PID: 414},
	}
	child := Stage2aChildStartPayload{Schema: "agent-bot-machine/stage2a-child-start/v1",
		Stage2aStopRequest: q, FinalizationSHA256: stage2aReservationSHA256(r.finalizationEnvelope),
		HelloFinalizationSHA256: stage2aReservationSHA256(r.hello.finalizationEnvelope),
		BindReceiptSHA256:       r.bindReceiptSHA256, GrantSHA256: r.childGrantSHA256,
		Runner: stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		ChildLauncher: stage2aLiveRoleIdentity(r.childLauncherProcess),
		Child:         stage2aLiveRoleIdentity(r.childProcess), RelaySocket: "/private/relay.sock"}
	final := Stage2aFinalizationPayload{Schema: "agent-bot-machine/stage2a-finalization/v1",
		Stage2aStopRequest: q, BindReceiptSHA256: r.bindReceiptSHA256,
		BridgePID: r.bridgePID, RelaySocket: Stage2aRelayClaim{Path: child.RelaySocket}}
	if !stage2aLiveJoinRecordsMatch(q, r, child, final) {
		t.Fatal("matching A records refused")
	}
	wrongChild := child
	wrongChild.Child.PID++
	if stage2aLiveJoinRecordsMatch(q, r, wrongChild, final) {
		t.Fatal("a child from a different process accepted")
	}
	wrongChild = child
	wrongChild.GrantSHA256 = "sha256:" + strings.Repeat("2", 64)
	if stage2aLiveJoinRecordsMatch(q, r, wrongChild, final) {
		t.Fatal("a different child launcher grant accepted")
	}
	wrongChild = child
	wrongChild.LaunchID = "ln_" + strings.Repeat("9", 24)
	if stage2aLiveJoinRecordsMatch(q, r, wrongChild, final) {
		t.Fatal("a child from a different launch accepted")
	}
	wrongFinal := final
	wrongFinal.BindReceiptSHA256 = "sha256:" + strings.Repeat("0", 64)
	if stage2aLiveJoinRecordsMatch(q, r, child, wrongFinal) {
		t.Fatal("a different B bind receipt accepted")
	}
	wrongFinal = final
	wrongFinal.RelaySocket.Path = "/private/other.sock"
	if stage2aLiveJoinRecordsMatch(q, r, child, wrongFinal) {
		t.Fatal("a different B relay accepted")
	}
	if stage2aLiveJoinRecordsMatch(q, nil, child, final) {
		t.Fatal("missing active reservation accepted")
	}
}
