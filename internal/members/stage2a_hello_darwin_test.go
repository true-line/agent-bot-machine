//go:build darwin

package members

import (
	"slices"
	"strings"
	"testing"
)

func TestStage2aHelloFinalizationJoinsEveryHQRuntimeToOriginalHello(t *testing.T) {
	selectors := stage2aHelloTestSelectors()
	binding := Stage2aMeasurementBinding{
		SoulID:                  "agent_01234567-0123-0123-0123-0123456789ab",
		ClaimedDefinitionDigest: "sha256:" + strings.Repeat("d", 64),
		DefinitionMeasurement:   "sha256:" + strings.Repeat("e", 64),
		LaunchInputMeasurement:  "sha256:" + strings.Repeat("f", 64),
	}
	r := &stage2aLiveReservation{bindReceiptSHA256: "sha256:" + strings.Repeat("1", 64),
		hello: &stage2aHelloState{helloSHA256: "sha256:" + strings.Repeat("2", 64), members: []string{"a", "b"}}}
	q := Stage2aHelloFinalizeRequest{Stage2aStopRequest: selectors, Expected: Stage2aHelloExpected{
		ReservationSHA256: selectors.ReservationSHA256, StartID: selectors.StartID, LaunchID: selectors.LaunchID,
		HQEpoch: selectors.HQEpoch, SoulID: binding.SoulID, InstallationID: selectors.InstallationID,
		DefinitionDigest: binding.ClaimedDefinitionDigest, DefinitionMeasurement: binding.DefinitionMeasurement,
		LaunchInputMeasurement: binding.LaunchInputMeasurement,
		HelloPayloadSHA256:     r.hello.helloSHA256, HQBrokerBindReceiptSHA256: r.bindReceiptSHA256,
		AdmittedRuntimes: []Stage2aHelloRuntime{{MemberID: "a", RuntimeID: "rt_aaaaaaaa"},
			{MemberID: "b", RuntimeID: "rt_bbbbbbbb"}},
	}}
	p := stage2aInstalledPolicy{Binding: binding}
	if !stage2aHelloExpectedMatches(q, r, p) {
		t.Fatal("matching HQ tuple refused")
	}
	check := func(name string, change func(*Stage2aHelloFinalizeRequest)) {
		t.Helper()
		bad := q
		bad.Expected.AdmittedRuntimes = slices.Clone(q.Expected.AdmittedRuntimes)
		change(&bad)
		if stage2aHelloExpectedMatches(bad, r, p) {
			t.Fatalf("%s accepted", name)
		}
	}
	check("other Hello", func(q *Stage2aHelloFinalizeRequest) {
		q.Expected.HelloPayloadSHA256 = "sha256:" + strings.Repeat("3", 64)
	})
	check("other bind", func(q *Stage2aHelloFinalizeRequest) {
		q.Expected.HQBrokerBindReceiptSHA256 = "sha256:" + strings.Repeat("3", 64)
	})
	check("other definition", func(q *Stage2aHelloFinalizeRequest) {
		q.Expected.DefinitionMeasurement = "sha256:" + strings.Repeat("3", 64)
	})
	check("missing member", func(q *Stage2aHelloFinalizeRequest) { q.Expected.AdmittedRuntimes = q.Expected.AdmittedRuntimes[:1] })
	check("other member", func(q *Stage2aHelloFinalizeRequest) { q.Expected.AdmittedRuntimes[1].MemberID = "c" })
	check("reused runtime", func(q *Stage2aHelloFinalizeRequest) {
		q.Expected.AdmittedRuntimes[1].RuntimeID = q.Expected.AdmittedRuntimes[0].RuntimeID
	})
}

func TestStage2aRunnerPeerRejectsSameUIDWrongProcess(t *testing.T) {
	peer := soulKernelProcessSnapshot{PID: 4202, ParentPID: 4101, ProcessGroupID: 4202,
		StartSeconds: 1, RealUID: 310, EffectiveUID: 310, SavedUID: 310,
		RealGID: 310, PrimaryGroupGID: 310, SavedGID: 310}
	if !stage2aRunnerPeerKernelMatches(peer, 4101, 310, 310) {
		t.Fatal("direct measured Node child refused")
	}
	wrong := peer
	wrong.ParentPID = 4102 // another same-UID wrapper
	if stage2aRunnerPeerKernelMatches(wrong, 4101, 310, 310) {
		t.Fatal("same-UID unrelated child accepted as runner")
	}
	wrong = peer
	wrong.PID = 4101 // the Go wrapper is not the Node admission peer
	if stage2aRunnerPeerKernelMatches(wrong, 4101, 310, 310) {
		t.Fatal("wrapper PID accepted as Node peer")
	}
	wrong = peer
	wrong.ProcessGroupID = 4102
	if stage2aRunnerPeerKernelMatches(wrong, 4101, 310, 310) {
		t.Fatal("wrong process group accepted")
	}
}
