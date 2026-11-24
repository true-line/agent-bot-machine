package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStage2aT03PositiveBindsExactStartAndDualStackBaseline(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	selectors := Stage2aStopRequest{
		ReservationSHA256: digest, InstallationID: "soul-one", StartID: "st_0123456789abcdef01234567",
		LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64),
	}
	v4, v6 := stage2aT03ProviderURLs(selectors)
	peer := Stage2aT03RelayPeer{UID: 310, PID: 800, PIDVersion: 2,
		StartSeconds: 100, StartMicros: 123, ParentPID: 700, ParentUID: 310,
		ParentStartSeconds: 99, ParentStartMicros: 456}
	peerBytes, err := marshalStage2aReservationJCS(peer)
	if err != nil {
		t.Fatal(err)
	}
	const canonicalPeer = `{"parent_pid":700,"parent_start_micros":456,"parent_start_seconds":99,"parent_uid":310,"pid":800,"pid_version":2,"start_micros":123,"start_seconds":100,"uid":310}`
	if string(peerBytes) != canonicalPeer {
		t.Fatalf("B peer canonical integer profile differs: %s", peerBytes)
	}
	q := Stage2aT03ArmRequest{Stage2aStopRequest: selectors, Receipt: Stage2aT03PositiveReceipt{
		Schema: stage2aT03PositiveSchema, ProviderSelector: stage2aT03ProviderAlgorithm, HTTPStatus: 200,
		ChildReceiptSHA256: digest, FinalizationSHA256: digest, BindReceiptSHA256: digest, RelaySocket: "/private/test/relay.sock",
		ProviderConfigSHA256: digest, ProviderIPv4URL: v4, ProviderIPv6URL: v6, RequestSHA256: digest,
		Model: "fixture-model", PromptSHA256: digest, ProviderReplySHA256: digest, ResponseWireSHA256: digest,
		ResponseWireBytes: 100, CompletedAtMS: 100, ReachabilityIPv4SHA256: digest, ReachabilityIPv6SHA256: digest, IPv4RequestCount: 1,
		Peer: peer, PeerSHA256: stage2aReservationSHA256(peerBytes),
	}}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseStage2aT03ArmRequest(raw); err != nil || parsed != q {
		t.Fatalf("valid receipt refused: %v", err)
	}
	for _, mutate := range []func(*Stage2aT03ArmRequest){
		func(p *Stage2aT03ArmRequest) { p.Receipt.IPv6RequestCount = 1 },
		func(p *Stage2aT03ArmRequest) { p.Receipt.HTTPStatus = 201 },
		func(p *Stage2aT03ArmRequest) { p.Receipt.ProviderIPv4URL += "/v1/messages" },
		func(p *Stage2aT03ArmRequest) { p.HQEpoch = strings.Repeat("d", 64) },
		func(p *Stage2aT03ArmRequest) { p.Receipt.PromptSHA256 = "" },
		func(p *Stage2aT03ArmRequest) { p.Receipt.Peer.PID++ },
		func(p *Stage2aT03ArmRequest) { p.Receipt.Peer.ParentUID++ },
	} {
		bad := q
		mutate(&bad)
		raw, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStage2aT03ArmRequest(raw); err == nil {
			t.Fatal("accepted an unbound or incomplete receipt")
		}
	}
}
