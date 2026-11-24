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
	q := Stage2aT03ArmRequest{Stage2aStopRequest: selectors, Receipt: Stage2aT03PositiveReceipt{
		Schema: stage2aT03PositiveSchema, ProviderSelector: stage2aT03ProviderAlgorithm, HTTPStatus: 200,
		ChildReceiptSHA256: digest, FinalizationSHA256: digest, BindReceiptSHA256: digest, RelaySocket: "/private/test/relay.sock",
		ProviderConfigSHA256: digest, ProviderIPv4URL: v4, ProviderIPv6URL: v6, RequestSHA256: digest,
		Model: "fixture-model", PromptSHA256: digest, ProviderReplySHA256: digest, ResponseWireSHA256: digest,
		ResponseWireBytes: 100, CompletedAtMS: 100, ReachabilityIPv4SHA256: digest, ReachabilityIPv6SHA256: digest, IPv4RequestCount: 1,
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
