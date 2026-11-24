package members

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStage2aT03DirectChildWitnessFrameIsExact(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	q := Stage2aT03DirectChildWitnessRequest{
		Verb: "stage2a-t03-child-credential-witness",
		Stage2aT03SiblingCredentialWitnessRequest: Stage2aT03SiblingCredentialWitnessRequest{
			Stage2aStopRequest: Stage2aStopRequest{
				ReservationSHA256: digest, InstallationID: "soul-one", StartID: "st_0123456789abcdef01234567",
				LaunchID: "ln_0123456789abcdef01234567", PlanID: "plan-20261122T120000Z-abcd",
				PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)},
			Witness: Stage2aT03SiblingCredentialWitness{
				Schema:             "agent-bot-machine/stage2a-t03-sibling-credential-witness/v1",
				ChallengeBase64URL: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))), PrimaryReservationSHA256: digest,
				SiblingReservationSHA256: digest, ChildReceiptSHA256: digest,
				MetadataSHA256: digest, LeaseSequence: 7, CredentialPath: "/private/test/credential",
				ObservedAtMS: 1000}}}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aT03DirectChildWitnessRequest(raw); err != nil {
		t.Fatalf("valid direct child witness refused: %v", err)
	}
	q.Verb = "stage2a-t03-sibling-credential-witness"
	bad, _ := json.Marshal(q)
	if _, err := ParseStage2aT03DirectChildWitnessRequest(bad); err == nil {
		t.Fatal("paired HQ witness verb entered direct child route")
	}
	dup := append(raw[:len(raw)-1], []byte(`,"verb":"stage2a-t03-child-credential-witness"}`)...)
	if _, err := ParseStage2aT03DirectChildWitnessRequest(dup); err == nil {
		t.Fatal("duplicate direct verb accepted")
	}
	unknown := append(raw[:len(raw)-1], []byte(`,"sign_privileged_operation":true}`)...)
	if _, err := ParseStage2aT03DirectChildWitnessRequest(unknown); err == nil {
		t.Fatal("undeclared direct child field accepted")
	}
}

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
	peerBytes, err := stage2aT03PeerCanonical(peer)
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
		Peer: peer, PeerSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(peerBytes)),
	}}
	q.BrokerCompletion = Stage2aT03BrokerCompletion{
		Stage2aT03BrokerPrewrite: Stage2aT03BrokerPrewrite{
			Selectors: Stage2aT03BrokerSelectors{InstallationID: selectors.InstallationID,
				StartID: selectors.StartID, LaunchID: selectors.LaunchID, PlanID: selectors.PlanID,
				PlanDigest: selectors.PlanDigest, ReservationDigest: selectors.ReservationSHA256},
			BindReceiptSHA256: q.Receipt.BindReceiptSHA256, Peer: peer, PeerSHA256: q.Receipt.PeerSHA256,
			RequestSHA256: q.Receipt.RequestSHA256, PromptSHA256: q.Receipt.PromptSHA256,
			Model: q.Receipt.Model, ResponseWireSHA256: q.Receipt.ResponseWireSHA256,
			ResponseWireBytes: q.Receipt.ResponseWireBytes, HTTPStatus: q.Receipt.HTTPStatus},
		WriteStartedAt: "1970-01-01T00:00:00.05Z", WriteCompletedAt: "1970-01-01T00:00:00.1Z",
		PrewriteReceipt: strings.Repeat("1", 64), CompletionOriginMAC: strings.Repeat("2", 64),
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseStage2aT03ArmRequest(raw); err != nil || parsed != q {
		t.Fatalf("valid receipt refused: %v", err)
	}
	prewrite := Stage2aT03PrewriteRequest{Stage2aStopRequest: selectors,
		ChildReceiptSHA256: digest, BrokerPrewrite: q.BrokerCompletion.Stage2aT03BrokerPrewrite}
	prewriteRaw, err := json.Marshal(prewrite)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal(prewriteRaw, &outer) != nil || len(outer) != 9 {
		t.Fatalf("paired prewrite must have seven selectors, child digest and broker record: %s", prewriteRaw)
	}
	var broker map[string]json.RawMessage
	if json.Unmarshal(outer["broker_prewrite"], &broker) != nil || len(broker) != 10 {
		t.Fatalf("B prepared-wire record must have ten exact fields: %s", outer["broker_prewrite"])
	}
	if parsed, err := ParseStage2aT03PrewriteRequest(prewriteRaw); err != nil || parsed != prewrite {
		t.Fatalf("valid paired prewrite refused: %v", err)
	}
	var arm map[string]json.RawMessage
	if json.Unmarshal(raw, &arm) != nil || json.Unmarshal(arm["broker_completion"], &broker) != nil || len(broker) != 14 {
		t.Fatalf("B completion must have fourteen exact fields: %s", arm["broker_completion"])
	}
	badPrewrite := prewrite
	badPrewrite.BrokerPrewrite.Selectors.ReservationDigest = "sha256:" + strings.Repeat("d", 64)
	badRaw, _ := json.Marshal(badPrewrite)
	if _, err := ParseStage2aT03PrewriteRequest(badRaw); err == nil {
		t.Fatal("B selectors differed from paired Machine start")
	}
	duplicate := append(prewriteRaw[:len(prewriteRaw)-1], []byte(`,"child_receipt_sha256":"`+digest+`"}`)...)
	if _, err := ParseStage2aT03PrewriteRequest(duplicate); err == nil {
		t.Fatal("duplicate paired prewrite field accepted")
	}
	unknown := append(prewriteRaw[:len(prewriteRaw)-1], []byte(`,"key_request":true}`)...)
	if _, err := ParseStage2aT03PrewriteRequest(unknown); err == nil {
		t.Fatal("undeclared paired prewrite field accepted")
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
