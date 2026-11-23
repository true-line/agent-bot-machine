package daemon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/members"
)

func TestStage2aReserveBoundHQOnly(t *testing.T) {
	testPlanRole(t, "777")
	hq, key := keyPair(t)
	terminal, terminalKey := keyPair(t)
	epoch := strings.Repeat("b", 64)
	input := members.Stage2aReserveRequest{PlanDigest: strings.Repeat("a", 64), InstallationID: "soul-one", StartID: "st_0123456789abcdef01234567", HQEpoch: epoch, LaunchID: "ln_0123456789abcdef01234567"}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Verb: stage2aReserveVerb, Stage2aRequest: base64.RawURLEncoding.EncodeToString(encoded), Timestamp: time.Now().Unix(), Nonce: "reserve-1"}
	pairing := Pairing{Live: hq, Extra: []ed25519.PublicKey{terminal}, Terminal: terminal, AgentDaemon: hq, AgentDaemonUID: 777, AgentDaemonBound: true, OwnerPresenceRequired: true, HQEpoch: epoch}
	for _, tc := range []struct {
		name string
		pair Pairing
		key  ed25519.PrivateKey
		uid  int
		req  Request
		want bool
	}{
		{"enrolled", pairing, key, 777, request, true},
		{"wrong UID", pairing, key, 778, request, false},
		{"terminal", pairing, terminalKey, 777, request, false},
		{"unbound", func() Pairing { p := pairing; p.AgentDaemonBound = false; return p }(), key, 777, request, false},
		{"wrong epoch", func() Pairing { p := pairing; p.HQEpoch = strings.Repeat("c", 64); return p }(), key, 777, request, false},
		{"legacy pairing", func() Pairing { p := pairing; p.OwnerPresenceRequired = false; return p }(), key, 777, request, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, id, _ := (&Gate{Pairing: tc.pair}).verify(tc.uid, signed(t, tc.key, tc.req))
			if (id == "") != tc.want || (tc.want && got.stage2aReserve != input) {
				t.Fatalf("verdict %q parsed %+v", id, got.stage2aReserve)
			}
		})
	}
	for _, fragment := range []string{`"name":null,`, `"stage2a_request":null,`, `"stage2a_request":"other",`} {
		raw := signed(t, key, request)
		raw = []byte("{" + fragment + string(raw[1:]))
		if _, id, _ := (&Gate{Pairing: pairing}).verify(777, raw); id == "" {
			t.Fatalf("accepted undeclared or duplicate field: %s", fragment)
		}
	}
	lookup := Request{Verb: stage2aLookupVerb,
		Stage2aRequest: base64.RawURLEncoding.EncodeToString([]byte(`{"package_path":"/Library/Example.soul"}`)),
		Timestamp:      time.Now().Unix(), Nonce: "lookup-1"}
	if got, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, lookup)); id != "" ||
		got.stage2aLookup.PackagePath != "/Library/Example.soul" {
		t.Fatalf("paired read-only lookup refused: %q %+v", id, got.stage2aLookup)
	}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, lookup)); id == "" {
		t.Fatal("foreign UID accepted installed lookup")
	}
	list := Request{Verb: stage2aListVerb, Stage2aRequest: base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
		Timestamp: time.Now().Unix(), Nonce: "list-1"}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, list)); id != "" {
		t.Fatalf("paired installed list refused: %q", id)
	}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, list)); id == "" {
		t.Fatal("foreign UID accepted installed list")
	}
	list.Stage2aRequest = base64.RawURLEncoding.EncodeToString([]byte(`{"installation_id":"chosen"}`))
	if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, list)); id == "" {
		t.Fatal("caller-selected installed list accepted")
	}
	proof := members.Stage2aVerifyBRequest{
		ReservationSHA256: "sha256:" + strings.Repeat("a", 64), InstallationID: "soul-one",
		StartID: input.StartID, LaunchID: input.LaunchID, PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: input.PlanDigest, HQEpoch: epoch,
		Challenge: strings.Repeat("c", 64), Proof: strings.Repeat("d", 64),
	}
	proofRaw, _ := json.Marshal(proof)
	verify := Request{Verb: stage2aVerifyBVerb,
		Stage2aRequest: base64.RawURLEncoding.EncodeToString(proofRaw),
		Timestamp:      time.Now().Unix(), Nonce: "verify-b-1"}
	if got, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, verify)); id != "" ||
		got.stage2aVerifyB != proof {
		t.Fatalf("paired B verification request refused: %q %+v", id, got.stage2aVerifyB)
	}
	selectors := members.Stage2aStopRequest{ReservationSHA256: proof.ReservationSHA256,
		InstallationID: proof.InstallationID, StartID: proof.StartID, LaunchID: proof.LaunchID,
		PlanID: proof.PlanID, PlanDigest: proof.PlanDigest, HQEpoch: proof.HQEpoch}
	selectorRaw, _ := json.Marshal(selectors)
	for _, verb := range []string{stage2aStopVerb, stage2aLiveVerb} {
		requestRaw := selectorRaw
		if verb == stage2aLiveVerb {
			requestRaw, _ = json.Marshal(members.Stage2aLiveRequest{Stage2aStopRequest: selectors,
				Challenge: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))})
		}
		candidate := Request{Verb: verb, Stage2aRequest: base64.RawURLEncoding.EncodeToString(requestRaw),
			Timestamp: time.Now().Unix(), Nonce: verb + "-1"}
		if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, candidate)); id != "" {
			t.Fatalf("paired %s request refused: %q", verb, id)
		}
		if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, candidate)); id == "" {
			t.Fatalf("foreign UID accepted %s", verb)
		}
	}
	finalize := members.Stage2aFinalizeBRequest{Stage2aStopRequest: selectors,
		BindReceiptSHA256: "sha256:" + strings.Repeat("d", 64),
		RelaySocket: members.Stage2aRelayClaim{Path: "/private/example/relay.sock",
			Socket: members.Stage2aKernelNodeClaim{UID: 310, GID: 311, Device: "1", Inode: "2", Mode: 0660}}}
	finalRaw, _ := json.Marshal(finalize)
	finalReq := Request{Verb: stage2aFinalizeBVerb, Stage2aRequest: base64.RawURLEncoding.EncodeToString(finalRaw),
		Timestamp: time.Now().Unix(), Nonce: "finalize-1"}
	if got, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, finalReq)); id != "" ||
		got.stage2aFinalizeB.BindReceiptSHA256 != finalize.BindReceiptSHA256 {
		t.Fatalf("paired finalization refused: %q %+v", id, got.stage2aFinalizeB)
	}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, finalReq)); id == "" {
		t.Fatal("foreign UID accepted B finalization")
	}
	provider := members.Stage2aProviderRequest{Stage2aStopRequest: selectors,
		BindReceiptSHA256: finalize.BindReceiptSHA256, Model: "pilot-model",
		PromptSHA256: "sha256:" + strings.Repeat("e", 64)}
	providerRaw, _ := json.Marshal(provider)
	providerReq := Request{Verb: stage2aProviderVerb, Stage2aRequest: base64.RawURLEncoding.EncodeToString(providerRaw),
		Timestamp: time.Now().Unix(), Nonce: "provider-1"}
	if got, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, providerReq)); id != "" ||
		got.stage2aProvider.PromptSHA256 != provider.PromptSHA256 {
		t.Fatalf("paired provider request refused: %q %+v", id, got.stage2aProvider)
	}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, providerReq)); id == "" {
		t.Fatal("foreign UID accepted provider operation")
	}
	if got := (Hooks{}).reply(Request{Verb: stage2aReserveVerb}); got.OK || got.Diagnostic != diag.DaemonUnimplemented {
		t.Fatalf("nil authority did not refuse: %+v", got)
	}
}

func TestStage2aProtectedHandshakeVerbsReachAuthority(t *testing.T) {
	for _, verb := range []string{stage2aChildReadyVerb, stage2aHelloStartVerb,
		stage2aHelloFinalizeVerb, stage2aHelloAbortVerb, stage2aPeerRoleVerb} {
		t.Run(verb, func(t *testing.T) {
			if !knownVerb(verb) || !isStage2aVerb(verb) {
				t.Fatal("protected handshake verb is not admitted by both protocol gates")
			}
			called := false
			hooks := Hooks{Stage2a: func(req Request) Response {
				called = true
				if req.Verb != verb {
					t.Fatalf("dispatched wrong verb %q", req.Verb)
				}
				return Response{OK: true, State: "accepted"}
			}}
			if got := hooks.reply(Request{Verb: verb}); !called || !got.OK || got.State != "accepted" {
				t.Fatalf("protected handshake authority was not reached: %+v", got)
			}
			if got := (Hooks{}).reply(Request{Verb: verb}); got.OK || got.Diagnostic != diag.DaemonUnimplemented {
				t.Fatalf("missing authority did not fail closed: %+v", got)
			}
		})
	}
}

func TestCooperativeReserveResultRequiresExactPairedRequest(t *testing.T) {
	testPlanRole(t, "777")
	hq, key := keyPair(t)
	epoch := strings.Repeat("b", 64)
	challenge := make([]byte, 32)
	input := members.SoulCooperativeStartRequestV3{
		SoulCooperativeReserveRequest: members.SoulCooperativeReserveRequest{
			Profile: "managed-cooperative", HostID: "test-host", PackagePath: "/Library/Example.soul",
			PlanDigest: strings.Repeat("a", 64), InstallationID: "soul-one", HQEpoch: epoch,
			StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
			AdmissionChallengeSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)),
		},
		AdmissionChallengeBase64URL: base64.RawURLEncoding.EncodeToString(challenge),
	}
	pairing := Pairing{Live: hq, AgentDaemon: hq, AgentDaemonUID: 777, AgentDaemonBound: true,
		OwnerPresenceRequired: true, HQEpoch: epoch}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Verb: stage2aCooperativeReserveResultVerb, Timestamp: time.Now().Unix(),
		Nonce: "cooperative-reserve-result-1", Stage2aRequest: base64.RawURLEncoding.EncodeToString(raw)}
	for _, verb := range []string{stage2aCooperativeReserveVerb, stage2aCooperativeReserveResultVerb} {
		request := req
		request.Verb = verb
		got, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, request))
		if id != "" || got.stage2aCooperativeReserve != input || got.stage2aEpoch != epoch {
			t.Fatalf("paired %s refused or misrouted: %q", verb, id)
		}
		// The test has no installed owner authority. Each handler must reach
		// the guarded authority and refuse before any use of the host.
		res := stage2aHandler(nil, "", "")(got)
		if res.OK || res.Message != "Stage 2a installed authority unavailable or mismatched" {
			t.Fatalf("unexpected %s handler response: %+v", verb, res)
		}
	}
	if _, id, _ := (&Gate{Pairing: pairing}).verify(778, signed(t, key, req)); id == "" {
		t.Fatal("foreign peer accepted")
	}
	input.AdmissionChallengeBase64URL = ""
	raw, err = json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req.Stage2aRequest = base64.RawURLEncoding.EncodeToString(raw)
	if _, id, _ := (&Gate{Pairing: pairing}).verify(777, signed(t, key, req)); id == "" {
		t.Fatal("result lookup accepted without the original challenge")
	}
}
