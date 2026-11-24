package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/diag"
)

func TestRunnerPeerStillCannotUsePairedMachineVerbs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Pairing: Pairing{Live: pub, AgentDaemon: pub, AgentDaemonUID: 309,
		AgentDaemonBound: true, OwnerPresenceRequired: true, HQEpoch: strings.Repeat("a", 64)}}
	q := Request{Verb: stage2aLookupVerb,
		Stage2aRequest: base64.RawURLEncoding.EncodeToString([]byte(`{"package_path":"/private/fixture"}`)),
		Timestamp:      time.Now().Unix(), Nonce: "runner-witness-boundary"}
	if err := Sign(priv, &q); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, id, _ := g.verify(301, raw); id != diag.DaemonPeerRefused {
		t.Fatalf("R peer entered a paired Machine verb: %s", id)
	}
	q.Signature = ""
	raw, _ = json.Marshal(q)
	if _, id, _ := g.verify(301, raw); id != diag.DaemonUnsigned {
		t.Fatalf("unsigned R request reached paired Machine verb: %s", id)
	}
}

func TestDirectChildWitnessRequiresCurrentApprovedHQEpoch(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("a", 64)
	p := Pairing{Live: pub, AgentDaemon: pub, AgentDaemonUID: 309,
		AgentDaemonBound: true, OwnerPresenceRequired: true, HQEpoch: epoch}
	if !stage2aT03DirectPairingAllows(p, epoch) {
		t.Fatal("current approved HQ epoch refused")
	}
	if stage2aT03DirectPairingAllows(p, strings.Repeat("b", 64)) {
		t.Fatal("pre-restart HQ epoch accepted")
	}
	p.AgentDaemonBound = false
	if stage2aT03DirectPairingAllows(p, epoch) {
		t.Fatal("revoked HQ pairing accepted")
	}
	p.AgentDaemonBound = true
	p.OwnerPresenceRequired = false
	if stage2aT03DirectPairingAllows(p, epoch) {
		t.Fatal("unapproved HQ pairing accepted")
	}
}

func TestDirectChildWitnessReceiptCarriesNoMachineSignatureOrAuthorityBody(t *testing.T) {
	if knownVerb(stage2aT03DirectChildWitnessVerb) || isStage2aVerb(stage2aT03DirectChildWitnessVerb) {
		t.Fatal("direct R child input entered the paired HQ command set")
	}
	for _, accepted := range []bool{true, false} {
		client, server := net.Pipe()
		done := make(chan struct{})
		go func() {
			writeStage2aDirectReceipt(server, Response{OK: accepted, State: "privileged-state", Body: []byte(`{"secret":"never"}`)})
			server.Close()
			close(done)
		}()
		got, err := io.ReadAll(client)
		client.Close()
		<-done
		if err != nil {
			t.Fatal(err)
		}
		want := "{\"ok\":true}\n"
		if !accepted {
			want = "{\"ok\":false}\n"
		}
		if string(got) != want {
			t.Fatalf("direct receipt exposed authority fields: %q", got)
		}
	}
}

func TestCooperativeContainmentDeadlineIsBoundedWithoutChangingOtherVerbs(t *testing.T) {
	start := time.Date(2026, 11, 23, 1, 0, 0, 0, time.UTC)
	for _, verb := range []string{stage2aCooperativeStopVerb, stage2aCooperativeAbortVerb,
		stage2aCooperativeRecoveryVerb, upgradeVerb, recoveryVerb} {
		if got := stage2aConnDeadline(start, verb); got.Sub(start) != 9*time.Second {
			t.Fatalf("%s deadline = %s", verb, got.Sub(start))
		}
	}
	for _, verb := range []string{stage2aCooperativeQBeginVerb, stage2aCooperativeQFinishVerb} {
		if !stage2aLongQVerb(verb) || stage2aConnDeadline(start, verb).Sub(start) != 130*time.Second {
			t.Fatalf("%s must have a bounded Q-only deadline", verb)
		}
	}
	for _, verb := range []string{"", stage2aReserveVerb, stage2aProviderVerb,
		stage2aCooperativeReserveVerb, stage2aCooperativeProviderVerb} {
		if got := stage2aConnDeadline(start, verb); got.Sub(start) != 5*time.Second {
			t.Fatalf("%s widened daemon deadline to %s", verb, got.Sub(start))
		}
	}
}

func TestCooperativeQualificationVerbsReachStage2aHandler(t *testing.T) {
	h := Hooks{Stage2a: func(Request) Response { return Response{OK: true, State: "routed"} }}
	for _, verb := range []string{stage2aCooperativeQBeginVerb, stage2aCooperativeQFinishVerb,
		stage2aCooperativeQWitnessBeginVerb, stage2aCooperativeQWitnessFinishVerb} {
		if !knownVerb(verb) {
			t.Fatalf("%s was rejected before dispatch", verb)
		}
		if got := h.reply(Request{Verb: verb}); !got.OK || got.State != "routed" {
			t.Fatalf("%s did not reach Stage2a: %+v", verb, got)
		}
	}
}

func TestT03SiblingWitnessVerbReachesStage2aHandler(t *testing.T) {
	h := Hooks{Stage2a: func(Request) Response { return Response{OK: true, State: "routed"} }}
	if !knownVerb(stage2aT03SiblingWitnessVerb) || !isStage2aVerb(stage2aT03SiblingWitnessVerb) {
		t.Fatal("sibling witness verb is unavailable to the paired Machine channel")
	}
	if got := h.reply(Request{Verb: stage2aT03SiblingWitnessVerb}); !got.OK || got.State != "routed" {
		t.Fatalf("sibling witness did not reach Stage2a: %+v", got)
	}
}

func TestT03PrewriteVerbReachesPairedStage2aHandler(t *testing.T) {
	h := Hooks{Stage2a: func(Request) Response { return Response{OK: true, State: "routed"} }}
	if !knownVerb(stage2aT03PrewriteVerb) || !isStage2aVerb(stage2aT03PrewriteVerb) {
		t.Fatal("prewrite verb is unavailable to the paired Machine channel")
	}
	if got := h.reply(Request{Verb: stage2aT03PrewriteVerb}); !got.OK || got.State != "routed" {
		t.Fatalf("prewrite did not reach Stage2a: %+v", got)
	}
}
