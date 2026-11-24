package daemon

import (
	"testing"
	"time"
)

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
