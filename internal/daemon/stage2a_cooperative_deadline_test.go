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
