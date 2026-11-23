package members

import (
	"testing"
	"time"
)

func TestStage2aPostReadyLeaseWindowCutsOffWithoutFreshHandoff(t *testing.T) {
	now := time.Date(2026, 11, 23, 20, 0, 0, 0, time.UTC)
	ready := now.Add(2 * time.Second)
	approval := now.Add(6 * time.Second)
	first, err := stage2aPostReadyLeaseWindow(now, ready, approval, ready, time.Time{}, 0, 0)
	if err != nil || !first.Equal(now.Add(5*time.Second)) {
		t.Fatalf("first lease refused or extended: %v, %v", first, err)
	}
	second, err := stage2aPostReadyLeaseWindow(now.Add(3*time.Second), ready, approval,
		first, first, 1, 1)
	if err != nil || !second.Equal(approval) {
		t.Fatalf("renewal refused or crossed owner approval: %v, %v", second, err)
	}
	for name, input := range map[string]struct {
		now, ready, approval, prior, last time.Time
		after, sequence                   uint64
	}{
		"late first lease": {now.Add(3 * time.Second), ready, approval, ready, time.Time{}, 0, 0},
		"ready replay":     {now, ready, approval, ready, first, 1, 1},
		"late renewal":     {first, ready, approval, first, first, 1, 1},
		"wrong prior":      {now, ready, approval, ready, first, 1, 1},
		"wrong sequence":   {now, ready, approval, first, first, 0, 1},
		"owner cutoff":     {approval, ready, approval, first, first, 1, 1},
		"sequence limit":   {now, ready, approval, first, first, (1 << 53) - 1, (1 << 53) - 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := stage2aPostReadyLeaseWindow(input.now, input.ready, input.approval,
				input.prior, input.last, input.after, input.sequence); err == nil {
				t.Fatal("invalid post-Ready renewal accepted")
			}
		})
	}
}
