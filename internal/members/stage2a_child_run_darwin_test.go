//go:build darwin

package members

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage2aChildLiveCancelsWhileRenewalBlocksPastExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expires := time.Now().Add(1200 * time.Millisecond)
	first := Stage2aLiveLeasePayload{Sequence: 7, ExpiresAtMS: expires.UnixMilli()}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		watchStage2aChildLiveWithRequest(ctx, cancel, first, func(after uint64,
			deadline time.Time) (Stage2aLiveLeasePayload, error) {
			calls.Add(1)
			if after != 7 || !deadline.Equal(time.UnixMilli(first.ExpiresAtMS)) {
				return Stage2aLiveLeasePayload{}, errStage2aReservationAuthority
			}
			select {
			case started <- struct{}{}:
			default:
			}
			<-release // Simulate HQ I/O completing only after the old lease lapses.
			return Stage2aLiveLeasePayload{Sequence: 8,
				ExpiresAtMS: time.Now().Add(5 * time.Second).UnixMilli()}, nil
		})
	}()
	select {
	case <-started:
	case <-time.After(900 * time.Millisecond):
		close(release)
		t.Fatal("renewal did not begin before the signed lease expired")
	}
	select {
	case <-ctx.Done(): // The child is cut off while the renewal remains blocked.
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("blocked renewal hid the signed lease expiry")
	}
	select {
	case <-done:
		close(release)
		t.Fatal("watcher returned before the simulated HQ I/O completed")
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not discard the late renewal")
	}
	if calls.Load() != 1 {
		t.Fatalf("late renewal restarted the child watcher: %d calls", calls.Load())
	}
}
