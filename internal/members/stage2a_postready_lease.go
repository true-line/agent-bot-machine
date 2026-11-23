package members

import (
	"errors"
	"time"
)

// A short aggregate Ready admits the first runtime lease. Later renewals
// depend on the prior live lease, not on an expired admission record. Both
// paths remain bounded by the installed owner approval and the same five
// second live window.
func stage2aPostReadyLeaseWindow(now, readyExpires, approvedUntil, priorExpires,
	lastExpires time.Time, after, lastSequence uint64) (time.Time, error) {
	invalid := errors.New("invalid Stage 2a post-Ready lease window")
	if now.IsZero() || approvedUntil.IsZero() || readyExpires.IsZero() ||
		lastSequence >= (1<<53)-1 || after != lastSequence ||
		!now.Before(approvedUntil) {
		return time.Time{}, invalid
	}
	if lastSequence == 0 {
		if !lastExpires.IsZero() || !priorExpires.Equal(readyExpires) ||
			!now.Before(readyExpires) {
			return time.Time{}, invalid
		}
	} else if lastExpires.IsZero() || !priorExpires.Equal(lastExpires) ||
		!now.Before(lastExpires) {
		return time.Time{}, invalid
	}
	until := now.Add(5 * time.Second)
	if approvedUntil.Before(until) {
		until = approvedUntil
	}
	if !until.After(now) {
		return time.Time{}, invalid
	}
	return until, nil
}
