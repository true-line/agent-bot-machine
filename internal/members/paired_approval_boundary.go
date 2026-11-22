package members

import (
	"errors"
	"time"
)

// Recheck the live pairing and exact owner approval window under the pair
// read lock at every durable privilege transition. The same boundary serves
// both the harness grant and the separately reviewed Soul bridge provision.
type harnessBoundary func(func() error) error

func harnessAuthority(a Approval, guard upgradePairGuard, now func() time.Time) harnessBoundary {
	return func(commit func() error) error {
		if guard == nil {
			return errors.New("paired approval verifier unavailable")
		}
		return guard(a, func() error {
			start, err := time.Parse(approvalTime, a.ApprovedAt)
			end, endErr := time.Parse(approvalTime, a.ExpiresAt)
			t := now()
			if err != nil || endErr != nil || end.Sub(start) != ApprovalTTL || t.Before(start) || !t.Before(end) {
				return errors.New("paired approval is outside its validity window")
			}
			if commit == nil {
				return nil
			}
			return commit()
		})
	}
}
