package members

import (
	"context"
	"os"
	"time"
)

// captureStage2aT03 is the A-owned callback for the phase-aware Q session.
// The caller provides the pinned test-plan file and a guard that takes the
// current pairing lock only around a supplied local operation. Never keep the
// guard across the wait, during which HQ relays short R Live renewals.
func (s *Stage2aService) captureStage2aT03(ctx context.Context, hqUID int, epoch string, q Stage2aStopRequest,
	command stage2aDriverCommand, testPlan qualificationFile, paired func(func() error) error) (stage2aDriverCorroboration, error) {
	var evidence stage2aDriverCorroboration
	if paired == nil || command.TestPlanSHA256 != "sha256:"+testPlan.SHA256 {
		return evidence, errStage2aReservationAuthority
	}
	review, err := loadStage2aT03Review(testPlan)
	if err != nil {
		return evidence, err
	}
	positive, err := s.waitStage2aT03Positive(ctx, hqUID, epoch, q)
	if err != nil {
		return evidence, err
	}
	err = paired(func() error { return s.armStage2aT03(hqUID, epoch, positive, command, review) })
	if err != nil {
		return evidence, err
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r := s.active[q.ReservationSHA256]; r != nil && r.t03Pending != nil &&
			r.t03Pending.directive.ChallengeBase64URL == command.Challenge {
			r.t03Pending = nil
		}
	}()
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(positive.Receipt.CompletedAtMS).Add(stage2aT03ReceiptLifetime))
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		r := s.active[q.ReservationSHA256]
		live := stage2aMatchesStopSelectors(r, q, hqUID) && r.t03Pending != nil
		completed := live && len(r.t03Pending.complete) != 0
		s.mu.Unlock()
		if !live {
			return evidence, errStage2aReservationAuthority
		}
		if completed {
			err = paired(func() error {
				s.mu.Lock()
				defer s.mu.Unlock()
				return s.withStage2aT03Start(hqUID, epoch, q,
					func(r *stage2aLiveReservation, p stage2aInstalledPolicy, store stage2aAdminClaimStore, dir *os.File) error {
						pending := r.t03Pending
						if pending == nil || pending.directive.ChallengeBase64URL != command.Challenge ||
							s.checkStage2aT03Sibling(review, p.Runner, hqUID, epoch) != nil ||
							stage2aCheckFinalizationFile(dir, ".stage2a-t03-complete-"+soulStartClaimName(q.InstallationID, q.StartID)+".json",
								store.uid, store.gid, pending.complete) != nil {
							return errStage2aReservationAuthority
						}
						evidence = stage2aDriverCorroboration{artifact: pending.complete, osWitness: pending.osWitness,
							probe: stage2aQualificationObserveV1{
								Processes: []stage2aQualificationProcessRequestV1{{Role: "child-launcher", PID: r.childLauncherPID}},
							},
						}
						return nil
					})
			})
			return evidence, err
		}
		select {
		case <-ctx.Done():
			return evidence, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Stage2aService) waitStage2aT03Positive(ctx context.Context, hqUID int, epoch string,
	q Stage2aStopRequest) (Stage2aT03ArmRequest, error) {
	var positive Stage2aT03ArmRequest
	if q.HQEpoch != epoch {
		return positive, errStage2aReservationAuthority
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		r := s.active[q.ReservationSHA256]
		live := stage2aMatchesStopSelectors(r, q, hqUID) && r.runModeV3 == stage2aCandidateRunV3
		if live && r.t03Positive != nil {
			positive = *r.t03Positive
		}
		s.mu.Unlock()
		if !live {
			return positive, errStage2aReservationAuthority
		}
		if positive.Receipt.Schema != "" {
			return positive, nil
		}
		select {
		case <-ctx.Done():
			return positive, ctx.Err()
		case <-ticker.C:
		}
	}
}
