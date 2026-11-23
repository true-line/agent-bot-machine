//go:build darwin

package members

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"
)

// A reviewed live Q installation retains one authenticated Q generation and
// its A-only owner-driver listener from the prelaunch baseline through live
// capture. A failed or stopped run closes both; no second Q may claim a start.
type stage2aProtectedQRun struct {
	ctx       context.Context
	cancel    context.CancelFunc
	session   *stage2aQualificationSessionV1
	waitQ     func() error
	driver    *stage2aRetainedDriver
	baseline  stage2aDriverPhaseCapture
	install   stage2aQualificationQInstall
	review    stage2aDriverReview
	store     stage2aAdminClaimStore
	got       stage2aReservation
	expected  stage2aQualificationReservationV3
	key       ed25519.PublicKey
	sign      func([]byte) ([]byte, error)
	checkLive func() error
	mu        sync.Mutex
	closed    bool
	selector  *stage2aInnerACPCaptureSelectorV1
	once      sync.Once
}

func (run *stage2aProtectedQRun) abort() {
	if run == nil {
		return
	}
	run.once.Do(func() {
		run.cancel()
		run.mu.Lock()
		run.closed = true
		run.session.close()
		_ = run.driver.close(false)
		run.mu.Unlock()
		go func() { _ = run.waitQ() }()
	})
}

func captureStage2aProtectedRun(hqUID int, epoch string, guard stage2aReservationGuardV3,
	got stage2aReservation, reply stage2aReservationWorkerReplyV3, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (*stage2aProtectedQRun, error) {
	// An invalid occupied review never drops a required protected observer.
	if info, err := os.Lstat(stage2aQualificationQConfig); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil || !info.Mode().IsRegular() {
		return nil, errStage2aReservationAuthority
	}
	install, err := readStage2aQualificationQInstall()
	if err != nil {
		return nil, err
	}
	if install.Review.InstallationID != guard.assignment.InstallationID || !install.Review.DriverLive {
		return nil, captureStage2aProtectedBaseline(hqUID, epoch, guard, got, reply, key, sign)
	}
	return startStage2aProtectedLiveQ(hqUID, epoch, guard, got, reply, key, sign, install)
}

func startStage2aProtectedLiveQ(hqUID int, epoch string, guard stage2aReservationGuardV3,
	got stage2aReservation, reply stage2aReservationWorkerReplyV3, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error), install stage2aQualificationQInstall) (*stage2aProtectedQRun, error) {
	if !install.Review.DriverLive || install.Review.DriverBaselineOnly ||
		install.Review.InstallationID != guard.assignment.InstallationID ||
		install.Review.QualificationStartID != guard.assignment.StartID ||
		guard.binding.ProfileInForce != "managed-protected" ||
		reply.Mode != stage2aCandidateRunV3 {
		return nil, errStage2aReservationAuthority
	}
	// The Q protocol permits at most one hour. The installed reservation may
	// shorten that bound; never keep an observer alive past its authorization.
	expires, err := time.Parse(time.RFC3339Nano, guard.assignment.ExpiresAt)
	if err != nil || !time.Now().Before(expires) {
		return nil, errStage2aReservationAuthority
	}
	review, err := loadStage2aQualificationDriverReview(install.Review.TestPlan)
	if err != nil || !stage2aQualificationPrintable(review.CohortID, 128) ||
		!qualificationRevision.MatchString(review.SuiteRevision) {
		return nil, errStage2aReservationAuthority
	}
	var expected stage2aQualificationReservationV3
	var providerDigest string
	expected.mode = reply.Mode
	switch reply.Mode {
	case stage2aQualifiedRunV3:
		var payload stage2aReservationPayloadV3
		if stage2aDecodeExact(reply.Expected, &payload) != nil {
			return nil, errStage2aReservationAuthority
		}
		expected.qualified = &payload
		providerDigest = payload.MeasurementBinding.Broker.ProviderConfigSHA256
	case stage2aCandidateRunV3:
		var payload stage2aQualificationCandidateReservationV3
		if stage2aDecodeExact(reply.Expected, &payload) != nil {
			return nil, errStage2aReservationAuthority
		}
		expected.candidate = &payload
		providerDigest = payload.MeasurementBinding.Broker.ProviderConfigSHA256
	default:
		return nil, errStage2aReservationAuthority
	}
	if providerDigest != "sha256:"+install.Review.Provider.SHA256 {
		return nil, errStage2aReservationAuthority
	}
	runtime, err := stage2aLoadInstalledRuntimeV3(key, hqUID, epoch, guard.assignment.InstallationID)
	if err != nil || runtime.VerifiedR.ref != guard.r || stage2aReservationSHA256(runtime.PolicyRaw) != reply.PolicyDigest {
		return nil, errStage2aReservationAuthority
	}
	approvedUntil, err := time.Parse(time.RFC3339Nano, runtime.Policy.ApprovedUntil)
	if err != nil || !time.Now().Before(approvedUntil) {
		return nil, errStage2aReservationAuthority
	}
	deadline := minStage2aTime(minStage2aTime(expires, approvedUntil), time.Now().Add(10*time.Minute))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	keep := false
	defer func() {
		if !keep {
			cancel()
		}
	}()
	store, _ := runtime.Policy.stores()
	checkLive := func() error {
		if ctx.Err() != nil || recheckStage2aProtectedBaseline(install, guard, key, got, reply) != nil {
			return errStage2aReservationAuthority
		}
		return stage2aRecheckVerifiedDomainV3(runtime.VerifiedR)
	}
	begin := stage2aQualificationBeginV1{
		CohortID: review.CohortID, InstallationID: guard.assignment.InstallationID,
		SoulID: guard.assignment.SoulID, StartID: guard.assignment.StartID,
		HostID: guard.binding.HostID, Profile: guard.binding.ProfileInForce,
		ReservationSHA256: got.sha256, TestPlanSHA256: review.testPlanSHA256,
		SuiteRevision: review.SuiteRevision, PSSHA256: "sha256:" + install.PS.SHA256,
		PathRoots: install.Roots, QUID: install.UID, QGID: install.GID,
		DeadlineAt: deadline.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	session, waitQ, err := openStage2aQualificationObserverV3(ctx, begin, got.envelope, expected, key, store, checkLive)
	if err != nil {
		return nil, err
	}
	driver, baseline, err := startStage2aDriverBaselineChild(ctx, install, review, session, checkLive)
	if err != nil {
		session.close()
		_ = waitQ()
		return nil, err
	}
	if session.conn.SetDeadline(deadline) != nil || driver.conn.SetDeadline(deadline) != nil {
		session.close()
		_ = driver.close(false)
		_ = waitQ()
		return nil, errStage2aReservationAuthority
	}
	if checkLive() != nil || !reflect.DeepEqual(install.Review, readCurrentStage2aQReview()) {
		session.close()
		_ = driver.close(false)
		_ = waitQ()
		return nil, errStage2aReservationAuthority
	}
	run := &stage2aProtectedQRun{
		ctx: ctx, cancel: cancel, session: session, waitQ: waitQ, driver: driver,
		baseline: baseline, install: install, review: review, store: store,
		got: got, expected: expected, key: key, sign: sign, checkLive: checkLive,
	}
	keep = true
	go func() { <-ctx.Done(); run.abort() }()
	return run, nil
}

func readCurrentStage2aQReview() stage2aQualificationQReview {
	current, err := readStage2aQualificationQInstall()
	if err != nil {
		return stage2aQualificationQReview{}
	}
	return current.Review
}
