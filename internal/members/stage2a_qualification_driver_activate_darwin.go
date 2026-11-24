package members

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"slices"
	"strconv"
	"time"
)

func captureStage2aProtectedBaseline(hqUID int, epoch string, guard stage2aReservationGuardV3,
	got stage2aReservation, reply stage2aReservationWorkerReplyV3, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (*stage2aPendingT03, error) {
	// Absence after an owner-reviewed observer removal restores ordinary launch.
	// An occupied but invalid installed record never drops a required baseline.
	if info, err := os.Lstat(stage2aQualificationQConfig); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil || !info.Mode().IsRegular() {
		return nil, errStage2aReservationAuthority
	}
	install, err := readStage2aQualificationQInstall()
	if err != nil {
		return nil, err
	}
	if install.Review.InstallationID != guard.assignment.InstallationID ||
		(!install.Review.DriverBaselineOnly && !install.Review.DriverLiveT03) {
		return nil, nil
	}
	if !install.Review.DriverLiveT03 {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, err := runStage2aProtectedQualification(ctx, install, hqUID, epoch, guard, got, reply, key, sign, nil)
		return nil, err
	}
	if guard.binding.ProfileInForce != "managed-protected" {
		return nil, errStage2aReservationAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	pending := &stage2aPendingT03{
		ctx: ctx, cancel: cancel, baseline: make(chan struct{}),
		request: make(chan stage2aT03DriverRequest), result: make(chan stage2aT03DriverResult, 1),
	}
	go func() {
		defer cancel()
		artifacts, err := runStage2aProtectedQualification(ctx, install, hqUID, epoch, guard, got, reply, key, sign, pending)
		pending.result <- stage2aT03DriverResult{artifacts, err}
	}()
	baselineDeadline := time.NewTimer(12 * time.Second)
	defer baselineDeadline.Stop()
	select {
	case <-pending.baseline:
		return pending, nil
	case failed := <-pending.result:
		return nil, failed.err
	case <-baselineDeadline.C:
		cancel()
		return nil, errStage2aReservationAuthority
	}
}

func runStage2aProtectedQualification(ctx context.Context, install stage2aQualificationQInstall,
	hqUID int, epoch string, guard stage2aReservationGuardV3, got stage2aReservation,
	reply stage2aReservationWorkerReplyV3, key ed25519.PublicKey, sign func([]byte) ([]byte, error),
	pending *stage2aPendingT03) (stage2aQualificationPreSignArtifactsV1, error) {
	var empty stage2aQualificationPreSignArtifactsV1
	review, err := loadStage2aQualificationDriverReview(install.Review.TestPlan)
	if err != nil || !stage2aQualificationPrintable(review.CohortID, 128) ||
		!qualificationRevision.MatchString(review.SuiteRevision) {
		return empty, errStage2aReservationAuthority
	}
	expected, providerDigest, err := decodeStage2aQualificationReservation(reply.Mode, reply.Expected)
	if err != nil {
		return empty, err
	}
	if providerDigest != "sha256:"+install.Review.Provider.SHA256 {
		return empty, errStage2aReservationAuthority
	}
	runtime, err := stage2aLoadInstalledRuntimeV3(key, hqUID, epoch, guard.assignment.InstallationID)
	if err != nil || runtime.VerifiedR.ref != guard.r || stage2aReservationSHA256(runtime.PolicyRaw) != reply.PolicyDigest {
		return empty, errStage2aReservationAuthority
	}
	store, _ := runtime.Policy.stores()
	checkLive := func() error {
		if ctx.Err() != nil ||
			recheckStage2aProtectedBaseline(install, guard, key, got, reply) != nil {
			return errStage2aReservationAuthority
		}
		return stage2aRecheckVerifiedDomainV3(runtime.VerifiedR)
	}
	deadline, _ := ctx.Deadline()
	begin := stage2aQualificationBeginV1{
		CohortID: review.CohortID, InstallationID: guard.assignment.InstallationID,
		SoulID: guard.assignment.SoulID, StartID: guard.assignment.StartID,
		HostID: guard.binding.HostID, Profile: guard.binding.ProfileInForce,
		ReservationSHA256: got.sha256, TestPlanSHA256: review.testPlanSHA256, SuiteRevision: review.SuiteRevision,
		PSSHA256: "sha256:" + install.PS.SHA256, PathRoots: install.Roots, QUID: install.UID, QGID: install.GID,
		DeadlineAt: deadline.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	session, wait, err := openStage2aQualificationObserverV3(ctx, begin, got.envelope, expected, key, store, checkLive)
	if err != nil {
		return empty, err
	}
	qExited := false
	defer func() {
		session.close()
		if !qExited {
			_ = wait()
		}
	}()
	driver, finishCheck, err := runStage2aDriverChild(ctx, install, review, session, checkLive, pending)
	if err != nil {
		return empty, err
	}
	result, err := session.finish()
	if err != nil || wait() != nil || finishCheck() != nil {
		return empty, errStage2aReservationAuthority
	}
	qExited = true
	challenge, err := stage2aQualificationReservationJoinV3(expected, result, got.envelope, key)
	if err != nil || finishCheck() != nil {
		return empty, errStage2aReservationAuthority
	}
	if pending == nil {
		return publishStage2aQualificationPreSignWithDriver(store, result, got.envelope, challenge, time.Now(), key, sign, &driver)
	}
	var artifacts stage2aQualificationPreSignArtifactsV1
	err = pending.finishPaired(func() error {
		if finishCheck() != nil {
			return errStage2aReservationAuthority
		}
		var err error
		artifacts, err = publishStage2aQualificationPreSignWithDriver(store, result, got.envelope,
			challenge, time.Now(), key, sign, &driver)
		return err
	})
	return artifacts, err
}

func recheckStage2aProtectedBaseline(install stage2aQualificationQInstall, guard stage2aReservationGuardV3,
	key ed25519.PublicKey, got stage2aReservation, reply stage2aReservationWorkerReplyV3) error {
	current, err := readStage2aQualificationQInstall()
	if err != nil || !reflect.DeepEqual(current, install) {
		return errStage2aReservationAuthority
	}
	verified, err := verifyStage2aReservationModeV3(reply.Mode, got.envelope, got.sha256, reply.Expected, key, time.Now())
	if err != nil || verified.binding != guard.binding || verified.r != guard.r {
		return errStage2aReservationAuthority
	}
	return nil
}

func runStage2aDriverChild(ctx context.Context, install stage2aQualificationQInstall, review stage2aDriverReview,
	session *stage2aQualificationSessionV1, checkLive func() error,
	pending *stage2aPendingT03) (stage2aDriverPhaseCapture, func() error, error) {
	var empty stage2aDriverPhaseCapture
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	self, selfErr := os.Executable()
	if err != nil || selfErr != nil || self != review.Authority.Path || !slices.Equal(os.Args, review.AuthorityArgv) ||
		review.Socket != stage2aQualificationDriverPath(account.HomeDir) ||
		!slices.Equal(review.Argv, []string{review.Executable.Path, "stage2a-qualification-owner-driver"}) ||
		verifyQualificationExecutable(review.Executable.Path, review.Executable.SHA256) != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	listener, err := newStage2aQualificationDriverListener(account.HomeDir, install.AdminUID, install.AdminGID)
	if err != nil {
		return empty, nil, err
	}
	defer listener.close()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(workerCtx, review.Executable.Path, review.Argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if err := cmd.Start(); err != nil {
		return empty, nil, err
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	conn, peer, err := acceptStage2aReviewedQualificationDriver(ctx, listener, review)
	if err != nil {
		return empty, nil, err
	}
	defer conn.Close()
	if peer.pid != cmd.Process.Pid || peer.kernel.ParentPID != os.Getpid() {
		return empty, nil, errStage2aReservationAuthority
	}
	checkPeer := func() error {
		if err := peer.recheck(); err != nil {
			return err
		}
		return checkLive()
	}
	trace, err := exchangeStage2aDriverCases(ctx, conn, session.begin, stage2aDriverBeforeLaunch, checkPeer,
		func(ctx context.Context, command stage2aDriverCommand, _ string) (stage2aDriverCorroboration, error) {
			return verifyStage2aDriverBaseline(ctx, command, review, install.Review.Provider, install.AdminUID)
		}, session.observe)
	if err != nil {
		return empty, nil, err
	}
	phase := stage2aDriverBeforeLaunch
	if pending != nil {
		close(pending.baseline)
		select {
		case request := <-pending.request:
			pending.finishPaired = request.paired
			checkLive = func() error {
				current, err := readStage2aQualificationQInstall()
				if err != nil || !reflect.DeepEqual(current, install) || verifyQualificationFile(review.Policy) != nil {
					return errStage2aReservationAuthority
				}
				return request.check()
			}
			followup, err := exchangeStage2aDriverCasesWithCapture(ctx, conn, session.begin,
				stage2aDriverLiveT03, checkPeer, nil, session.observe, request.capture)
			if err != nil {
				return empty, nil, err
			}
			phase = stage2aDriverProtectedT03Run
			trace = append(trace, followup...)
		case <-ctx.Done():
			return empty, nil, ctx.Err()
		}
	}
	_ = conn.Close()
	if cmd.Wait() != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	return stage2aDriverPhaseCapture{phase: phase, review: review, peer: peer, trace: trace}, checkLive, nil
}

func decodeStage2aQualificationReservation(mode stage2aReservationRunModeV3, raw []byte) (stage2aQualificationReservationV3, string, error) {
	expected := stage2aQualificationReservationV3{mode: mode}
	switch mode {
	case stage2aQualifiedRunV3:
		var payload stage2aReservationPayloadV3
		if stage2aDecodeExact(raw, &payload) == nil {
			expected.qualified = &payload
			return expected, payload.MeasurementBinding.Broker.ProviderConfigSHA256, nil
		}
	case stage2aCandidateRunV3:
		var payload stage2aQualificationCandidateReservationV3
		if stage2aDecodeExact(raw, &payload) == nil {
			expected.candidate = &payload
			return expected, payload.MeasurementBinding.Broker.ProviderConfigSHA256, nil
		}
	}
	return stage2aQualificationReservationV3{}, "", errStage2aReservationAuthority
}
