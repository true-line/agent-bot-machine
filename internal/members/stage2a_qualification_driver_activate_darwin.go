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
	sign func([]byte) ([]byte, error)) error {
	// Absence after an owner-reviewed observer removal restores ordinary launch.
	// An occupied but invalid installed record never drops a required baseline.
	if info, err := os.Lstat(stage2aQualificationQConfig); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || !info.Mode().IsRegular() {
		return errStage2aReservationAuthority
	}
	install, err := readStage2aQualificationQInstall()
	if err != nil {
		return err
	}
	if install.Review.InstallationID != guard.assignment.InstallationID || !install.Review.DriverBaselineOnly {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	review, err := loadStage2aQualificationDriverReview(install.Review.TestPlan)
	if err != nil || !stage2aQualificationPrintable(review.CohortID, 128) ||
		!qualificationRevision.MatchString(review.SuiteRevision) {
		return errStage2aReservationAuthority
	}
	var expected stage2aQualificationReservationV3
	var providerDigest string
	expected.mode = reply.Mode
	switch reply.Mode {
	case stage2aQualifiedRunV3:
		var payload stage2aReservationPayloadV3
		if stage2aDecodeExact(reply.Expected, &payload) != nil {
			return errStage2aReservationAuthority
		}
		expected.qualified = &payload
		providerDigest = payload.MeasurementBinding.Broker.ProviderConfigSHA256
	case stage2aCandidateRunV3:
		var payload stage2aQualificationCandidateReservationV3
		if stage2aDecodeExact(reply.Expected, &payload) != nil {
			return errStage2aReservationAuthority
		}
		expected.candidate = &payload
		providerDigest = payload.MeasurementBinding.Broker.ProviderConfigSHA256
	default:
		return errStage2aReservationAuthority
	}
	if providerDigest != "sha256:"+install.Review.Provider.SHA256 {
		return errStage2aReservationAuthority
	}
	runtime, err := stage2aLoadInstalledRuntimeV3(key, hqUID, epoch, guard.assignment.InstallationID)
	if err != nil || runtime.VerifiedR.ref != guard.r || stage2aReservationSHA256(runtime.PolicyRaw) != reply.PolicyDigest {
		return errStage2aReservationAuthority
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
		return err
	}
	qExited := false
	defer func() {
		session.close()
		if !qExited {
			_ = wait()
		}
	}()
	driver, err := runStage2aDriverBaselineChild(ctx, install, review, session, checkLive)
	if err != nil {
		return err
	}
	result, err := session.finish()
	if err != nil || wait() != nil || checkLive() != nil {
		return errStage2aReservationAuthority
	}
	qExited = true
	challenge, err := stage2aQualificationReservationJoinV3(expected, result, got.envelope, key)
	if err != nil || checkLive() != nil {
		return errStage2aReservationAuthority
	}
	_, err = publishStage2aQualificationPreSignWithDriver(store, result, got.envelope, challenge, time.Now(), key, sign, &driver)
	if err != nil {
		return err
	}
	return checkLive()
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

func runStage2aDriverBaselineChild(ctx context.Context, install stage2aQualificationQInstall, review stage2aDriverReview,
	session *stage2aQualificationSessionV1, checkLive func() error) (stage2aDriverPhaseCapture, error) {
	var empty stage2aDriverPhaseCapture
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	self, selfErr := os.Executable()
	if err != nil || selfErr != nil || self != review.Authority.Path || !slices.Equal(os.Args, review.AuthorityArgv) ||
		review.Socket != stage2aQualificationDriverPath(account.HomeDir) ||
		!slices.Equal(review.Argv, []string{review.Executable.Path, "stage2a-qualification-owner-driver"}) ||
		verifyQualificationExecutable(review.Executable.Path, review.Executable.SHA256) != nil {
		return empty, errStage2aReservationAuthority
	}
	listener, err := newStage2aQualificationDriverListener(account.HomeDir, install.AdminUID, install.AdminGID)
	if err != nil {
		return empty, err
	}
	defer listener.close()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(workerCtx, review.Executable.Path, review.Argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if err := cmd.Start(); err != nil {
		return empty, err
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	conn, peer, err := acceptStage2aReviewedQualificationDriver(ctx, listener, review)
	if err != nil {
		return empty, err
	}
	defer conn.Close()
	if peer.pid != cmd.Process.Pid || peer.kernel.ParentPID != os.Getpid() {
		return empty, errStage2aReservationAuthority
	}
	trace, err := runStage2aQualificationDriverCases(ctx, conn, peer, session.begin, stage2aDriverBeforeLaunch, checkLive,
		func(ctx context.Context, command stage2aDriverCommand, _ string) (stage2aDriverCorroboration, error) {
			return verifyStage2aDriverBaseline(ctx, command, review, install.Review.Provider, install.AdminUID)
		}, session.observe)
	if err != nil || cmd.Wait() != nil || len(trace) == 0 {
		return empty, errStage2aReservationAuthority
	}
	return stage2aDriverPhaseCapture{phase: stage2aDriverBeforeLaunch, review: review, peer: peer, trace: trace}, nil
}
