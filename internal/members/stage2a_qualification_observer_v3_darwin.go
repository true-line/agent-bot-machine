package members

import (
	"context"
	"crypto/ed25519"
	"os"
	"slices"
	"time"
)

// openStage2aQualificationObserverV3 is the A-local pre-start observer
// authority. The candidate grant must still be live after the kernel peer
// handshake. No request reaches this function through the Q transport.
func openStage2aQualificationObserverV3(ctx context.Context,
	begin stage2aQualificationBeginV1, raw []byte, expected stage2aQualificationReservationV3,
	key ed25519.PublicKey, store stage2aAdminClaimStore,
	checkLiveRun func() error) (*stage2aQualificationSessionV1, func() error, error) {
	if ctx == nil || checkLiveRun == nil || checkLiveRun() != nil {
		return nil, nil, errQualificationAdmissionUnavailable
	}
	install, err := loadStage2aQualificationQInstall()
	if err != nil || os.Getuid() != os.Geteuid() || os.Geteuid() != install.AdminUID ||
		os.Getgid() != os.Getegid() || os.Getegid() != install.AdminGID ||
		begin.HostID != install.Review.HostID || begin.InstallationID != install.Review.InstallationID ||
		begin.TestPlanSHA256 != "sha256:"+install.Review.TestPlan.SHA256 ||
		begin.QUID != install.UID || begin.QGID != install.GID || begin.PSSHA256 != "sha256:"+install.PS.SHA256 ||
		!slices.Equal(begin.PathRoots, install.Roots) {
		return nil, nil, errQualificationAdmissionUnavailable
	}
	var assignment stage2aReservationAssignmentV3
	switch expected.mode {
	case stage2aQualifiedRunV3:
		if expected.qualified == nil || expected.candidate != nil {
			return nil, nil, errQualificationAdmissionUnavailable
		}
		assignment = expected.qualified.Assignment
	case stage2aCandidateRunV3:
		if expected.candidate == nil || expected.qualified != nil {
			return nil, nil, errQualificationAdmissionUnavailable
		}
		assignment = expected.candidate.Assignment
	default:
		return nil, nil, errQualificationAdmissionUnavailable
	}
	if !stage2aQualificationAssignmentMatchesQInstall(assignment, install, begin.StartID) ||
		observeStage2aQualificationHost(ctx, install.Review.HostUUID) != nil ||
		verifyQualificationFile(install.Review.TestPlan) != nil || verifyQualificationFile(install.Review.Provider) != nil {
		return nil, nil, errQualificationAdmissionUnavailable
	}
	now := time.Now()
	if _, err := stage2aQualificationReservationJoinV3(expected,
		stage2aQualificationSessionResultV1{begin: begin, startedAt: now, eofObservedAt: now}, raw, key); err != nil {
		return nil, nil, err
	}
	// Consume the exact A-owned start before Q can connect. A failed spawn,
	// handshake or daemon restart leaves this session unavailable for replay.
	if err := claimStage2aQualificationSessionV3(store, begin, raw); err != nil {
		return nil, nil, err
	}
	listener, err := newStage2aQualificationListenerV1(stage2aQualificationQSocket, install.GID)
	if err != nil {
		return nil, nil, err
	}
	defer listener.close()
	session, wait, err := spawnStage2aQualificationQ(ctx, install, listener, begin)
	if err != nil {
		return nil, nil, err
	}
	_, joinErr := stage2aQualificationReservationJoinV3(expected,
		stage2aQualificationSessionResultV1{
			begin: session.begin, startedAt: session.started, eofObservedAt: session.started,
		}, raw, key)
	if err := checkLiveRun(); err != nil || joinErr != nil || session.peer.recheck() != nil ||
		bindStage2aQualificationSessionV3(store, session.begin, session.challengeSHA256, session.peer, raw) != nil ||
		checkLiveRun() != nil {
		session.close()
		_ = wait()
		return nil, nil, errQualificationAdmissionUnavailable
	}
	return session, wait, nil
}

func stage2aQualificationAssignmentMatchesQInstall(assignment stage2aReservationAssignmentV3,
	install stage2aQualificationQInstall, startID string) bool {
	return assignment.MachineUID == install.AdminUID && assignment.HQUID == install.HQUID &&
		assignment.RunnerGID == install.RunnerGID && assignment.BridgeGID == install.BridgeGID &&
		assignment.PlanDigest == install.Review.InstalledPlanDigest && assignment.StartID == startID
}
