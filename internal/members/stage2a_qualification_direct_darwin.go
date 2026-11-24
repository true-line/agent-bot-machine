//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"
)

func stage2aDirectQSessionName(installationID, startID string) string {
	return ".cooperative-q-session-" + soulStartClaimName(installationID, startID)
}

func stage2aDirectQBindingName(installationID, startID string) string {
	return ".cooperative-q-binding-" + soulStartClaimName(installationID, startID) + ".json"
}

// A direct T21 observer is joined to the signed cooperative reservation, not
// to a protected B reservation. A obtains every Q selector from the retained
// owner review and the installed cooperative authority.
func stage2aDirectQualificationBeginV3(live *soulCooperativeLiveV3,
	reservation soulCooperativeReservationPayloadV3, install stage2aQualificationQInstall,
	request QualificationRequest, owner string, now time.Time) (stage2aQualificationBeginV1, error) {
	var empty stage2aQualificationBeginV1
	issued, issuedErr := time.Parse(time.RFC3339Nano, reservation.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if live == nil {
		return empty, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(live.installed.RootReceipt, &receipt) != nil {
		return empty, errSoulCooperativeAuthority
	}
	if !live.attached || now.IsZero() ||
		issuedErr != nil || expiresErr != nil || expires.Sub(issued) != 30*time.Second ||
		now.Before(issued) ||
		live.digest != stage2aQualificationSHA256(live.envelope) ||
		reservation.Contract != "machine/v3" || reservation.Kind != "soul-cooperative-reservation" ||
		reservation.SchemaVersion != 3 || reservation.AdapterTransport != stage2aDirectComms ||
		reservation.MeasurementBinding.ProfileInForce != "managed-cooperative" ||
		reservation.Assignment.InstallationID != live.request.InstallationID ||
		reservation.Assignment.StartID != live.request.StartID ||
		reservation.Assignment.LaunchID != live.request.LaunchID ||
		reservation.Assignment.PlanDigest != live.request.PlanDigest ||
		reservation.Assignment.PlanID != receipt.PlanID ||
		reservation.Assignment.PlanDigest != receipt.PlanDigest ||
		receipt.Owner != owner ||
		reservation.Assignment.HQEpoch != live.request.HQEpoch ||
		reservation.Assignment.RunnerUID != live.installed.Policy.Runner.UID ||
		reservation.Assignment.RunnerGID != live.installed.Policy.Runner.GID ||
		reservation.Assignment.HQUID != live.installed.Policy.HQUID ||
		reservation.Assignment.MachineUID != live.installed.Policy.MachineUID ||
		reservation.HostID != live.installed.Policy.HostID ||
		reservation.AdmissionChallengeSHA256 != live.request.AdmissionChallengeSHA256 ||
		reservation.MeasurementBinding.RInventory != live.installed.RuntimeV3 ||
		reservation.MeasurementBinding.HDescriptorDigest != live.hDescriptorDigest ||
		reservation.MeasurementBinding.InstallationID != live.request.InstallationID ||
		reservation.MeasurementBinding.StartID != live.request.StartID ||
		reservation.MeasurementBinding.LaunchID != live.request.LaunchID ||
		reservation.MeasurementBinding.SoulID != reservation.Assignment.SoulID ||
		reservation.MeasurementBinding.HostID != reservation.HostID ||
		reservation.MeasurementBinding.HQEpoch != live.request.HQEpoch ||
		reservation.MeasurementBinding.InstalledPlanDigest != live.request.PlanDigest ||
		reservation.MeasurementBinding.PlanID != reservation.Assignment.PlanID ||
		!soulIdentity.MatchString(reservation.Assignment.SoulID) {
		return empty, errSoulCooperativeAuthority
	}
	if _, err := cooperativeQualificationHarnessV3(install, request,
		live.installed.Policy, owner, live.request.PlanDigest,
		live.installed.RuntimeV3.InventoryDigest); err != nil ||
		install.Source.SHA256 != request.Runner.BinarySHA ||
		install.Review.TestPlan != request.Candidate.TestPlan {
		return empty, errSoulCooperativeAuthority
	}
	return stage2aQualificationBeginV1{
		CohortID: install.Review.PlanID, InstallationID: live.request.InstallationID,
		SoulID: reservation.Assignment.SoulID, StartID: live.request.StartID,
		HostID: reservation.HostID, Profile: "managed-cooperative",
		ReservationSHA256: live.digest,
		TestPlanSHA256:    "sha256:" + install.Review.TestPlan.SHA256,
		SuiteRevision:     request.SuiteRevision,
		PSSHA256:          "sha256:" + install.PS.SHA256,
		PathRoots:         slices.Clone(install.Roots), QUID: install.UID, QGID: install.GID,
		DeadlineAt: now.UTC().Add(2 * time.Minute).Truncate(time.Second).Format(time.RFC3339),
	}, nil
}

// The private cooperative journal must contain this exact signed envelope.
// Spending the Q name before spawn makes a failed handshake and a restart
// terminal for this start. Protected claim names are deliberately unused.
func claimStage2aDirectQSessionV3(store stage2aAdminClaimStore, live *soulCooperativeLiveV3,
	key ed25519.PublicKey) error {
	if live == nil || !live.attached || live.digest != stage2aQualificationSHA256(live.envelope) ||
		len(live.envelope) == 0 || len(live.envelope) > 48<<10 {
		return errSoulCooperativeAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, live.request.InstallationID)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, live.request.InstallationID, live.request.StartID) != nil ||
		stage2aCheckSpentClaim(dir, cooperativeSpentName(live.request.InstallationID, live.request.StartID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, cooperativeAttachedName(live.request.InstallationID, live.request.StartID), store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, stage2aDirectQSessionName(live.request.InstallationID, live.request.StartID)) != nil {
		return errSoulCooperativeAuthority
	}
	_, journal, reserved, err := readSoulCooperativeRecoveryRequest(dir, store,
		live.request.InstallationID, live.request.StartID, live.installed.Policy, key)
	if err != nil || journal.ReservationSHA256 != live.digest ||
		journal.ReservationEnvelopeBase64URL != base64.RawURLEncoding.EncodeToString(live.envelope) ||
		reserved.Assignment.StartID != live.request.StartID ||
		reserved.Assignment.LaunchID != live.request.LaunchID {
		return errSoulCooperativeAuthority
	}
	return spendStage2aAdminName(dir, stage2aDirectQSessionName(live.request.InstallationID,
		live.request.StartID), store.uid, store.gid)
}

func bindStage2aDirectQSessionV3(store stage2aAdminClaimStore, live *soulCooperativeLiveV3,
	session *stage2aQualificationSessionV1) error {
	if live == nil || session == nil || !live.attached ||
		session.begin.ReservationSHA256 != live.digest ||
		session.begin.InstallationID != live.request.InstallationID ||
		session.begin.StartID != live.request.StartID {
		return errSoulCooperativeAuthority
	}
	record, err := stage2aQualificationSessionBindingBytes(session.begin,
		session.challengeSHA256, session.peer)
	if err != nil || len(record) > 8192 {
		return errSoulCooperativeAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, live.request.InstallationID)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, live.request.InstallationID, live.request.StartID) != nil ||
		stage2aCheckSpentClaim(dir, stage2aDirectQSessionName(live.request.InstallationID, live.request.StartID), store.uid, store.gid) != nil {
		return errSoulCooperativeAuthority
	}
	return commitStage2aReservation(dir,
		stage2aDirectQBindingName(live.request.InstallationID, live.request.StartID), record)
}

// openStage2aDirectQualificationObserverV3 is the A-local Q caller for the
// HQ-started, direct-Comms cooperative route. It returns no verdict. The
// caller must retain the session in A, choose T21 observations from an exact
// reviewed case plan, and require independent physical proof before a report.
func openStage2aDirectQualificationObserverV3(ctx context.Context, live *soulCooperativeLiveV3,
	key ed25519.PublicKey, checkLive func() error) (*stage2aQualificationSessionV1, func() error, error) {
	if ctx == nil || checkLive == nil || checkLive() != nil ||
		live == nil || !live.attached || len(key) != ed25519.PublicKeySize ||
		stage2aRecheckVerifiedDomainV3(live.h) != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	installed, r, err := loadSoulCooperativeInstalledV3(key,
		live.installed.Policy.HQUID, live.request.HQEpoch, live.request.InstallationID)
	if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
		stage2aRecheckVerifiedDomainV3(r) != nil || r.ref != live.installed.RuntimeV3 {
		return nil, nil, errSoulCooperativeAuthority
	}
	canonical, digest, err := verifySoulCooperativeEnvelopeV3(live.envelope, key)
	var reservation soulCooperativeReservationPayloadV3
	if err != nil || digest != live.digest || json.Unmarshal(canonical, &reservation) != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(installed.RootReceipt, &receipt) != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	install, request, err := loadStage2aQualificationQAuthority(ctx)
	if err != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	_, inventoryRaw, err := stage2aV3SidecarAt(r.ref.Sidecar.Path,
		uint32(installed.Policy.MachineUID), uint32(installed.Policy.Runner.GID))
	var inventory stage2aDomainInventoryV3
	if err != nil || json.Unmarshal(inventoryRaw, &inventory) != nil ||
		!cooperativeQualificationCodeInputsMatch(installed.Policy, inventory,
			request.Adapter.Launch.CodeInputs) {
		return nil, nil, errSoulCooperativeAuthority
	}
	begin, err := stage2aDirectQualificationBeginV3(live, reservation, install, request, receipt.Owner, time.Now())
	if err != nil {
		return nil, nil, err
	}
	store := installed.claimStore()
	if checkLive() != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	listener, err := newStage2aQualificationListenerV1(stage2aQualificationQSocket, install.GID)
	if err != nil {
		return nil, nil, errSoulCooperativeAuthority
	}
	defer listener.close()
	session, wait, err := spawnStage2aQualificationQ(ctx, install, listener, begin)
	if err != nil {
		return nil, nil, err
	}
	if checkLive() != nil || session.peer.recheck() != nil ||
		func() error {
			_, e := stage2aDirectQualificationBeginV3(live, reservation, install,
				request, receipt.Owner, session.started)
			return e
		}() != nil ||
		bindStage2aDirectQSessionV3(store, live, session) != nil || checkLive() != nil {
		session.close()
		_ = wait()
		return nil, nil, errSoulCooperativeAuthority
	}
	return session, wait, nil
}

func checkStage2aDirectQBindingV3(dir *os.File, store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1) error {
	begin := session.begin
	record, err := stage2aQualificationSessionBindingBytes(begin,
		session.challengeSHA256, session.peer)
	if err != nil || len(record) > 8192 ||
		stage2aCheckSpentClaim(dir, stage2aDirectQSessionName(begin.InstallationID, begin.StartID),
			store.uid, store.gid) != nil ||
		stage2aExactAdminRecord(dir, stage2aDirectQBindingName(begin.InstallationID, begin.StartID),
			store.uid, store.gid, record, 8192) != nil {
		return errSoulCooperativeAuthority
	}
	return nil
}

// A publishes the exact Q frames and two signed commitments while this
// cooperative start is still active. The EOF receipt is the last durable
// write. These artifacts remain evidence inputs, never a T21 pass verdict.
func persistStage2aDirectQualificationPreSignV3(store stage2aAdminClaimStore,
	live *soulCooperativeLiveV3, session stage2aQualificationSessionResultV1,
	install stage2aQualificationQInstall, request QualificationRequest, owner string,
	now time.Time, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (stage2aQualificationPreSignArtifactsV1, error) {
	var empty stage2aQualificationPreSignArtifactsV1
	if live == nil || !live.attached || session.startedAt.IsZero() ||
		session.eofObservedAt.After(now) || session.begin.RequireArgvProof != true ||
		stage2aQualificationSHA256(live.envelope) != live.digest ||
		verifyStage2aQualificationPairedFramesV1(session) != nil {
		return empty, errSoulCooperativeAuthority
	}
	canonical, digest, err := verifySoulCooperativeEnvelopeV3(live.envelope, key)
	var reservation soulCooperativeReservationPayloadV3
	if err != nil || digest != live.digest || json.Unmarshal(canonical, &reservation) != nil {
		return empty, errSoulCooperativeAuthority
	}
	expected, err := stage2aDirectQualificationBeginV3(live, reservation,
		install, request, owner, session.startedAt)
	if err != nil || session.begin.CohortID != expected.CohortID ||
		session.begin.InstallationID != expected.InstallationID ||
		session.begin.SoulID != expected.SoulID || session.begin.StartID != expected.StartID ||
		session.begin.HostID != expected.HostID || session.begin.Profile != expected.Profile ||
		session.begin.ReservationSHA256 != expected.ReservationSHA256 ||
		session.begin.TestPlanSHA256 != expected.TestPlanSHA256 ||
		session.begin.SuiteRevision != expected.SuiteRevision ||
		session.begin.PSSHA256 != expected.PSSHA256 ||
		!slices.Equal(session.begin.PathRoots, expected.PathRoots) ||
		session.begin.QUID != expected.QUID || session.begin.QGID != expected.QGID ||
		session.sourceSHA256 != "sha256:"+install.Source.SHA256 ||
		session.peer.uid != install.UID || session.peer.gid != install.GID ||
		!validStage2aQualificationBeginV1(session.begin, session.startedAt) {
		return empty, errSoulCooperativeAuthority
	}
	dir, err := store.open()
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, session.begin.InstallationID)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil ||
		cooperativeActiveClaimMatches(dir, store, session.begin.InstallationID,
			session.begin.StartID) != nil ||
		checkStage2aDirectQBindingV3(dir, store, session) != nil {
		return empty, errSoulCooperativeAuthority
	}
	wire, index, eof, err := issueStage2aQualificationPreSignV1(session,
		reservation.AdmissionChallengeSHA256, now, key, sign)
	if err != nil {
		return empty, errSoulCooperativeAuthority
	}
	prefix := ".cooperative-q-" + soulStartClaimName(session.begin.InstallationID,
		session.begin.StartID) + "-" + session.begin.SessionID
	result := stage2aQualificationPreSignArtifactsV1{
		WirePath: filepath.Join(store.path, prefix+"-wire.json"), WireSHA256: stage2aQualificationSHA256(wire),
		IndexPath: filepath.Join(store.path, prefix+"-index.json"), IndexSHA256: stage2aQualificationSHA256(index),
		EOFReceiptPath: filepath.Join(store.path, prefix+"-eof.json"), EOFReceiptSHA256: stage2aQualificationSHA256(eof),
	}
	if commitStage2aReservation(dir, filepath.Base(result.WirePath), wire) != nil ||
		commitStage2aReservation(dir, filepath.Base(result.IndexPath), index) != nil ||
		commitStage2aReservation(dir, filepath.Base(result.EOFReceiptPath), eof) != nil {
		return empty, errSoulCooperativeAuthority
	}
	return result, nil
}
