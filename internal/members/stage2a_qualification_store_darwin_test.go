//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
)

func TestStage2aStoredARecordRequiresPinnedSignature(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signStage2aEnvelope(map[string]any{"kind": "fixture"}, 1, Stage2aStopPurpose, pub,
		func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aStoredARecordV3(signed, Stage2aStopPurpose, 1, pub); err != nil {
		t.Fatal("valid pinned record refused", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyStage2aStoredARecordV3(signed, Stage2aStopPurpose, 1, other); err == nil {
		t.Fatal("wrong Machine key accepted")
	}
	if _, err := verifyStage2aStoredARecordV3(signed, Stage2aFinalizationPurpose, 1, pub); err == nil {
		t.Fatal("wrong purpose accepted")
	}
	changed := append(append([]byte{}, signed...), ' ')
	if _, err := verifyStage2aStoredARecordV3(changed, Stage2aStopPurpose, 1, pub); err == nil {
		t.Fatal("noncanonical envelope accepted")
	}
}

func TestStage2aQualificationStopBindsBarePlanDigest(t *testing.T) {
	req, in, _, _ := stage2aReservationFixture()
	q := Stage2aStopRequest{
		InstallationID: req.start.InstallationID, StartID: req.start.StartID,
		LaunchID: req.launchID, PlanID: in.planID, PlanDigest: req.start.PlanDigest,
		HQEpoch: req.start.HQEpoch,
	}
	if !stage2aQualificationStopBindsInstalled(in.binding, q) {
		t.Fatal("valid bare installed plan digest refused")
	}
	q.PlanDigest = "sha256:" + q.PlanDigest
	if stage2aQualificationStopBindsInstalled(in.binding, q) {
		t.Fatal("prefixed plan digest accepted as the installed bare digest")
	}
}

func TestStage2aQualificationSignedAChainAndStoredReservation(t *testing.T) {
	req, in, key, _ := stage2aReservationFixture()
	pub := key.Public().(ed25519.PublicKey)
	sign := func(raw []byte) ([]byte, error) { return ed25519.Sign(key, raw), nil }
	reservationPayload := stage2aReservationPayload{Assignment: stage2aReservationAssignment{
		SoulStartAssignment: SoulStartAssignment{
			InstallationID: req.start.InstallationID, StartID: req.start.StartID,
			LaunchID: req.launchID, PlanID: in.planID, PlanDigest: req.start.PlanDigest,
			HQEpoch: req.start.HQEpoch,
		}}, MeasurementBinding: in.binding}
	reservation, err := signStage2aEnvelope(reservationPayload, 2, stage2aAdminReservationPurpose, pub, sign)
	if err != nil {
		t.Fatal(err)
	}
	q := Stage2aStopRequest{ReservationSHA256: stage2aQualificationSHA256(reservation),
		InstallationID: req.start.InstallationID, StartID: req.start.StartID,
		LaunchID: req.launchID, PlanID: in.planID, PlanDigest: req.start.PlanDigest,
		HQEpoch: req.start.HQEpoch}
	finalization, err := signStage2aEnvelope(Stage2aFinalizationPayload{Stage2aStopRequest: q},
		1, Stage2aFinalizationPurpose, pub, sign)
	if err != nil {
		t.Fatal(err)
	}
	stopPayload := Stage2aStopPayload{ReservationSHA256: q.ReservationSHA256,
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch, BothUIDsIdle: true}
	stop, err := signStage2aEnvelope(stopPayload, 1, Stage2aStopPurpose, pub, sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStage2aQualificationARecordChainV3(q, in.binding, reservation, finalization, stop, pub); err != nil {
		t.Fatal("valid signed A chain refused", err)
	}
	dir, gid := stage2aReservationTestDir(t)
	name := ".stage2a-admin-envelope-" + soulStartClaimName(q.InstallationID, q.StartID)
	if err := commitStage2aReservation(dir, name, reservation); err != nil {
		t.Fatal(err)
	}
	if err := stage2aExactAdminRecord(dir, name, uint32(os.Getuid()), gid, reservation, 64<<10); err != nil {
		t.Fatal("valid stored A reservation refused", err)
	}
	q.ReservationSHA256 = "sha256:" + strings.Repeat("0", 64)
	if verifyStage2aQualificationARecordChainV3(q, in.binding, reservation, finalization, stop, pub) == nil {
		t.Fatal("spliced reservation digest accepted")
	}
	q.ReservationSHA256 = stage2aQualificationSHA256(reservation)
	stopPayload.BothUIDsIdle = false
	badStop, err := signStage2aEnvelope(stopPayload, 1, Stage2aStopPurpose, pub, sign)
	if err != nil || verifyStage2aQualificationARecordChainV3(q, in.binding, reservation, finalization, badStop, pub) == nil {
		t.Fatal("signed stop without idle proof accepted", err)
	}
}

func TestStage2aQualificationSessionBindsExactReservationAndSoul(t *testing.T) {
	req, in, _, _ := stage2aReservationFixture()
	reservationSHA := "sha256:" + strings.Repeat("a", 64)
	testPlanSHA := "sha256:" + strings.Repeat("b", 64)
	sourceSHA := "sha256:" + strings.Repeat("c", 64)
	q := Stage2aStopRequest{ReservationSHA256: reservationSHA,
		InstallationID: req.start.InstallationID, StartID: req.start.StartID}
	result := stage2aQualificationSessionResultV1{
		begin: stage2aQualificationBeginV1{CohortID: "reviewed-cohort", InstallationID: q.InstallationID,
			SoulID: in.binding.SoulID, StartID: q.StartID, HostID: in.binding.HostID,
			Profile: in.binding.ProfileInForce, ReservationSHA256: reservationSHA,
			TestPlanSHA256: testPlanSHA, PathRoots: []string{"/private/tmp"}, QUID: 650, QGID: 651},
		peer: stage2aQualificationPeerV1{uid: 650, gid: 651}, sourceSHA256: sourceSHA,
	}
	check := func() bool {
		return stage2aQualificationSessionBindsRun(result, q, in.binding, sourceSHA,
			testPlanSHA, "reviewed-cohort", []string{"/private/tmp"}, 650, 651)
	}
	if !check() {
		t.Fatal("exact A/Q session refused")
	}
	result.begin.ReservationSHA256 = "sha256:" + strings.Repeat("d", 64)
	if check() {
		t.Fatal("Q session for another reservation accepted")
	}
	result.begin.ReservationSHA256 = reservationSHA
	result.begin.SoulID = "other-soul"
	if check() {
		t.Fatal("Q session for another Soul accepted")
	}
	result.begin.SoulID = in.binding.SoulID
	result.begin.CohortID = "other-cohort"
	if check() {
		t.Fatal("Q session for another cohort accepted")
	}
}

func TestStage2aQualificationTranscriptRejectsReplay(t *testing.T) {
	session := strings.Repeat("a", 32)
	challenge := "sha256:" + strings.Repeat("b", 64)
	frame := map[string]any{
		"schema": stage2aQualificationSchemaV1, "kind": "observation", "session_id": session,
		"challenge_sha256": challenge, "sequence": 1, "request_sha256": "sha256:" + strings.Repeat("c", 64),
		"captured_at": "2026-11-22T20:00:00.120Z", "gate": "T01", "phase": "before", "event_id": "event-1",
		"processes": []any{}, "paths": []any{},
	}
	var stream bytes.Buffer
	if _, err := writeStage2aQualificationFrame(&stream, frame); err != nil {
		t.Fatal(err)
	}
	raw := stream.Bytes()
	if n, err := stage2aQualificationTranscriptV1(raw, session, challenge); err != nil || n != 1 {
		t.Fatal("valid raw observation refused", err)
	}
	if _, err := stage2aQualificationTranscriptV1(append(append([]byte{}, raw...), raw...), session, challenge); err == nil {
		t.Fatal("replayed sequence accepted")
	}
	if _, err := stage2aQualificationTranscriptV1(raw, strings.Repeat("d", 32), challenge); err == nil {
		t.Fatal("wrong session accepted")
	}
	if _, err := stage2aQualificationTranscriptV1(raw[:len(raw)-1], session, challenge); err == nil {
		t.Fatal("truncated frame accepted")
	}
	frame["other"] = true
	stream.Reset()
	if _, err := writeStage2aQualificationFrame(&stream, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := stage2aQualificationTranscriptV1(stream.Bytes(), session, challenge); err == nil {
		t.Fatal("extra field accepted")
	}
}
