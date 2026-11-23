package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestStage2aQualificationQCandidateReservationJoinUsesExactModeAndPlan(t *testing.T) {
	var fixture struct {
		Envelope string `json:"reservation_envelope_jcs"`
		Payload  string `json:"reservation_payload_jcs"`
	}
	raw, err := os.ReadFile("testdata/stage2a-qualification-candidate-v3-contract.json")
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("candidate fixture unavailable", err)
	}
	raw = []byte(fixture.Envelope)
	var wire stage2aSignedReservation
	var want stage2aQualificationCandidateReservationV3
	if stage2aDecodeExact(raw, &wire) != nil || stage2aDecodeExact([]byte(fixture.Payload), &want) != nil {
		t.Fatal("candidate fixture invalid")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(wire.IssuerPublicKeyBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.PublicKey(decoded)
	issued, err := time.Parse(time.RFC3339Nano, want.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	session := stage2aQualificationSessionResultV1{startedAt: issued.Add(time.Second), eofObservedAt: issued.Add(45 * time.Second),
		begin: stage2aQualificationBeginV1{
			ReservationSHA256: stage2aQualificationSHA256(raw), HostID: want.HostID,
			InstallationID: want.Assignment.InstallationID, SoulID: want.Assignment.SoulID, StartID: want.Assignment.StartID,
			Profile: want.MeasurementBinding.ProfileInForce, TestPlanSHA256: want.Attempt.TestPlanSHA256,
			SuiteRevision: want.Attempt.SuiteRevision,
		},
	}
	authority := stage2aQualificationReservationV3{mode: stage2aCandidateRunV3, candidate: &want}
	if challenge, err := stage2aQualificationReservationJoinV3(authority, session, raw, key); err != nil || challenge != want.AdmissionChallengeSHA256 {
		t.Fatalf("exact candidate wasn't joined: %s, %v", challenge, err)
	}
	authority.mode = stage2aQualifiedRunV3
	if _, err := stage2aQualificationReservationJoinV3(authority, session, raw, key); err == nil {
		t.Fatal("candidate reservation crossed into ordinary qualified mode")
	}
	authority.mode = stage2aCandidateRunV3
	session.begin.TestPlanSHA256 = "wrong-plan"
	if _, err := stage2aQualificationReservationJoinV3(authority, session, raw, key); err == nil {
		t.Fatal("candidate reservation joined a different Q test plan")
	}
	session.begin.TestPlanSHA256 = want.Attempt.TestPlanSHA256
	session.startedAt = issued.Add(time.Minute)
	session.eofObservedAt = session.startedAt.Add(time.Second)
	if _, err := stage2aQualificationReservationJoinV3(authority, session, raw, key); err == nil {
		t.Fatal("candidate reservation joined an expired start")
	}
}
