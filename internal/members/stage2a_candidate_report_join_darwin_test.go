package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestStage2aCandidateReportJoinV3(t *testing.T) {
	load := func(file string, target any) {
		t.Helper()
		raw, err := os.ReadFile("testdata/" + file)
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatalf("invalid fixture %s: %v", file, err)
		}
	}
	var candidate, ordinary struct {
		Envelope string `json:"reservation_envelope_jcs"`
		Key      string `json:"issuer_public_key_base64url"`
	}
	load("stage2a-qualification-candidate-v3-contract.json", &candidate)
	load("stage2a-reservation-v3-contract.json", &ordinary)
	pin, err := base64.RawURLEncoding.Strict().DecodeString(ordinary.Key)
	if err != nil || len(pin) != ed25519.PublicKeySize {
		t.Fatal("invalid fixture pin", err)
	}
	report, err := os.ReadFile("testdata/stage2a-candidate-host-summary-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStage2aCandidateReportJoinV3(report, []byte(candidate.Envelope), pin); err != nil {
		t.Fatal("exact signed candidate projection refused", err)
	}
	for _, pair := range [][2]string{
		{`"contract":"machine/v2"`, `"contract":"machine/v3"`},
		{`"kind":"stage2a-measurement-binding"`, `"kind":"stage2a-qualification-candidate-binding"`},
		{`"host_id":"synthetic-host"`, `"host_id":"substituted-host"`},
		{stage2aReservationSHA256([]byte(candidate.Envelope)), stage2aReservationSHA256([]byte(ordinary.Envelope))},
		{`"challenge_sha256":"sha256:`, `"challenge_sha256":"sha256:0`},
	} {
		changed := bytes.Replace(report, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(changed, report) || VerifyStage2aCandidateReportJoinV3(changed, []byte(candidate.Envelope), pin) == nil {
			t.Fatalf("accepted changed summary field %s", pair[0])
		}
	}
	if VerifyStage2aCandidateReportJoinV3(report, []byte(ordinary.Envelope), pin) == nil {
		t.Fatal("ordinary v3 reservation authorized candidate report")
	}
}
