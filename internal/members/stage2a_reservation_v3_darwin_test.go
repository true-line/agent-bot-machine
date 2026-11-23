package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Public synthetic wire fixture from Soul Contracts #69 at 86290ad420a7.
// It carries neither machine custody, qualification nor physical evidence.
func TestStage2aReservationV3ContractEnvelope(t *testing.T) {
	var vector struct {
		Envelope    string `json:"reservation_envelope_jcs"`
		Payload     string `json:"reservation_payload_jcs"`
		Key         string `json:"issuer_public_key_base64url"`
		At          string `json:"verification_at"`
		HEnvelope   string `json:"h_envelope_jcs"`
		RInventory  string `json:"r_inventory_jcs"`
		AdapterCode string `json:"adapter_code_inputs_jcs"`
	}
	bytesOnDisk, err := os.ReadFile("testdata/stage2a-reservation-v3-contract.json")
	if err != nil || stage2aDecodeExact(bytesOnDisk, &vector) != nil {
		t.Fatal("invalid fixture", err)
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(vector.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatal("invalid fixture key", err)
	}
	now, err := time.Parse(time.RFC3339Nano, vector.At)
	if err != nil {
		t.Fatal(err)
	}
	var expected stage2aReservationPayloadV3
	if err := stage2aDecodeExact([]byte(vector.Payload), &expected); err != nil {
		t.Fatal(err)
	}
	canonical, err := marshalStage2aReservationJCS(expected)
	if err != nil || !bytes.Equal(canonical, []byte(vector.Payload)) {
		t.Fatal("Machine wire differs from Contracts", err)
	}
	h, digestH, err := stage2aDecodeHDescriptorV3([]byte(vector.HEnvelope), pub)
	if err != nil || digestH != expected.Assignment.HDescriptorDigest || h.HostID != expected.HostID {
		t.Fatal("H descriptor differs from the reservation binding", err)
	}
	runtimeInventory, _, err := stage2aDomainInventoryDigestV3([]byte(vector.RInventory))
	var code []string
	if err != nil || stage2aDecodeExact([]byte(vector.AdapterCode), &code) != nil {
		t.Fatal("invalid R or adapter fixture", err)
	}
	projected := stage2aReservationEvidenceV3{r: stage2aVerifiedDomainRefV3{ref: expected.MeasurementBinding.RInventory},
		base: stage2aReservationInputs{binding: expected.MeasurementBinding.Stage2aMeasurementBinding}, rInventory: runtimeInventory,
		rComponents: expected.MeasurementBinding.RComponents, broker: expected.MeasurementBinding.Broker,
		adapter: expected.MeasurementBinding.Adapter, adapterCode: code}
	if err := stage2aCheckReservationREvidence(projected); err != nil {
		t.Fatal("published R adapter rows differ from the reviewed wire", err)
	}
	projected.adapterCode = append([]string(nil), code...)
	projected.adapterCode[0] = projected.adapter.ExecutablePath + ".changed"
	if err := stage2aCheckReservationREvidence(projected); err == nil {
		t.Fatal("accepted code outside the exact approved adapter closure")
	}
	raw := []byte(vector.Envelope)
	digest := stage2aReservationSHA256(raw)
	if _, err := verifyStage2aReservationModeV3(stage2aQualifiedRunV3, raw, digest, []byte(vector.Payload), pub, now); err != nil {
		t.Fatal("matching signed mode refused", err)
	}
	for _, mode := range []stage2aReservationRunModeV3{stage2aCandidateRunV3, "", "machine/v2"} {
		if _, err := verifyStage2aReservationModeV3(mode, raw, digest, []byte(vector.Payload), pub, now); err == nil {
			t.Fatalf("mismatched or missing run mode accepted: %q", mode)
		}
	}
	if err := verifyStage2aReservationV3(raw, digest, expected, pub, now); err != nil {
		t.Fatal(err)
	}
	if err := verifyStage2aReservationV3(raw, stage2aV3PurposeDigest(stage2aReservationPurposeV3, canonical), expected, pub, now); err == nil {
		t.Fatal("accepted a purpose digest as the complete Q reservation digest")
	}
	for name, mutate := range map[string]func(*stage2aReservationPayloadV3){
		"host": func(p *stage2aReservationPayloadV3) { p.HostID = "wrong-host" },
		"owner receipt": func(p *stage2aReservationPayloadV3) {
			p.InstalledPlanReceiptSHA256 = "sha256:" + strings.Repeat("0", 64)
		},
		"H descriptor": func(p *stage2aReservationPayloadV3) {
			p.Assignment.HDescriptorDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"R owner approval": func(p *stage2aReservationPayloadV3) {
			p.MeasurementBinding.RInventory.OwnerPlanDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"adapter source": func(p *stage2aReservationPayloadV3) {
			p.MeasurementBinding.RComponents[0].SourceCommit = strings.Repeat("0", 40)
		},
		"admission challenge": func(p *stage2aReservationPayloadV3) { p.AdmissionChallengeSHA256 = "sha256:" + strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var changed stage2aReservationPayloadV3
			if err := json.Unmarshal(canonical, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := verifyStage2aReservationV3(raw, digest, changed, pub, now); err == nil {
				t.Fatal("accepted a changed expected binding")
			}
		})
	}
	v2Purpose := bytes.Replace(raw, []byte(stage2aReservationPurposeV3), []byte(stage2aAdminReservationPurpose), 1)
	if err := verifyStage2aReservationV3(v2Purpose, stage2aReservationSHA256(v2Purpose), expected, pub, now); err == nil {
		t.Fatal("accepted v2 purpose as protected v3")
	}
	if err := verifyStage2aReservationV3(raw, digest, expected, pub, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted an expired reservation")
	}
}

func TestStage2aReserveRequiresV3Authority(t *testing.T) {
	// The default service keeps positive protected issuance disabled until the
	// offline v3 installed-authority worker is configured.
	service := NewStage2aService(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	epoch := strings.Repeat("a", 64)
	reply, err := service.Reserve(309, epoch, Stage2aReserveRequest{HQEpoch: epoch,
		PlanDigest: strings.Repeat("1", 64), InstallationID: "test-installation",
		StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567"})
	if err == nil || reply.EnvelopeBase64URL != "" || len(service.active) != 0 {
		t.Fatalf("protected reservation fell back without v3 authority: %+v, %v", reply, err)
	}
}
