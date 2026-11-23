//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This synthetic replay pins the exact Contracts #89 wire shape. It does not
// substitute for the installed two-account qualification or relay proof.
func TestStage2aMemberHQFinalizationContract89Replay(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "stage2a-member-finalization-contract89.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RecordJCS         string `json:"record_jcs"`
		RequestJCS        string `json:"request_jcs"`
		AckEnvelopeJCS    string `json:"ack_envelope_jcs"`
		AckPayloadJCS     string `json:"ack_payload_jcs"`
		RuntimeRequestJCS string `json:"runtime_request_jcs"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	request, err := ParseStage2aMemberHQFinalizationRequest([]byte(fixture.RequestJCS))
	if err != nil {
		t.Fatalf("contract intake request: %v", err)
	}
	record, err := stage2aDecodeHQFinalizationRecord(request.FinalizationBase64URL,
		request.FinalizationSHA256)
	if err != nil || !bytes.Equal(record, []byte(fixture.RecordJCS)) {
		t.Fatalf("contract H record bytes: %v", err)
	}
	var h stage2aMemberHQFinalizationRecord
	if err := stage2aDecodeExact(record, &h); err != nil {
		t.Fatalf("contract H record fields: %v", err)
	}
	canonical, err := marshalStage2aReservationJCS(h)
	if err != nil || !bytes.Equal(canonical, record) ||
		h.HostID == "" || h.CommittedAt == "" ||
		h.Stage2aStopRequest != request.Stage2aStopRequest ||
		h.Members[0].MemberID >= h.Members[1].MemberID {
		t.Fatalf("contract H record canonical join: %v", err)
	}
	var envelope stage2aSignedReservation
	if err := stage2aDecodeExact([]byte(fixture.AckEnvelopeJCS), &envelope); err != nil {
		t.Fatalf("contract A ack envelope: %v", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(envelope.IssuerPublicKeyBase64URL)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("contract synthetic A key: %v", err)
	}
	payload, err := verifyStage2aStoredARecordV3([]byte(fixture.AckEnvelopeJCS),
		Stage2aMemberHQFinalizationAckPurpose, 1, ed25519.PublicKey(key))
	if err != nil || !bytes.Equal(payload, []byte(fixture.AckPayloadJCS)) {
		t.Fatalf("contract A ack signature/payload: %v", err)
	}
	var ack stage2aMemberHQFinalizationAckPayload
	if err := stage2aDecodeExact(payload, &ack); err != nil ||
		ack.HQFinalizationSHA256 != request.FinalizationSHA256 ||
		ack.ReadyEnvelopeSHA256 != h.ReadyEnvelopeSHA256 ||
		ack.ChildObservationEnvelopeSHA256 != h.ChildObservationEnvelopeSHA256 {
		t.Fatalf("contract A ack joins: %v", err)
	}
	runtime, err := ParseStage2aMemberRuntimeRequest([]byte(fixture.RuntimeRequestJCS))
	if err != nil || runtime.HQFinalizationSHA256 != request.FinalizationSHA256 ||
		runtime.HQFinalizationBase64URL != request.FinalizationBase64URL {
		t.Fatalf("contract renewed H record bytes: %v", err)
	}
	runtime.HQFinalizationBase64URL = base64.RawURLEncoding.EncodeToString([]byte(`{"changed":true}`))
	changed, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aMemberRuntimeRequest(changed); err == nil {
		t.Fatal("changed H record accepted under the committed digest")
	}
}
