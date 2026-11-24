package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDirectQFinishRequiresWitnessInsteadOfCallerReceipt(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	q := Stage2aDirectQFinishRequestV3{
		SoulCooperativeLiveRequestV3: SoulCooperativeLiveRequestV3{
			Stage2aStopRequest: Stage2aStopRequest{
				ReservationSHA256: digest, InstallationID: "inst_0000000000000001",
				StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
				PlanID: "plan-20261122T141516Z-abcd", PlanDigest: strings.Repeat("b", 64),
				HQEpoch: strings.Repeat("f", 64)}, AttachSHA256: digest},
		PreResponseSHA256: digest, WitnessSHA256: digest}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aDirectQFinishRequestV3(raw); err != nil {
		t.Fatalf("witness-bound finish refused: %v", err)
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid fixture")
	}
	delete(fields, "witness_sha256")
	fields["hq_refusal_receipt_base64url"] = "eyJraW5kIjoicHJvZmlsZV9pbnN1ZmZpY2llbnQifQ"
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStage2aDirectQFinishRequestV3(raw); err == nil {
		t.Fatal("caller supplied refusal accepted without A witness")
	}
}
