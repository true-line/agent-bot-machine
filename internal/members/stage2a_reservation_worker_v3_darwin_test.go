package members

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestStage2aReservationWorkerV3SelectorOnly(t *testing.T) {
	selector := Stage2aReserveRequest{
		PlanDigest: strings.Repeat("b", 64), InstallationID: "inst_0000000000000001",
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("a", 64),
		LaunchID: "ln_0123456789abcdef01234567",
	}
	rawSelector, err := json.Marshal(selector)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(raw json.RawMessage) []byte {
		t.Helper()
		payload, err := json.Marshal(stage2aReservationWorkerRequestV3{
			HQUID: 309, MachineFingerprint: strings.Repeat("c", 64), Selector: raw,
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	payload := encode(rawSelector)
	if _, got, err := decodeStage2aReservationWorkerRequestV3(payload); err != nil || got != selector {
		t.Fatalf("worker did not recover exact selector: %v", err)
	}
	for _, unknown := range []string{"adapter_release", "installed_policy_sha256", "measurement_binding", "mode"} {
		outer := append([]byte(`{"`+unknown+`":{},`), payload[1:]...)
		inner := append([]byte(`{"`+unknown+`":{},`), rawSelector[1:]...)
		for _, packet := range [][]byte{outer, encode(inner)} {
			if _, _, err := decodeStage2aReservationWorkerRequestV3(packet); err == nil {
				t.Fatalf("worker accepted caller-provided %s", unknown)
			}
		}
	}
	if err := runStage2aReservationWorkerV3(strings.NewReader(string(payload)), io.Discard, nil, nil); err == nil {
		t.Fatal("worker accepted request without the paired signer and installed runtime authority")
	}
}
