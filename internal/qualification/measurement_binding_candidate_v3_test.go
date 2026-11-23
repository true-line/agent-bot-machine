package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func candidateContractBindingV3(t *testing.T) []byte {
	t.Helper()
	vector, err := os.ReadFile("testdata/stage2a-candidate-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ReservationPayloadJCS string `json:"reservation_payload_jcs"`
	}
	if json.Unmarshal(vector, &v) != nil {
		t.Fatal("invalid Contracts v0.9.0 candidate fixture")
	}
	fields, err := canonicalBytes([]byte(v.ReservationPayloadJCS), MaxReportBytes)
	if err != nil {
		t.Fatal(err)
	}
	return fields["measurement_binding"]
}

func TestCandidateMeasurementBindingV3ContractVector(t *testing.T) {
	raw := candidateContractBindingV3(t)
	binding, err := parseCandidateMeasurementBindingV3(raw)
	if err != nil {
		t.Fatalf("rejected Contracts v0.9.0 candidate binding: %v", err)
	}
	if binding.Base.Kind != "stage2a-qualification-candidate-binding" ||
		binding.CandidateAdapter.ComponentID != "adapter" ||
		binding.RInventory.Domain != "R-runtime" {
		t.Fatal("candidate binding lost selected identity")
	}
	legacy, err := parseMeasurementBindingV2(binding.ReportProjection)
	if err != nil || legacy.Contract != "machine/v2" ||
		legacy.Kind != "stage2a-measurement-binding" || legacy.SchemaVersion != 2 ||
		legacy.InstallationID != binding.Base.InstallationID ||
		legacy.PackageSHA256 != binding.Base.PackageSHA256 ||
		legacy.SoulArtifactSHA256 != binding.Base.SoulArtifactSHA256 {
		t.Fatal("candidate report projection changed common Soul identity")
	}
	if bytes.Contains(binding.ReportProjection, []byte("candidate_adapter")) ||
		bytes.Contains(binding.ReportProjection, []byte("adapter_release")) ||
		bytes.Contains(binding.ReportProjection, []byte("r_inventory")) {
		t.Fatal("candidate authority leaked into report summary")
	}
	for name, mutate := range map[string]func(map[string]any){
		"ordinary release injection": func(v map[string]any) {
			v["adapter_release"] = v["candidate_adapter"]
		},
		"unapproved build root injection": func(v map[string]any) {
			v["candidate_adapter"].(map[string]any)["candidate_build_attestation_sha256"] = "sha256:" + string(bytes.Repeat([]byte("a"), 64))
		},
		"wrong R artifact": func(v map[string]any) {
			v["candidate_adapter"].(map[string]any)["package_sha256"] = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		},
		"wrong R manifest": func(v map[string]any) {
			v["candidate_adapter"].(map[string]any)["candidate_manifest_sha256"] = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		},
		"ordinary kind": func(v map[string]any) { v["kind"] = "stage2a-measurement-binding" },
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("invalid candidate fixture")
			}
			mutate(value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseCandidateMeasurementBindingV3(changed); err == nil {
				t.Fatal("accepted changed candidate binding")
			}
		})
	}
}
