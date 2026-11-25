package qualification

import (
	"encoding/json"
	"os"
	"testing"
)

func TestHRMeasurementBindingV3ContractVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-hr-binding-v3-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := parseHRMeasurementBindingV3(raw)
	if err != nil {
		t.Fatalf("rejected Contracts v0.8.0 binding: %v", err)
	}
	if binding.Base.Contract != "machine/v3" || binding.Base.SchemaVersion != 3 ||
		binding.RInventory.Domain != "R-runtime" ||
		binding.AdapterRelease.ComponentID != "adapter" ||
		binding.HServiceDescriptorDigest == "" {
		t.Fatal("v3 H/R binding lost selected identity")
	}
	for name, mutate := range map[string]func(map[string]any){
		"old contract":     func(v map[string]any) { v["contract"] = "machine/v2" },
		"missing H digest": func(v map[string]any) { delete(v, "h_service_descriptor_digest") },
		"wrong R root": func(v map[string]any) {
			r := v["r_inventory"].(map[string]any)
			r["snapshot"].(map[string]any)["path"] = "/private/var/db/managed-machine/soul-snapshots/r_wrong/snap_wrong"
		},
		"wrong R plan": func(v map[string]any) {
			v["r_inventory"].(map[string]any)["owner_plan_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"missing adapter attestation": func(v map[string]any) {
			delete(v["adapter_release"].(map[string]any), "release_attestation_sha256")
		},
		"adapter artifact substitution": func(v map[string]any) {
			v["adapter_release"].(map[string]any)["package_sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		},
		"null R source tag": func(v map[string]any) {
			v["r_components"].([]any)[0].(map[string]any)["source_tag"] = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("invalid fixture")
			}
			mutate(value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseHRMeasurementBindingV3(changed); err == nil {
				t.Fatal("accepted changed v3 H/R binding")
			}
		})
	}
}
