package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStage2aMeasurementBindingContractVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-binding-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := digest(raw), "sha256:e1c71c3cca87386b7a4c1d5159565ea644debc5585e5663c91d73119e21234a4"; got != want {
		t.Fatalf("contract canonical byte vector changed: %s", got)
	}
	binding, err := parseMeasurementBinding(raw)
	if err != nil {
		t.Fatal("released-shape synthetic binding refused:", err)
	}
	if binding.HostID != "fixture-physical-mac" || binding.ProfileInForce != "managed-protected" ||
		binding.Snapshots.Definition.RootPath == binding.Snapshots.LaunchInputs.RootPath {
		t.Fatal("parsed binding lost host, profile or distinct snapshots")
	}

	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing definition measurement", func(v map[string]any) { delete(v, "definition_measurement") }},
		{"bare launch measurement", func(v map[string]any) { v["launch_input_measurement"] = strings.Repeat("a", 64) }},
		{"prefixed installed plan digest", func(v map[string]any) { v["installed_plan_digest"] = "sha256:" + strings.Repeat("a", 64) }},
		{"wrong start identifier", func(v map[string]any) { v["start_id"] = "started-only" }},
		{"wrong profile", func(v map[string]any) { v["profile_in_force"] = "managed" }},
		{"unowned snapshot", func(v map[string]any) {
			v["snapshots"].(map[string]any)["definition"].(map[string]any)["owner_uid"] = float64(501)
		}},
		{"group writable snapshot", func(v map[string]any) {
			v["snapshots"].(map[string]any)["definition"].(map[string]any)["mode"] = "0575"
		}},
		{"other writable snapshot", func(v map[string]any) {
			v["snapshots"].(map[string]any)["launch_inputs"].(map[string]any)["mode"] = "0557"
		}},
		{"special mode snapshot", func(v map[string]any) {
			v["snapshots"].(map[string]any)["definition"].(map[string]any)["mode"] = "1555"
		}},
		{"changed snapshot inode", func(v map[string]any) { v["snapshots"].(map[string]any)["definition"].(map[string]any)["inode"] = "01" }},
		{"aliased snapshot roots", func(v map[string]any) {
			s := v["snapshots"].(map[string]any)
			s["launch_inputs"].(map[string]any)["root_path"] = s["definition"].(map[string]any)["root_path"]
		}},
		{"extra snapshot field", func(v map[string]any) {
			v["snapshots"].(map[string]any)["definition"].(map[string]any)["unverified"] = true
		}},
		{"backslash root path", func(v map[string]any) {
			v["snapshots"].(map[string]any)["definition"].(map[string]any)["root_path"] = "/private/stage2a\\escape"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var candidate map[string]any
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			tc.edit(candidate)
			altered, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseMeasurementBinding(altered); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	duplicate := bytes.Replace(raw, []byte(`"host_id":"fixture-physical-mac"`),
		[]byte(`"host_id":"fixture-physical-mac","host_id":"fixture-physical-mac"`), 1)
	if bytes.Equal(duplicate, raw) {
		t.Fatal("duplicate-key fixture setup failed")
	}
	if _, err := parseMeasurementBinding(duplicate); err == nil {
		t.Fatal("duplicate host key accepted")
	}
}
