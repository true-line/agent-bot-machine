package qualification

import (
	"encoding/json"
	"os"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestRInventorySidecarV3ContractVector(t *testing.T) {
	fixture, err := os.ReadFile("testdata/stage2a-cooperative-r-inventory-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(fixture, &wrapper) != nil {
		t.Fatal("invalid Contracts #74 R fixture")
	}
	var rawString string
	var ref hrInventoryRefV3
	if json.Unmarshal(wrapper["inventory_jcs"], &rawString) != nil ||
		json.Unmarshal(wrapper["reference"], &ref) != nil {
		t.Fatal("invalid R vector")
	}
	raw := []byte(rawString)
	inv, err := verifyRInventorySidecarV3(raw, ref)
	if err != nil || len(inv.Files) != ref.FileCount {
		t.Fatal("refused paired Contracts R inventory and signed reference:", err)
	}
	for name, mutate := range map[string]func(map[string]any, *hrInventoryRefV3){
		"writable file": func(v map[string]any, _ *hrInventoryRefV3) {
			v["files"].([]any)[0].(map[string]any)["mode"] = "0660"
		},
		"release alias": func(v map[string]any, _ *hrInventoryRefV3) {
			v["files"].([]any)[1].(map[string]any)["release_path"] = "cli"
		},
		"parent traversal": func(v map[string]any, _ *hrInventoryRefV3) {
			v["files"].([]any)[0].(map[string]any)["path"] = "adapter/../cli"
		},
		"missing parent": func(v map[string]any, r *hrInventoryRefV3) {
			v["directories"] = v["directories"].([]any)[1:]
			r.DirectoryCount--
		},
		"widened limit": func(v map[string]any, _ *hrInventoryRefV3) {
			v["limits"].(map[string]any)["max_files"] = float64(513)
		},
		"false total": func(v map[string]any, r *hrInventoryRefV3) {
			v["total_bytes"] = v["total_bytes"].(float64) - 1
			r.TotalBytes--
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(raw, &value) != nil {
				t.Fatal("invalid inventory")
			}
			changedRef := ref
			mutate(value, &changedRef)
			changedJSON, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := jsoncanonicalizer.Transform(changedJSON)
			if err != nil {
				t.Fatal(err)
			}
			changedRef.Sidecar.SizeBytes = uint64(len(changed))
			changedRef.Sidecar.SHA256 = digest(changed)
			changedRef.InventoryDigest = digest(preimage(rInventoryPurposeV3, changed))
			changedRef.ReviewedSourceInventoryDigest = changedRef.InventoryDigest
			if _, err := verifyRInventorySidecarV3(changed, changedRef); err == nil {
				t.Fatal("accepted invalid R sidecar with matching recalculated digests")
			}
		})
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-2] ^= 1
	if _, err := verifyRInventorySidecarV3(changed, ref); err == nil {
		t.Fatal("accepted changed sidecar against signed reference")
	}
}
