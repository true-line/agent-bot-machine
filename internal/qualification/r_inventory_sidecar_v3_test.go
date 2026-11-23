package qualification

import (
	"crypto/ed25519"
	"encoding/base64"
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

func TestRAdapterReportInventoryV3ContractVector(t *testing.T) {
	reservationFixture, err := os.ReadFile("testdata/stage2a-cooperative-reservation-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var reservationWrapper map[string]json.RawMessage
	if json.Unmarshal(reservationFixture, &reservationWrapper) != nil {
		t.Fatal("invalid reservation fixture")
	}
	var envelope machineRecordV3
	if json.Unmarshal(reservationWrapper["input"], &envelope) != nil {
		t.Fatal("invalid signed reservation")
	}
	key, err := base64.RawURLEncoding.DecodeString(envelope.IssuerPublicKeyBase64URL)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal("invalid reservation signer")
	}
	canonicalEnvelope, err := jsoncanonicalizer.Transform(reservationWrapper["input"])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := qSignedRecordV3(canonicalEnvelope, cooperativeReservationPurposeV3, 3, key)
	if err != nil {
		t.Fatal("invalid signed reservation:", err)
	}
	reservation, err := strictObject(payload, MaxReportBytes)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := parseCooperativeMeasurementBindingV3(reservation["measurement_binding"])
	if err != nil {
		t.Fatal("invalid reservation binding:", err)
	}
	inventoryFixture, err := os.ReadFile("testdata/stage2a-cooperative-r-inventory-v3-contract-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventoryWrapper struct {
		InventoryJCS string           `json:"inventory_jcs"`
		Reference    hrInventoryRefV3 `json:"reference"`
	}
	if json.Unmarshal(inventoryFixture, &inventoryWrapper) != nil ||
		binding.RInventory != inventoryWrapper.Reference {
		t.Fatal("reservation and inventory reference differ")
	}
	inventoryRaw := []byte(inventoryWrapper.InventoryJCS)
	inventory, err := verifyRInventorySidecarV3(inventoryRaw, binding.RInventory)
	if err != nil {
		t.Fatal("invalid signed R inventory:", err)
	}
	reportFixture, err := os.ReadFile("testdata/stage2a-candidate-host-summary-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if json.Unmarshal(reportFixture, &report) != nil {
		t.Fatal("invalid host summary")
	}
	report["adapter"].(map[string]any)["id"] = "fake-adapter"
	report["adapter"].(map[string]any)["version"] = "1.0.0"
	report["launch"].(map[string]any)["argv"] = []any{}
	report["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["sha256"] =
		inventory.Files[1].SHA256
	reportRaw := cooperativeTestJCSV3(t, report)
	if err := verifyRAdapterReportInventoryV3(reportRaw, inventoryRaw, binding); err != nil {
		t.Fatal("refused matching signed R inventory and host launch files:", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"different code bytes": func(v map[string]any) {
			v["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["sha256"] =
				digest([]byte("other code bytes"))
		},
		"different executable": func(v map[string]any) {
			v["launch"].(map[string]any)["executable_sha256"] =
				digest([]byte("other executable"))
		},
		"other component": func(v map[string]any) {
			v["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["path"] =
				binding.RInventory.Snapshot.Path + "/bin/node"
			v["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["sha256"] =
				inventory.Files[3].SHA256
		},
		"unlisted file": func(v map[string]any) {
			v["launch"].(map[string]any)["code_inputs"].([]any)[0].(map[string]any)["path"] =
				binding.RInventory.Snapshot.Path + "/adapter/unlisted.mjs"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed map[string]any
			if json.Unmarshal(reportRaw, &changed) != nil {
				t.Fatal("invalid report")
			}
			mutate(changed)
			if err := verifyRAdapterReportInventoryV3(cooperativeTestJCSV3(t, changed), inventoryRaw, binding); err == nil {
				t.Fatal("accepted report bytes absent from R inventory")
			}
		})
	}
	var changedInventory map[string]any
	if json.Unmarshal(inventoryRaw, &changedInventory) != nil {
		t.Fatal("invalid inventory")
	}
	changedInventory["files"].([]any)[1].(map[string]any)["sha256"] = digest([]byte("different installed code"))
	changedInventoryRaw := cooperativeTestJCSV3(t, changedInventory)
	changedBinding := binding
	changedBinding.RInventory.Sidecar.SizeBytes = uint64(len(changedInventoryRaw))
	changedBinding.RInventory.Sidecar.SHA256 = digest(changedInventoryRaw)
	changedBinding.RInventory.InventoryDigest = digest(preimage(rInventoryPurposeV3, changedInventoryRaw))
	changedBinding.RInventory.ReviewedSourceInventoryDigest = changedBinding.RInventory.InventoryDigest
	if err := verifyRAdapterReportInventoryV3(reportRaw, changedInventoryRaw, changedBinding); err == nil {
		t.Fatal("accepted coherent inventory replacement with different adapter code bytes")
	}
}
