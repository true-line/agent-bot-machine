package qualification_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/members"
	"github.com/qwts/managed-machine/internal/qualification"
)

func inventoryBlobV3(t *testing.T, root, role string, data []byte) map[string]any {
	t.Helper()
	hash := sha256.Sum256(data)
	name := hex.EncodeToString(hash[:])
	dir := filepath.Join(root, "objects", "sha256", name[:2])
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"role": role, "uri": "qualification://stage2a/blob/" + name,
		"sha256": "sha256:" + name, "size_bytes": len(data), "issuer": "machine-a"}
}

func inventoryFixtureV3(t *testing.T) (string, map[string]any, []byte) {
	t.Helper()
	_, definitionRaw, err := members.Stage2aDefinitionDigest(measuredDefinitionFixtureV3())
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../members/testdata/stage2a-launch-inputs.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var launchFixture struct {
		Input members.Stage2aLaunchInputRecords `json:"input"`
	}
	if err := json.Unmarshal(fixture, &launchFixture); err != nil {
		t.Fatal(err)
	}
	_, launchRaw, err := members.Stage2aLaunchInputDigest(launchFixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	reportRaw, err := os.ReadFile("testdata/stage2a-report-v3-protected-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		MeasurementBinding json.RawMessage `json:"measurement_binding"`
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(report.MeasurementBinding, &binding); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	refs := map[string]any{}
	refs["definition_records"] = inventoryBlobV3(t, root, "definition_records", definitionRaw)
	refs["launch_input_records"] = inventoryBlobV3(t, root, "launch_input_records", launchRaw)
	refs["host_adapters_json"] = inventoryBlobV3(t, root, "host_adapters_json", []byte(`{"selected":"fixture-adapter"}`))
	refs["host_installation_json"] = inventoryBlobV3(t, root, "host_installation_json", []byte(`{"id":"fixture-installation"}`))

	type record struct {
		Path   string `json:"path"`
		Kind   string `json:"kind"`
		Mode   string `json:"mode"`
		Size   uint64 `json:"size"`
		SHA256 string `json:"sha256"`
	}
	var definition []record
	var launch struct {
		Files []record `json:"files"`
	}
	if json.Unmarshal(definitionRaw, &definition) != nil || json.Unmarshal(launchRaw, &launch) != nil {
		t.Fatal("invalid source vectors")
	}
	files := make([]map[string]any, 0, len(definition)+len(launch.Files))
	for scope, records := range map[string][]record{"definition": definition, "launch": launch.Files} {
		for _, rec := range records {
			if rec.Kind != "regular" {
				continue
			}
			files = append(files, map[string]any{
				"scope": scope, "path": rec.Path, "size_bytes": rec.Size,
				"mode": rec.Mode, "sha256": rec.SHA256, "owner_uid": 500, "owner_gid": 703,
				"device": "1", "inode": "2001", "generation": "1",
				"birthtime_ns": "1795300000000000000", "link_count": 1,
				"acl_allow_count": 0, "observed_at": "2026-11-22T12:00:00Z",
			})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i]["scope"].(string)+"/"+files[i]["path"].(string) <
			files[j]["scope"].(string)+"/"+files[j]["path"].(string)
	})
	mb := sha256.Sum256(report.MeasurementBinding)
	snapshots := binding["snapshots"].(map[string]any)
	inventory := map[string]any{
		"schema_version": 1, "kind": "stage2a-installed-inputs",
		"installation_id": binding["installation_id"], "soul_id": binding["soul_id"],
		"start_id": binding["start_id"], "launch_id": binding["launch_id"],
		"host_id": binding["host_id"], "profile": binding["profile_in_force"],
		"plan_id": binding["plan_id"], "installed_plan_digest": binding["installed_plan_digest"],
		"measurement_binding_sha256": "sha256:" + hex.EncodeToString(mb[:]),
		"definition_records":         refs["definition_records"], "launch_input_records": refs["launch_input_records"],
		"host_adapters_json": refs["host_adapters_json"], "host_installation_json": refs["host_installation_json"],
		"definition_snapshot": snapshots["definition"], "launch_inputs_snapshot": snapshots["launch_inputs"],
		"opened_files": files, "observed_at": "2026-11-22T12:00:01Z",
	}
	return root, inventory, report.MeasurementBinding
}

func TestInstalledInventoryOfflineJoinV3(t *testing.T) {
	root, inventory, binding := inventoryFixtureV3(t)
	check := func(object map[string]any) error {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		_, err = qualification.ResolveInstalledInputInventoryV3(root, raw, binding,
			time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC))
		return err
	}
	if err := check(inventory); err != nil {
		t.Fatalf("exact byte vector rejected: %v", err)
	}
	files := inventory["opened_files"].([]map[string]any)
	for name, change := range map[string]func(){
		"file hash": func() { files[0]["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000" },
		"owner":     func() { files[0]["owner_uid"] = 501 },
		"ACL":       func() { files[0]["acl_allow_count"] = 1 },
	} {
		original := map[string]any{}
		for k, v := range files[0] {
			original[k] = v
		}
		change()
		if err := check(inventory); err == nil {
			t.Errorf("accepted changed %s", name)
		}
		files[0] = original
	}
	inventory["opened_files"] = files[1:]
	if err := check(inventory); err == nil {
		t.Error("accepted missing opened file")
	}
}

func TestInstalledInventoryRejectsUnmeasuredComponentWithMatchingRecordDigestV3(t *testing.T) {
	root, inventory, bindingRaw := inventoryFixtureV3(t)
	ref := inventory["launch_input_records"].(map[string]any)
	name := strings.TrimPrefix(ref["sha256"].(string), "sha256:")
	launchRaw, err := os.ReadFile(filepath.Join(root, "objects", "sha256", name[:2], name))
	if err != nil {
		t.Fatal(err)
	}
	var launch map[string]any
	if err := json.Unmarshal(launchRaw, &launch); err != nil {
		t.Fatal(err)
	}
	launch["component_digests"].(map[string]any)["machine"] = "sha256:" + strings.Repeat("0", 64)
	changedLaunch, err := json.Marshal(launch)
	if err != nil {
		t.Fatal(err)
	}
	inventory["launch_input_records"] = inventoryBlobV3(t, root, "launch_input_records", changedLaunch)
	var binding map[string]any
	if err := json.Unmarshal(bindingRaw, &binding); err != nil {
		t.Fatal(err)
	}
	measured := sha256.Sum256(append([]byte("agent-bot/stage2a-launch-inputs/v1\x00"), changedLaunch...))
	binding["launch_input_measurement"] = "sha256:" + hex.EncodeToString(measured[:])
	changedBinding, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	bound := sha256.Sum256(changedBinding)
	inventory["measurement_binding_sha256"] = "sha256:" + hex.EncodeToString(bound[:])
	changedInventory, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualification.ResolveInstalledInputInventoryV3(root, changedInventory,
		changedBinding, time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("unmeasured component accepted despite recomputed matching record and binding digests")
	}
}

func TestInstalledInventoryRejectsBrokenDefinitionTreeWithMatchingDigestV3(t *testing.T) {
	root, inventory, bindingRaw := inventoryFixtureV3(t)
	ref := inventory["definition_records"].(map[string]any)
	name := strings.TrimPrefix(ref["sha256"].(string), "sha256:")
	recordsRaw, err := os.ReadFile(filepath.Join(root, "objects", "sha256", name[:2], name))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	if err := json.Unmarshal(recordsRaw, &records); err != nil {
		t.Fatal(err)
	}
	var changedRecords []map[string]any
	for _, record := range records {
		if record["path"] != "Contents/opt" {
			changedRecords = append(changedRecords, record)
		}
	}
	changedDefinition, err := json.Marshal(changedRecords)
	if err != nil {
		t.Fatal(err)
	}
	inventory["definition_records"] = inventoryBlobV3(t, root, "definition_records", changedDefinition)
	var binding map[string]any
	if err := json.Unmarshal(bindingRaw, &binding); err != nil {
		t.Fatal(err)
	}
	measured := sha256.Sum256(append([]byte("agent-bot/stage2a-definition-opt-closure/v1\x00"), changedDefinition...))
	binding["definition_measurement"] = "sha256:" + hex.EncodeToString(measured[:])
	changedBinding, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	bound := sha256.Sum256(changedBinding)
	inventory["measurement_binding_sha256"] = "sha256:" + hex.EncodeToString(bound[:])
	changedInventory, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualification.ResolveInstalledInputInventoryV3(root, changedInventory,
		changedBinding, time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("broken definition parent accepted despite recomputed matching digests")
	}
}
