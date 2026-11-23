package qualification_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

func signInstalledFixtureV3(t *testing.T, purpose string, payload map[string]any,
	key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	signature := ed25519.Sign(key, append([]byte(purpose+"\x00"), raw...))
	envelope, err := json.Marshal(map[string]any{
		"schema_version": 1, "purpose": purpose,
		"issuer_public_key_base64url": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		"payload_sha256":              "sha256:" + hex.EncodeToString(hash[:]),
		"payload_base64url":           base64.RawURLEncoding.EncodeToString(raw),
		"signature_base64url":         base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

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
				"acl_allow_count": 0, "observed_at": "2026-11-22T12:00:04Z",
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
		"opened_files": files, "observed_at": "2026-11-22T12:00:04.5Z",
	}
	return root, inventory, report.MeasurementBinding
}

func TestInstalledInventoryOfflineJoinV3(t *testing.T) {
	root, inventory, binding := inventoryFixtureV3(t)
	stoppedAt := time.Date(2026, 11, 22, 12, 0, 3, 0, time.UTC)
	signedAt := time.Date(2026, 11, 22, 12, 0, 5, 0, time.UTC)
	check := func(object map[string]any) error {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		_, err = qualification.ResolveInstalledInputInventoryV3(root, raw, binding, stoppedAt, signedAt,
			time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC))
		return err
	}
	if err := check(inventory); err != nil {
		t.Fatalf("exact byte vector rejected: %v", err)
	}
	for name, bounds := range map[string][2]time.Time{
		"stop after opened rows":   {time.Date(2026, 11, 22, 12, 0, 4, 1, time.UTC), signedAt},
		"signature before wrapper": {stoppedAt, time.Date(2026, 11, 22, 12, 0, 4, 0, time.UTC)},
		"signature before stop":    {signedAt, stoppedAt},
	} {
		raw, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := qualification.ResolveInstalledInputInventoryV3(root, raw, binding,
			bounds[0], bounds[1], time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)); err == nil {
			t.Errorf("accepted %s", name)
		}
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

func TestSignedInstalledInventoryStopToSegmentJoinV3(t *testing.T) {
	root, inventory, bindingRaw := inventoryFixtureV3(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(bindingRaw, &binding); err != nil {
		t.Fatal(err)
	}
	sha := func(raw []byte) string {
		hash := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	stop := map[string]any{
		"schema":             "agent-bot-machine/stage2a-stop/v1",
		"reservation_sha256": sha([]byte("reservation")),
		"installation_id":    binding["installation_id"], "start_id": binding["start_id"],
		"launch_id": binding["launch_id"], "plan_id": binding["plan_id"],
		"plan_digest": binding["installed_plan_digest"], "hq_epoch": binding["hq_epoch"],
		"runner_uid": 310, "bridge_uid": 311, "runner_pid": 812, "bridge_pid": 813,
		"both_uids_idle": true, "stopped_at": "2026-11-22T12:00:03Z",
	}
	stopEnvelope := signInstalledFixtureV3(t, "agent-bot/stage2a-stop/v1", stop, private)
	inventoryRaw, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := sha([]byte("other evidence"))
	attestation := map[string]any{
		"schema_version": 1, "kind": "stage2a-physical-segment-attestation",
		"gate": "T01", "profile": binding["profile_in_force"], "host_id": binding["host_id"],
		"cohort_id": "fixture-cohort", "suite_revision": strings.Repeat("1", 40),
		"owner_plan_sha256": placeholder, "segment_id": "fixture-segment", "purpose": "initial",
		"report_anchor": true, "terminal_state": "stopped",
		"installation_id": binding["installation_id"], "soul_id": binding["soul_id"],
		"start_id": binding["start_id"], "launch_id": binding["launch_id"],
		"measurement_binding_sha256": sha(bindingRaw), "q_session_status": "completed",
		"q_session_id": strings.Repeat("1", 32), "q_challenge_sha256": placeholder,
		"segment_manifest_sha256": placeholder, "reservation_sha256": stop["reservation_sha256"],
		"b_finalization_sha256": placeholder, "stop_sha256": sha(stopEnvelope),
		"q_wire_sha256": placeholder, "q_index_sha256": placeholder,
		"q_eof_sha256": placeholder, "owner_acp_to_hq_sha256": placeholder,
		"hq_acp_to_owner_sha256": placeholder, "os_observation_sha256": placeholder,
		"installed_inputs_sha256": sha(inventoryRaw), "signed_at": "2026-11-22T12:00:05Z",
	}
	attestationEnvelope := signInstalledFixtureV3(t, "agent-bot/stage2a-physical-segment/v1",
		attestation, private)
	now := time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)
	verify := func(inventoryRaw, stopEnvelope, attestationEnvelope []byte,
		key ed25519.PublicKey) error {
		_, err := qualification.ResolveSignedInstalledInputInventoryV3(root, inventoryRaw,
			bindingRaw, stopEnvelope, attestationEnvelope, key, now)
		return err
	}
	if err := verify(inventoryRaw, stopEnvelope, attestationEnvelope, public); err != nil {
		t.Fatalf("signed A inventory join rejected: %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(inventoryRaw, stopEnvelope, attestationEnvelope, otherPublic); err == nil {
		t.Error("accepted an unenrolled A key")
	}
	changedStop := make(map[string]any, len(stop))
	for key, value := range stop {
		changedStop[key] = value
	}
	changedStop["both_uids_idle"] = false
	if err := verify(inventoryRaw,
		signInstalledFixtureV3(t, "agent-bot/stage2a-stop/v1", changedStop, private),
		attestationEnvelope, public); err == nil {
		t.Error("accepted a non-idle signed stop")
	}
	changedAttestation := make(map[string]any, len(attestation))
	for key, value := range attestation {
		changedAttestation[key] = value
	}
	changedAttestation["installed_inputs_sha256"] = placeholder
	if err := verify(inventoryRaw, stopEnvelope,
		signInstalledFixtureV3(t, "agent-bot/stage2a-physical-segment/v1",
			changedAttestation, private), public); err == nil {
		t.Error("accepted signed inventory digest substitution")
	}
	changedAttestation["installed_inputs_sha256"] = sha(inventoryRaw)
	changedAttestation["owner_plan_sha256"] = "unmeasured-plan"
	if err := verify(inventoryRaw, stopEnvelope,
		signInstalledFixtureV3(t, "agent-bot/stage2a-physical-segment/v1",
			changedAttestation, private), public); err == nil {
		t.Error("accepted malformed signed owner-plan digest")
	}
	changedAttestation["owner_plan_sha256"] = placeholder
	changedAttestation["signed_at"] = "2026-11-22T12:00:04Z"
	if err := verify(inventoryRaw, stopEnvelope,
		signInstalledFixtureV3(t, "agent-bot/stage2a-physical-segment/v1",
			changedAttestation, private), public); err == nil {
		t.Error("accepted inventory wrapper observed after A segment signature")
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
		changedBinding, time.Date(2026, 11, 22, 12, 0, 3, 0, time.UTC),
		time.Date(2026, 11, 22, 12, 0, 5, 0, time.UTC),
		time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)); err == nil {
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
		changedBinding, time.Date(2026, 11, 22, 12, 0, 3, 0, time.UTC),
		time.Date(2026, 11, 22, 12, 0, 5, 0, time.UTC),
		time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("broken definition parent accepted despite recomputed matching digests")
	}
}
