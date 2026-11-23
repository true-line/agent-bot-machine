package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// VerifiedInstalledInputInventoryV3 joins a compact A-observed file inventory
// to the exact canonical definition and launch-input records. It is not proof
// of descriptor custody, a signed A issuer, an owner-approved plan or a gate.
type VerifiedInstalledInputInventoryV3 struct {
	verified                                                              bool
	InventorySHA256, DefinitionMeasurementSHA256, LaunchMeasurementSHA256 string
	InstallationID, SoulID, StartID, LaunchID, HostID, Profile            string
	FileCount                                                             int
}

// VerifiedSignedInstalledInputInventoryV3 distinguishes the A-signed stop and
// segment digest join from the unsigned record-and-file inventory component.
// Neither value represents a physical gate verdict.
type VerifiedSignedInstalledInputInventoryV3 struct {
	verified                 bool
	Inventory                VerifiedInstalledInputInventoryV3
	StopSHA256               string
	SegmentAttestationSHA256 string
}

type installedInputFileV3 struct {
	Scope         string `json:"scope"`
	Path          string `json:"path"`
	SizeBytes     uint64 `json:"size_bytes"`
	Mode          string `json:"mode"`
	SHA256        string `json:"sha256"`
	OwnerUID      uint32 `json:"owner_uid"`
	OwnerGID      uint32 `json:"owner_gid"`
	Device        string `json:"device"`
	Inode         string `json:"inode"`
	Generation    string `json:"generation"`
	BirthtimeNS   string `json:"birthtime_ns"`
	LinkCount     uint32 `json:"link_count"`
	ACLAllowCount uint32 `json:"acl_allow_count"`
	ObservedAt    string `json:"observed_at"`
}

type installedInventoryV3 struct {
	SchemaVersion            int                    `json:"schema_version"`
	Kind                     string                 `json:"kind"`
	InstallationID           string                 `json:"installation_id"`
	SoulID                   string                 `json:"soul_id"`
	StartID                  string                 `json:"start_id"`
	LaunchID                 string                 `json:"launch_id"`
	HostID                   string                 `json:"host_id"`
	Profile                  string                 `json:"profile"`
	PlanID                   string                 `json:"plan_id"`
	InstalledPlanDigest      string                 `json:"installed_plan_digest"`
	MeasurementBindingSHA256 string                 `json:"measurement_binding_sha256"`
	DefinitionRecords        gateObjectRefV3        `json:"definition_records"`
	LaunchInputRecords       gateObjectRefV3        `json:"launch_input_records"`
	HostAdaptersJSON         gateObjectRefV3        `json:"host_adapters_json"`
	HostInstallationJSON     gateObjectRefV3        `json:"host_installation_json"`
	DefinitionSnapshot       snapshotIdentity       `json:"definition_snapshot"`
	LaunchInputsSnapshot     snapshotIdentity       `json:"launch_inputs_snapshot"`
	OpenedFiles              []installedInputFileV3 `json:"opened_files"`
	ObservedAt               string                 `json:"observed_at"`
}

type installedPortableFileV3 struct {
	Path   string  `json:"path"`
	Kind   string  `json:"kind"`
	Mode   string  `json:"mode"`
	Size   *uint64 `json:"size,omitempty"`
	SHA256 string  `json:"sha256,omitempty"`
}

func installedRefV3(raw []byte, role string, maximum int64) (gateObjectRefV3, error) {
	ref, err := parseGateObjectRefV3(raw)
	if err != nil || ref.Role != role || ref.Issuer != "machine-a" ||
		ref.SizeBytes <= 0 || ref.SizeBytes > maximum {
		return gateObjectRefV3{}, ErrUnqualified
	}
	return ref, nil
}

func installedPathV3(path string) bool {
	if path == "" || len(path) > 4096 || path[0] == '/' || strings.HasSuffix(path, "/") ||
		strings.Contains(path, "//") || strings.Contains(path, "\\") {
		return false
	}
	for _, c := range path {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func installedModeV3(mode string) bool {
	if len(mode) != 4 || mode[0] != '0' {
		return false
	}
	for _, c := range mode {
		if c < '0' || c > '7' {
			return false
		}
	}
	return (mode[1]-'0')&2 == 0 && (mode[2]-'0')&2 == 0 && (mode[3]-'0')&2 == 0
}

func installedRecordFilesV3(raw []byte, scope string, expected map[string]installedPortableFileV3) error {
	var records []installedPortableFileV3
	if scope == "definition" {
		if json.Unmarshal(raw, &records) != nil || len(records) < 5 || len(records) > 512 {
			return ErrUnqualified
		}
	} else {
		var object struct {
			Files []installedPortableFileV3 `json:"files"`
		}
		if json.Unmarshal(raw, &object) != nil || len(object.Files) < 1 || len(object.Files) > 64 {
			return ErrUnqualified
		}
		records = object.Files
	}
	previous := ""
	aliases := map[string]bool{}
	kinds := map[string]string{}
	impliedDirs := map[string]bool{}
	children := map[string]map[string]string{}
	var total uint64
	for _, record := range records {
		if !installedPathV3(record.Path) || !installedModeV3(record.Mode) ||
			(previous != "" && record.Path <= previous) || aliases[strings.ToLower(record.Path)] {
			return ErrUnqualified
		}
		previous = record.Path
		aliases[strings.ToLower(record.Path)] = true
		if scope == "definition" {
			if record.Path != "Contents" && !strings.HasPrefix(record.Path, "Contents/") ||
				record.Path != "Contents" && record.Path != "Contents/SoulInfo.json" &&
					record.Path != "Contents/SoulLock.json" && record.Path != "Contents/opt" &&
					record.Path != "Contents/primitives" &&
					!strings.HasPrefix(record.Path, "Contents/opt/") &&
					!strings.HasPrefix(record.Path, "Contents/primitives/") ||
				record.Path != "Contents" && kinds[path.Dir(record.Path)] != "directory" {
				return ErrUnqualified
			}
			kinds[record.Path] = record.Kind
		} else {
			parent := ""
			parts := strings.Split(record.Path, "/")
			for i, part := range parts {
				if children[parent] == nil {
					children[parent] = map[string]string{}
				}
				folded := strings.ToLower(part)
				if old, exists := children[parent][folded]; exists && old != part {
					return ErrUnqualified
				}
				children[parent][folded] = part
				parent = path.Join(parent, part)
				if i < len(parts)-1 {
					if kinds[parent] == "regular" {
						return ErrUnqualified
					}
					impliedDirs[parent] = true
				}
			}
			if impliedDirs[record.Path] {
				return ErrUnqualified
			}
			kinds[record.Path] = record.Kind
		}
		if scope == "definition" && record.Kind == "directory" {
			if record.Size != nil || record.SHA256 != "" {
				return ErrUnqualified
			}
			continue
		}
		if record.Kind != "regular" || record.Size == nil || *record.Size > 256<<20 ||
			!validHex(record.SHA256, 64) || total > (1<<30)-*record.Size {
			return ErrUnqualified
		}
		total += *record.Size
		expected[scope+"/"+record.Path] = record
	}
	if scope == "definition" {
		for required, kind := range map[string]string{
			"Contents": "directory", "Contents/SoulInfo.json": "regular",
			"Contents/SoulLock.json": "regular", "Contents/opt": "directory",
			"Contents/primitives": "directory",
		} {
			if kinds[required] != kind {
				return ErrUnqualified
			}
		}
	}
	return nil
}

func installedHostJSONV3(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) || !json.Valid(raw) ||
		!validStage2aSurrogatesV3(raw) {
		return nil, ErrUnqualified
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if scanStage2aJSONV3(decoder, 0, &nodes) != nil {
		return nil, ErrUnqualified
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, ErrUnqualified
	}
	return value, nil
}

func installedSelectedCommandV3(command string, binding measurementBinding,
	files map[string]installedPortableFileV3) bool {
	for _, candidate := range []struct {
		root, scope string
	}{
		{binding.Snapshots.Definition.RootPath, "definition"},
		{binding.Snapshots.LaunchInputs.RootPath, "launch"},
	} {
		if !strings.HasPrefix(command, candidate.root+"/") {
			continue
		}
		relative := strings.TrimPrefix(command, candidate.root+"/")
		if candidate.scope == "definition" && !strings.HasPrefix(relative, "Contents/opt/") ||
			candidate.scope == "launch" && (relative == "host/adapters.json" || relative == "host/installation.json") {
			return false
		}
		file, ok := files[candidate.scope+"/"+relative]
		return ok && file.Kind == "regular" && installedModeV3(file.Mode) &&
			(file.Mode[2]-'0')&1 != 0
	}
	return false
}

// ResolveInstalledInputInventoryV3 checks one content-addressed compact
// inventory and its nested record/host-projection objects against the signed
// per-start binding supplied by its caller. The caller must first authenticate
// that binding, the idle-stop time, the segment-signing time, and the inventory
// digest via A's signed stop and segment attestation. Every descriptor read
// must follow the stop and precede the signature. This function does not
// measure live installed files or authenticate A custody.
func ResolveInstalledInputInventoryV3(root string, inventoryRaw, bindingRaw []byte,
	stoppedAt, signedAt, now time.Time) (VerifiedInstalledInputInventoryV3, error) {
	var zero VerifiedInstalledInputInventoryV3
	if stoppedAt.IsZero() || signedAt.IsZero() || now.IsZero() ||
		signedAt.Before(stoppedAt) || signedAt.After(now) {
		return zero, ErrUnqualified
	}
	fields, err := canonicalBytes(inventoryRaw, 1<<20)
	if err != nil || !hasFields(fields, "schema_version", "kind", "installation_id", "soul_id", "start_id", "launch_id", "host_id", "profile", "plan_id", "installed_plan_digest", "measurement_binding_sha256", "definition_records", "launch_input_records", "host_adapters_json", "host_installation_json", "definition_snapshot", "launch_inputs_snapshot", "opened_files", "observed_at") {
		return zero, ErrUnqualified
	}
	jcs, err := jsoncanonicalizer.Transform(inventoryRaw)
	if err != nil || !bytes.Equal(jcs, inventoryRaw) {
		return zero, ErrUnqualified
	}
	for _, name := range []string{"definition_snapshot", "launch_inputs_snapshot"} {
		identity, err := strictObject(fields[name], 1<<20)
		if err != nil || !hasFields(identity, "root_path", "device", "inode", "generation",
			"birthtime_ns", "owner_uid", "owner_gid", "mode") {
			return zero, ErrUnqualified
		}
	}
	var openedRows []json.RawMessage
	if json.Unmarshal(fields["opened_files"], &openedRows) != nil ||
		len(openedRows) == 0 || len(openedRows) > 576 {
		return zero, ErrUnqualified
	}
	for _, raw := range openedRows {
		row, err := strictObject(raw, 1<<20)
		if err != nil || !hasFields(row, "scope", "path", "size_bytes", "mode", "sha256",
			"owner_uid", "owner_gid", "device", "inode", "generation", "birthtime_ns",
			"link_count", "acl_allow_count", "observed_at") {
			return zero, ErrUnqualified
		}
	}
	binding, err := parseMeasurementBindingV2(bindingRaw)
	if err != nil {
		return zero, ErrUnqualified
	}
	var inventory installedInventoryV3
	if json.Unmarshal(inventoryRaw, &inventory) != nil || inventory.SchemaVersion != 1 ||
		inventory.Kind != "stage2a-installed-inputs" ||
		inventory.InstallationID != binding.InstallationID || inventory.SoulID != binding.SoulID ||
		inventory.StartID != binding.StartID || inventory.LaunchID != binding.LaunchID ||
		inventory.HostID != binding.HostID || inventory.Profile != binding.ProfileInForce ||
		inventory.PlanID != binding.PlanID || inventory.InstalledPlanDigest != binding.InstalledPlanDigest ||
		inventory.MeasurementBindingSHA256 != digest(bindingRaw) ||
		inventory.DefinitionSnapshot != binding.Snapshots.Definition ||
		inventory.LaunchInputsSnapshot != binding.Snapshots.LaunchInputs ||
		len(inventory.OpenedFiles) == 0 || len(inventory.OpenedFiles) > 576 {
		return zero, ErrUnqualified
	}
	observedAt, err := parseTime(inventory.ObservedAt)
	if err != nil || observedAt.Before(stoppedAt) || observedAt.After(signedAt) {
		return zero, ErrUnqualified
	}
	objects := map[string][]byte{}
	refs := map[string]gateObjectRefV3{}
	declared := map[string]gateObjectRefV3{
		"definition_records":     inventory.DefinitionRecords,
		"launch_input_records":   inventory.LaunchInputRecords,
		"host_adapters_json":     inventory.HostAdaptersJSON,
		"host_installation_json": inventory.HostInstallationJSON,
	}
	for _, item := range []struct {
		name string
		max  int64
	}{
		{"definition_records", 4 << 20}, {"launch_input_records", 1 << 20},
		{"host_adapters_json", 64 << 10}, {"host_installation_json", 64 << 10},
	} {
		ref, err := installedRefV3(fields[item.name], item.name, item.max)
		if err != nil || ref != declared[item.name] {
			return zero, ErrUnqualified
		}
		objects[item.name], err = physicalSegmentObjectV3(root, ref, item.name, item.max)
		if err != nil {
			return zero, ErrUnqualified
		}
		refs[item.name] = ref
	}
	if refs["definition_records"].SHA256 == refs["launch_input_records"].SHA256 ||
		refs["host_adapters_json"].SHA256 == refs["host_installation_json"].SHA256 {
		return zero, ErrUnqualified
	}
	measurements, err := VerifyMeasurementRecordDigestsV3(bindingRaw,
		objects["definition_records"], objects["launch_input_records"])
	if err != nil || !measurements.verified {
		return zero, ErrUnqualified
	}
	expected := map[string]installedPortableFileV3{}
	if installedRecordFilesV3(objects["definition_records"], "definition", expected) != nil ||
		installedRecordFilesV3(objects["launch_input_records"], "launch", expected) != nil ||
		len(expected) != len(inventory.OpenedFiles) {
		return zero, ErrUnqualified
	}
	var launch struct {
		SelectedCommand     string            `json:"selected_command"`
		Argv                []string          `json:"argv"`
		EffectiveConfig     map[string]any    `json:"effective_config"`
		ComponentDigests    map[string]string `json:"component_digests"`
		SandboxPolicyDigest string            `json:"sandbox_policy_digest"`
		HostProjection      struct {
			Adapters     map[string]any `json:"adapters"`
			Installation map[string]any `json:"installation"`
		} `json:"host_projection"`
	}
	if json.Unmarshal(objects["launch_input_records"], &launch) != nil ||
		launch.HostProjection.Adapters == nil || launch.HostProjection.Installation == nil ||
		len(launch.Argv) == 0 || launch.Argv[0] != launch.SelectedCommand ||
		launch.EffectiveConfig["profile"] != binding.ProfileInForce ||
		len(launch.ComponentDigests) != 8 {
		return zero, ErrUnqualified
	}
	if !installedSelectedCommandV3(launch.SelectedCommand, binding, expected) {
		return zero, ErrUnqualified
	}
	launchHashes := make(map[string]bool)
	for key, file := range expected {
		if strings.HasPrefix(key, "launch/") {
			launchHashes["sha256:"+file.SHA256] = true
		}
	}
	for _, name := range []string{"machine", "hq", "souls", "bridge", "comms_broker",
		"adapter", "harness", "test_provider"} {
		if !launchHashes[launch.ComponentDigests[name]] {
			return zero, ErrUnqualified
		}
	}
	if !launchHashes[launch.SandboxPolicyDigest] {
		return zero, ErrUnqualified
	}
	for _, item := range []struct {
		name, path string
		want       map[string]any
	}{
		{"host_adapters_json", "host/adapters.json", launch.HostProjection.Adapters},
		{"host_installation_json", "host/installation.json", launch.HostProjection.Installation},
	} {
		value, err := installedHostJSONV3(objects[item.name])
		file, ok := expected["launch/"+item.path]
		if err != nil || !ok || file.Size == nil || *file.Size != uint64(len(objects[item.name])) ||
			"sha256:"+file.SHA256 != refs[item.name].SHA256 || !reflect.DeepEqual(value, item.want) {
			return zero, ErrUnqualified
		}
	}
	previous := ""
	for _, opened := range inventory.OpenedFiles {
		key := opened.Scope + "/" + opened.Path
		file, ok := expected[key]
		if !ok || file.Size == nil || key <= previous || opened.SizeBytes != *file.Size ||
			opened.Mode != file.Mode || opened.SHA256 != file.SHA256 ||
			opened.LinkCount != 1 || opened.ACLAllowCount != 0 ||
			!stage2aDecimal.MatchString(opened.Inode) || opened.Inode == "0" ||
			!stage2aDecimal.MatchString(opened.Generation) ||
			!stage2aDecimal.MatchString(opened.BirthtimeNS) || opened.BirthtimeNS == "0" {
			return zero, ErrUnqualified
		}
		snapshot := binding.Snapshots.Definition
		if opened.Scope == "launch" {
			snapshot = binding.Snapshots.LaunchInputs
		}
		if opened.OwnerUID != snapshot.OwnerUID || opened.OwnerGID != snapshot.OwnerGID ||
			opened.Device != snapshot.Device {
			return zero, ErrUnqualified
		}
		at, err := parseTime(opened.ObservedAt)
		if err != nil || at.Before(stoppedAt) || at.After(observedAt) {
			return zero, ErrUnqualified
		}
		previous = key
		delete(expected, key)
	}
	if len(expected) != 0 {
		return zero, ErrUnqualified
	}
	return VerifiedInstalledInputInventoryV3{verified: true, InventorySHA256: digest(inventoryRaw),
		DefinitionMeasurementSHA256: measurements.DefinitionMeasurementSHA256,
		LaunchMeasurementSHA256:     measurements.LaunchInputMeasurementSHA256,
		InstallationID:              binding.InstallationID, SoulID: binding.SoulID,
		StartID: binding.StartID, LaunchID: binding.LaunchID, HostID: binding.HostID,
		Profile: binding.ProfileInForce, FileCount: len(inventory.OpenedFiles)}, nil
}

// ResolveSignedInstalledInputInventoryV3 authenticates the narrow A custody
// join for one stopped protected start. The independently enrolled Machine A
// key must be supplied by the caller; an envelope's embedded key is never a
// trust anchor. Full reservation/Q/ACP/OS chains, the owner plan, released
// bytes, case inventory and gate outcomes remain separate requirements.
func ResolveSignedInstalledInputInventoryV3(root string, inventoryRaw, bindingRaw,
	stopEnvelope, segmentAttestationEnvelope []byte, machineKey ed25519.PublicKey,
	now time.Time) (VerifiedSignedInstalledInputInventoryV3, error) {
	var zero VerifiedSignedInstalledInputInventoryV3
	if len(machineKey) != ed25519.PublicKeySize || now.IsZero() {
		return zero, ErrUnqualified
	}
	binding, err := parseMeasurementBindingV2(bindingRaw)
	if err != nil {
		return zero, ErrUnqualified
	}
	stopRaw, err := qSignedRecordV3(stopEnvelope, "agent-bot/stage2a-stop/v1", 1, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	stopFields, err := strictObject(stopRaw, 48<<10)
	if err != nil || !hasFields(stopFields, "schema", "reservation_sha256", "installation_id",
		"start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch", "runner_uid",
		"bridge_uid", "runner_pid", "bridge_pid", "both_uids_idle", "stopped_at") {
		return zero, ErrUnqualified
	}
	var stop struct {
		Schema            string `json:"schema"`
		ReservationSHA256 string `json:"reservation_sha256"`
		InstallationID    string `json:"installation_id"`
		StartID           string `json:"start_id"`
		LaunchID          string `json:"launch_id"`
		PlanID            string `json:"plan_id"`
		PlanDigest        string `json:"plan_digest"`
		HQEpoch           string `json:"hq_epoch"`
		RunnerUID         int    `json:"runner_uid"`
		BridgeUID         int    `json:"bridge_uid"`
		RunnerPID         int    `json:"runner_pid"`
		BridgePID         int    `json:"bridge_pid"`
		BothUIDsIdle      bool   `json:"both_uids_idle"`
		StoppedAt         string `json:"stopped_at"`
	}
	if json.Unmarshal(stopRaw, &stop) != nil ||
		stop.Schema != "agent-bot-machine/stage2a-stop/v1" || !stop.BothUIDsIdle ||
		!validSHA(stop.ReservationSHA256) || stop.RunnerPID <= 0 || stop.BridgePID <= 0 ||
		stop.RunnerUID < 300 || stop.RunnerUID > 399 ||
		stop.BridgeUID < 300 || stop.BridgeUID > 399 || stop.RunnerUID == stop.BridgeUID ||
		stop.InstallationID != binding.InstallationID || stop.StartID != binding.StartID ||
		stop.LaunchID != binding.LaunchID || stop.PlanID != binding.PlanID ||
		stop.PlanDigest != binding.InstalledPlanDigest || stop.HQEpoch != binding.HQEpoch {
		return zero, ErrUnqualified
	}
	stoppedAt, err := parseTime(stop.StoppedAt)
	if err != nil {
		return zero, ErrUnqualified
	}
	attestationRaw, err := qSignedRecordV3(segmentAttestationEnvelope,
		physicalSegmentPurposeV3, 1, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	attestationFields, err := strictObject(attestationRaw, 48<<10)
	if err != nil || !hasFields(attestationFields, "schema_version", "kind", "gate",
		"profile", "host_id", "cohort_id", "suite_revision", "owner_plan_sha256",
		"segment_id", "purpose", "report_anchor", "terminal_state", "installation_id",
		"soul_id", "start_id", "launch_id", "measurement_binding_sha256",
		"q_session_status", "q_session_id", "q_challenge_sha256",
		"segment_manifest_sha256", "reservation_sha256", "b_finalization_sha256",
		"stop_sha256", "q_wire_sha256", "q_index_sha256", "q_eof_sha256",
		"owner_acp_to_hq_sha256", "hq_acp_to_owner_sha256", "os_observation_sha256",
		"installed_inputs_sha256", "signed_at") {
		return zero, ErrUnqualified
	}
	var attestation physicalSegmentAttestationV3
	if json.Unmarshal(attestationRaw, &attestation) != nil ||
		attestation.SchemaVersion != 1 ||
		attestation.Kind != "stage2a-physical-segment-attestation" ||
		(attestation.Gate != "T01" && attestation.Gate != "T02" && attestation.Gate != "T03") ||
		attestation.Profile != "managed-protected" ||
		!reportID.MatchString(attestation.CohortID) ||
		!validHex(attestation.SuiteRevision, 40) ||
		!reportID.MatchString(attestation.SegmentID) ||
		!gatePurposeV3(attestation.Purpose) ||
		len(attestation.QSessionID) != 32 || !qLowerHexV3(attestation.QSessionID) ||
		attestation.TerminalState != "stopped" || attestation.QSessionStatus != "completed" ||
		attestation.InstallationID != binding.InstallationID ||
		attestation.SoulID != binding.SoulID || attestation.StartID != binding.StartID ||
		attestation.LaunchID != binding.LaunchID || attestation.HostID != binding.HostID ||
		attestation.Profile != binding.ProfileInForce ||
		attestation.MeasurementBindingSHA256 != digest(bindingRaw) ||
		attestation.ReservationSHA256 != stop.ReservationSHA256 ||
		attestation.StopSHA256 != digest(stopEnvelope) ||
		attestation.InstalledInputsSHA256 != digest(inventoryRaw) {
		return zero, ErrUnqualified
	}
	for _, value := range []string{
		attestation.OwnerPlanSHA256, attestation.QChallengeSHA256,
		attestation.SegmentManifestSHA256, attestation.ReservationSHA256,
		attestation.BFinalizationSHA256, attestation.StopSHA256,
		attestation.QWireSHA256, attestation.QIndexSHA256,
		attestation.QEOFSHA256, attestation.OwnerACPToHQSha256,
		attestation.HQACPToOwnerSHA256, attestation.OSObservationSHA256,
		attestation.InstalledInputsSHA256,
	} {
		if !validSHA(value) {
			return zero, ErrUnqualified
		}
	}
	signedAt, err := parseTime(attestation.SignedAt)
	if err != nil {
		return zero, ErrUnqualified
	}
	inventory, err := ResolveInstalledInputInventoryV3(root, inventoryRaw, bindingRaw,
		stoppedAt, signedAt, now)
	if err != nil || !inventory.verified {
		return zero, ErrUnqualified
	}
	return VerifiedSignedInstalledInputInventoryV3{verified: true,
		Inventory: inventory, StopSHA256: digest(stopEnvelope),
		SegmentAttestationSHA256: digest(segmentAttestationEnvelope)}, nil
}
