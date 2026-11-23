package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var (
	hrComponentIDV3 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hrRepositoryV3  = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	hrSourceTagV3   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$`)
)

type hrNodeRefV3 struct {
	Path        string `json:"path"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	Generation  string `json:"generation"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    uint32 `json:"owner_uid"`
	OwnerGID    uint32 `json:"owner_gid"`
	Mode        string `json:"mode"`
}

type hrSidecarRefV3 struct {
	Path        string `json:"path"`
	Device      string `json:"device"`
	Inode       string `json:"inode"`
	Generation  string `json:"generation"`
	BirthtimeNS string `json:"birthtime_ns"`
	OwnerUID    uint32 `json:"owner_uid"`
	OwnerGID    uint32 `json:"owner_gid"`
	Mode        string `json:"mode"`
	SizeBytes   uint64 `json:"size_bytes"`
	SHA256      string `json:"sha256"`
}

type hrInventoryRefV3 struct {
	Contract                      string         `json:"contract"`
	Kind                          string         `json:"kind"`
	SchemaVersion                 int            `json:"schema_version"`
	Domain                        string         `json:"domain"`
	InstallationID                string         `json:"installation_id"`
	OwnerPlanDigest               string         `json:"owner_plan_digest"`
	ReviewedSourceInventoryDigest string         `json:"reviewed_source_inventory_digest"`
	MachineUID                    uint32         `json:"machine_uid"`
	ReaderUID                     uint32         `json:"reader_uid"`
	ReaderGID                     uint32         `json:"reader_gid"`
	Snapshot                      hrNodeRefV3    `json:"snapshot"`
	Sidecar                       hrSidecarRefV3 `json:"sidecar"`
	FileCount                     int            `json:"file_count"`
	DirectoryCount                int            `json:"directory_count"`
	TotalBytes                    uint64         `json:"total_bytes"`
	InventoryDigest               string         `json:"inventory_digest"`
}

type hrReleaseComponentV3 struct {
	ComponentID           string `json:"component_id"`
	SourceRepository      string `json:"source_repository"`
	SourceCommit          string `json:"source_commit"`
	SourceTag             string `json:"source_tag,omitempty"`
	ReleaseArtifactSHA256 string `json:"release_artifact_sha256"`
	ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
}

type hrAdapterReleaseV3 struct {
	ComponentID              string `json:"component_id"`
	PackageSHA256            string `json:"package_sha256"`
	ReleaseAttestationSHA256 string `json:"release_attestation_sha256"`
	ReleaseManifestSHA256    string `json:"release_manifest_sha256"`
	ExecutablePath           string `json:"executable_path"`
	ExecutableSHA256         string `json:"executable_sha256"`
	CodeInputsDigest         string `json:"code_inputs_digest"`
	CodeInputCount           int    `json:"code_input_count"`
}

type hrBrokerExecutableV3 struct {
	Path                 string `json:"path"`
	SHA256               string `json:"sha256"`
	ProviderConfigSHA256 string `json:"provider_config_sha256"`
}

// hrMeasurementBindingV3 is the strict portable shape of the Machine v3
// reservation binding. It is only a parsed claim: the caller must separately
// authenticate the reservation, H descriptor, R installed bytes, release
// manifests, owner plan and one-use lifecycle before granting any gate.
type hrMeasurementBindingV3 struct {
	Base                     measurementBinding
	HServiceDescriptorDigest string
	RInventory               hrInventoryRefV3
	RComponents              []hrReleaseComponentV3
	AdapterRelease           hrAdapterReleaseV3
	BrokerExecutable         hrBrokerExecutableV3
}

func hrNodeNumbersV3(device, inode, generation, birthtime string) bool {
	for _, value := range []string{device, inode, generation, birthtime} {
		if !stage2aDecimal.MatchString(value) {
			return false
		}
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func hrInventoryNamesV3(installationID string) (string, string) {
	slot := sha256.Sum256([]byte("agent-bot/stage2a-domain-slot/v3\x00R-runtime\x00" + installationID))
	stem := sha256.Sum256([]byte("agent-bot/stage2a-domain-snapshot/v3\x00R-runtime\x00" + installationID))
	parent := path.Join("/private/var/db/managed-machine/soul-snapshots", "r_"+hex.EncodeToString(slot[:10]))
	suffix := hex.EncodeToString(stem[:12])
	return path.Join(parent, "snap_"+suffix), path.Join(parent, "inventory_"+suffix+".jcs")
}

func hrInventoryRefShapeV3(raw []byte, binding measurementBinding) (hrInventoryRefV3, error) {
	var zero hrInventoryRefV3
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, "contract", "kind", "schema_version", "domain",
		"installation_id", "owner_plan_digest", "reviewed_source_inventory_digest",
		"machine_uid", "reader_uid", "reader_gid", "snapshot", "sidecar",
		"file_count", "directory_count", "total_bytes", "inventory_digest") {
		return zero, ErrUnqualified
	}
	snapshot, err := strictObject(fields["snapshot"], MaxReportBytes)
	if err != nil || !hasFields(snapshot, "path", "device", "inode", "generation", "birthtime_ns",
		"owner_uid", "owner_gid", "mode") {
		return zero, ErrUnqualified
	}
	sidecar, err := strictObject(fields["sidecar"], MaxReportBytes)
	if err != nil || !hasFields(sidecar, "path", "device", "inode", "generation", "birthtime_ns",
		"owner_uid", "owner_gid", "mode", "size_bytes", "sha256") {
		return zero, ErrUnqualified
	}
	var ref hrInventoryRefV3
	if json.Unmarshal(raw, &ref) != nil {
		return zero, ErrUnqualified
	}
	rootPath, sidecarPath := hrInventoryNamesV3(ref.InstallationID)
	if ref.Contract != "machine/v3" || ref.Kind != "stage2a-inventory-ref" ||
		ref.SchemaVersion != 3 || ref.Domain != "R-runtime" ||
		ref.InstallationID != binding.InstallationID ||
		ref.OwnerPlanDigest != "sha256:"+binding.InstalledPlanDigest ||
		!validSHA(ref.InventoryDigest) ||
		ref.ReviewedSourceInventoryDigest != ref.InventoryDigest ||
		ref.MachineUID < 400 || ref.MachineUID != binding.Snapshots.Definition.OwnerUID ||
		ref.ReaderUID == 0 || ref.ReaderUID == ref.MachineUID || ref.ReaderGID == 0 ||
		ref.FileCount < 1 || ref.FileCount > 512 ||
		ref.DirectoryCount < 0 || ref.DirectoryCount > 1024 ||
		ref.TotalBytes > 1<<30 ||
		ref.Snapshot.Path != rootPath || ref.Sidecar.Path != sidecarPath ||
		ref.Snapshot.OwnerUID != ref.MachineUID || ref.Snapshot.OwnerGID != ref.ReaderGID ||
		ref.Snapshot.Mode != "0555" ||
		!hrNodeNumbersV3(ref.Snapshot.Device, ref.Snapshot.Inode,
			ref.Snapshot.Generation, ref.Snapshot.BirthtimeNS) ||
		ref.Sidecar.OwnerUID != ref.MachineUID || ref.Sidecar.OwnerGID != ref.ReaderGID ||
		ref.Sidecar.Mode != "0440" || ref.Sidecar.SizeBytes < 1 ||
		ref.Sidecar.SizeBytes > 2<<20 || !validSHA(ref.Sidecar.SHA256) ||
		!hrNodeNumbersV3(ref.Sidecar.Device, ref.Sidecar.Inode,
			ref.Sidecar.Generation, ref.Sidecar.BirthtimeNS) {
		return zero, ErrUnqualified
	}
	return ref, nil
}

func hrComponentsV3(raw []byte) ([]hrReleaseComponentV3, error) {
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) < 1 || len(rows) > 32 {
		return nil, ErrUnqualified
	}
	result := make([]hrReleaseComponentV3, 0, len(rows))
	previous := ""
	for _, row := range rows {
		fields, err := strictObject(row, MaxReportBytes)
		if err != nil {
			return nil, ErrUnqualified
		}
		names := []string{"component_id", "source_repository", "source_commit",
			"release_artifact_sha256", "release_manifest_sha256"}
		if _, present := fields["source_tag"]; present {
			names = append(names, "source_tag")
		}
		if !hasFields(fields, names...) {
			return nil, ErrUnqualified
		}
		var component hrReleaseComponentV3
		if json.Unmarshal(row, &component) != nil ||
			!hrComponentIDV3.MatchString(component.ComponentID) ||
			component.ComponentID <= previous ||
			!hrRepositoryV3.MatchString(component.SourceRepository) ||
			!validHex(component.SourceCommit, 40) ||
			!validSHA(component.ReleaseArtifactSHA256) ||
			!validSHA(component.ReleaseManifestSHA256) {
			return nil, ErrUnqualified
		}
		if _, present := fields["source_tag"]; present &&
			!hrSourceTagV3.MatchString(component.SourceTag) {
			return nil, ErrUnqualified
		}
		result = append(result, component)
		previous = component.ComponentID
	}
	return result, nil
}

// parseHRMeasurementBindingV3 consumes the exact release-backed machine/v3
// H/R binding. It serves ordinary protected and managed-cooperative claims;
// the first-qualification candidate has a distinct binding. The common
// frozen definition/launch fields retain the v2 nonroot A constraints.
func parseHRMeasurementBindingV3(raw []byte) (hrMeasurementBindingV3, error) {
	var zero hrMeasurementBindingV3
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil || !hasFields(fields, "contract", "kind", "schema_version",
		"installation_id", "soul_id", "start_id", "launch_id", "host_id", "hq_epoch",
		"plan_id", "installed_plan_digest", "package_sha256", "profile_in_force",
		"claimed_definition_digest", "definition_measurement",
		"launch_input_measurement", "snapshots", "soul_artifact_sha256",
		"h_service_descriptor_digest", "r_inventory", "r_components",
		"adapter_release", "broker_executable") {
		return zero, ErrUnqualified
	}
	if string(fields["contract"]) != `"machine/v3"` ||
		string(fields["kind"]) != `"stage2a-measurement-binding"` ||
		string(fields["schema_version"]) != "3" {
		return zero, ErrUnqualified
	}
	legacyNames := []string{"contract", "kind", "schema_version", "installation_id",
		"soul_id", "start_id", "launch_id", "host_id", "hq_epoch", "plan_id",
		"installed_plan_digest", "package_sha256", "profile_in_force",
		"claimed_definition_digest", "definition_measurement",
		"launch_input_measurement", "snapshots", "soul_artifact_sha256"}
	legacy := make(map[string]json.RawMessage, len(legacyNames))
	for _, name := range legacyNames {
		legacy[name] = fields[name]
	}
	legacy["contract"] = json.RawMessage(`"machine/v2"`)
	legacy["schema_version"] = json.RawMessage("2")
	legacyRaw, err := json.Marshal(legacy)
	if err != nil {
		return zero, ErrUnqualified
	}
	base, err := parseMeasurementBindingV2(legacyRaw)
	if err != nil {
		return zero, ErrUnqualified
	}
	base.Contract, base.SchemaVersion = "machine/v3", 3
	var hDigest string
	if json.Unmarshal(fields["h_service_descriptor_digest"], &hDigest) != nil ||
		!validSHA(hDigest) {
		return zero, ErrUnqualified
	}
	r, err := hrInventoryRefShapeV3(fields["r_inventory"], base)
	if err != nil {
		return zero, ErrUnqualified
	}
	components, err := hrComponentsV3(fields["r_components"])
	if err != nil {
		return zero, ErrUnqualified
	}
	adapterFields, err := strictObject(fields["adapter_release"], MaxReportBytes)
	if err != nil || !hasFields(adapterFields, "component_id", "package_sha256",
		"release_attestation_sha256", "release_manifest_sha256",
		"executable_path", "executable_sha256", "code_inputs_digest",
		"code_input_count") {
		return zero, ErrUnqualified
	}
	var adapter hrAdapterReleaseV3
	if json.Unmarshal(fields["adapter_release"], &adapter) != nil ||
		!hrComponentIDV3.MatchString(adapter.ComponentID) ||
		!validSHA(adapter.PackageSHA256) ||
		!validSHA(adapter.ReleaseAttestationSHA256) ||
		!validSHA(adapter.ReleaseManifestSHA256) ||
		!reportPath(adapter.ExecutablePath) ||
		!strings.HasPrefix(adapter.ExecutablePath, r.Snapshot.Path+"/") ||
		!validSHA(adapter.ExecutableSHA256) ||
		!validSHA(adapter.CodeInputsDigest) ||
		adapter.CodeInputCount < 1 || adapter.CodeInputCount > 512 {
		return zero, ErrUnqualified
	}
	matched := false
	for _, component := range components {
		if component.ComponentID == adapter.ComponentID {
			if component.ReleaseArtifactSHA256 != adapter.PackageSHA256 ||
				component.ReleaseManifestSHA256 != adapter.ReleaseManifestSHA256 {
				return zero, ErrUnqualified
			}
			matched = true
		}
	}
	if !matched {
		return zero, ErrUnqualified
	}
	brokerFields, err := strictObject(fields["broker_executable"], MaxReportBytes)
	if err != nil || !hasFields(brokerFields, "path", "sha256", "provider_config_sha256") {
		return zero, ErrUnqualified
	}
	var broker hrBrokerExecutableV3
	if json.Unmarshal(fields["broker_executable"], &broker) != nil ||
		!reportPath(broker.Path) || !validSHA(broker.SHA256) ||
		!validSHA(broker.ProviderConfigSHA256) {
		return zero, ErrUnqualified
	}
	return hrMeasurementBindingV3{Base: base, HServiceDescriptorDigest: hDigest,
		RInventory: r, RComponents: components, AdapterRelease: adapter,
		BrokerExecutable: broker}, nil
}
