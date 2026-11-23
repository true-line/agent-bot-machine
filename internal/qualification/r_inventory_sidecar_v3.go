package qualification

import (
	"crypto/ed25519"
	"encoding/json"
	"path"
	"regexp"
	"strings"
	"time"
)

const rInventoryPurposeV3 = "agent-bot/stage2a-r-runtime-inventory/v3"

var rInventoryPathV3 = regexp.MustCompile("^[A-Za-z0-9._+@/-]+$")

type rInventoryLimitsV3 struct {
	MaxFiles      uint64 `json:"max_files"`
	MaxFileBytes  uint64 `json:"max_file_bytes"`
	MaxTotalBytes uint64 `json:"max_total_bytes"`
}

type rInventoryDirectoryV3 struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Mode string `json:"mode"`
}

type rInventoryFileV3 struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Mode        string `json:"mode"`
	SizeBytes   uint64 `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	ComponentID string `json:"component_id"`
	ReleasePath string `json:"release_path"`
}

type rInventorySidecarV3 struct {
	Contract       string                  `json:"contract"`
	Kind           string                  `json:"kind"`
	SchemaVersion  int                     `json:"schema_version"`
	Domain         string                  `json:"domain"`
	InstallationID string                  `json:"installation_id"`
	Limits         rInventoryLimitsV3      `json:"limits"`
	Directories    []rInventoryDirectoryV3 `json:"directories"`
	Files          []rInventoryFileV3      `json:"files"`
	TotalBytes     uint64                  `json:"total_bytes"`
}

func rInventoryRecordPathV3(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !rInventoryPathV3.MatchString(value) ||
		value[0] == '/' || value[len(value)-1] == '/' ||
		strings.Contains(value, "//") || strings.Count(value, "/") > 16 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// verifyRInventorySidecarV3 checks the exact canonical sidecar against the
// R reference carried by an independently authenticated A reservation. It
// validates the portable closure and release-path claims, not installed file
// custody, release manifest bytes, or physical observation.
func verifyRInventorySidecarV3(raw []byte, ref hrInventoryRefV3) (rInventorySidecarV3, error) {
	var zero rInventorySidecarV3
	fields, err := canonicalBytes(raw, 2<<20)
	if err != nil || !hasFields(fields, "contract", "kind", "schema_version", "domain",
		"installation_id", "limits", "directories", "files", "total_bytes") ||
		ref.Contract != "machine/v3" || ref.Kind != "stage2a-inventory-ref" ||
		ref.SchemaVersion != 3 || ref.Domain != "R-runtime" ||
		ref.Sidecar.SizeBytes < 1 || ref.Sidecar.SizeBytes > 2<<20 ||
		len(raw) != int(ref.Sidecar.SizeBytes) || digest(raw) != ref.Sidecar.SHA256 ||
		digest(preimage(rInventoryPurposeV3, raw)) != ref.InventoryDigest ||
		ref.ReviewedSourceInventoryDigest != ref.InventoryDigest {
		return zero, ErrUnqualified
	}
	limitsFields, err := strictObject(fields["limits"], 2<<20)
	if err != nil || !hasFields(limitsFields, "max_files", "max_file_bytes", "max_total_bytes") {
		return zero, ErrUnqualified
	}
	var inv rInventorySidecarV3
	if json.Unmarshal(raw, &inv) != nil || inv.Contract != "machine/v3" ||
		inv.Kind != "stage2a-domain-inventory" || inv.SchemaVersion != 3 ||
		inv.Domain != "R-runtime" || inv.InstallationID != ref.InstallationID ||
		len(inv.Files) < 1 || len(inv.Files) > 512 ||
		len(inv.Directories) > 1024 || len(inv.Files) != ref.FileCount ||
		len(inv.Directories) != ref.DirectoryCount || inv.TotalBytes != ref.TotalBytes ||
		inv.Limits.MaxFiles < 1 || inv.Limits.MaxFiles > 512 ||
		uint64(len(inv.Files)) > inv.Limits.MaxFiles ||
		inv.Limits.MaxFileBytes < 1 || inv.Limits.MaxFileBytes > 402653184 ||
		inv.Limits.MaxTotalBytes < 1 || inv.Limits.MaxTotalBytes > 1<<30 ||
		inv.TotalBytes > inv.Limits.MaxTotalBytes {
		return zero, ErrUnqualified
	}
	var fileRows, dirRows []json.RawMessage
	if json.Unmarshal(fields["files"], &fileRows) != nil || len(fileRows) != len(inv.Files) ||
		json.Unmarshal(fields["directories"], &dirRows) != nil || len(dirRows) != len(inv.Directories) {
		return zero, ErrUnqualified
	}
	seen := make(map[string]bool, len(inv.Files)+len(inv.Directories))
	released := make(map[string]bool, len(inv.Files))
	parents := make(map[string]bool)
	previous := ""
	var total uint64
	for i, file := range inv.Files {
		row, err := strictObject(fileRows[i], 2<<20)
		if err != nil || !hasFields(row, "path", "kind", "mode", "size_bytes", "sha256",
			"component_id", "release_path") ||
			!rInventoryRecordPathV3(file.Path) || file.Path <= previous ||
			seen[strings.ToLower(file.Path)] ||
			file.Kind != "regular" || file.Mode != "0440" && file.Mode != "0550" ||
			file.SizeBytes > inv.Limits.MaxFileBytes || !validSHA(file.SHA256) ||
			!hrComponentIDV3.MatchString(file.ComponentID) ||
			!rInventoryRecordPathV3(file.ReleasePath) ||
			released[file.ComponentID+"\x00"+strings.ToLower(file.ReleasePath)] ||
			file.SizeBytes > inv.Limits.MaxTotalBytes ||
			total > inv.Limits.MaxTotalBytes-file.SizeBytes {
			return zero, ErrUnqualified
		}
		total += file.SizeBytes
		previous = file.Path
		seen[strings.ToLower(file.Path)] = true
		released[file.ComponentID+"\x00"+strings.ToLower(file.ReleasePath)] = true
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			parents[parent] = true
		}
	}
	if total != inv.TotalBytes || len(parents) != len(inv.Directories) {
		return zero, ErrUnqualified
	}
	previous = ""
	for i, dir := range inv.Directories {
		row, err := strictObject(dirRows[i], 2<<20)
		if err != nil || !hasFields(row, "path", "kind", "mode") ||
			!rInventoryRecordPathV3(dir.Path) || dir.Path <= previous ||
			seen[strings.ToLower(dir.Path)] || !parents[dir.Path] ||
			dir.Kind != "directory" || dir.Mode != "0550" && dir.Mode != "0555" {
			return zero, ErrUnqualified
		}
		previous = dir.Path
		seen[strings.ToLower(dir.Path)] = true
	}
	return inv, nil
}

// verifyRAdapterReportInventoryV3 joins the adapter executable and every
// reported code input to the A-referenced R inventory's exact file digests.
// The caller must first authenticate the host report and A reservation. This
// diagnostic does not authenticate the actual installed files, component
// release manifests, Q runner, or physical gate results.
func verifyRAdapterReportInventoryV3(reportRaw, inventoryRaw []byte,
	binding hrMeasurementBindingV3) error {
	inv, err := verifyRInventorySidecarV3(inventoryRaw, binding.RInventory)
	if err != nil {
		return ErrUnqualified
	}
	fields, err := canonicalBytes(reportRaw, MaxReportBytes)
	if err != nil || fields["adapter"] == nil || fields["launch"] == nil {
		return ErrUnqualified
	}
	adapterFields, err := strictObject(fields["adapter"], MaxReportBytes)
	if err != nil || !hasFields(adapterFields, "id", "version", "package_sha256") {
		return ErrUnqualified
	}
	launchFields, err := strictObject(fields["launch"], MaxReportBytes)
	if err != nil || !hasFields(launchFields, "executable", "executable_sha256", "argv", "code_inputs") {
		return ErrUnqualified
	}
	var report struct {
		Adapter struct {
			PackageSHA256 string `json:"package_sha256"`
		} `json:"adapter"`
		Launch struct {
			Executable       string       `json:"executable"`
			ExecutableSHA256 string       `json:"executable_sha256"`
			CodeInputs       []reportFile `json:"code_inputs"`
		} `json:"launch"`
	}
	if json.Unmarshal(reportRaw, &report) != nil ||
		report.Adapter.PackageSHA256 != binding.AdapterRelease.PackageSHA256 ||
		report.Launch.Executable != binding.AdapterRelease.ExecutablePath ||
		report.Launch.ExecutableSHA256 != binding.AdapterRelease.ExecutableSHA256 ||
		len(report.Launch.CodeInputs) != binding.AdapterRelease.CodeInputCount {
		return ErrUnqualified
	}
	files := make(map[string]rInventoryFileV3, len(inv.Files))
	for _, file := range inv.Files {
		files[file.Path] = file
	}
	root := binding.RInventory.Snapshot.Path + "/"
	if !strings.HasPrefix(report.Launch.Executable, root) {
		return ErrUnqualified
	}
	executable, ok := files[strings.TrimPrefix(report.Launch.Executable, root)]
	if !ok || executable.ComponentID != binding.AdapterRelease.ComponentID ||
		executable.SHA256 != report.Launch.ExecutableSHA256 || executable.Mode != "0550" {
		return ErrUnqualified
	}
	seen := map[string]bool{report.Launch.Executable: true}
	for _, input := range report.Launch.CodeInputs {
		if !strings.HasPrefix(input.Path, root) || !validSHA(input.SHA256) || seen[input.Path] {
			return ErrUnqualified
		}
		file, ok := files[strings.TrimPrefix(input.Path, root)]
		if !ok || file.ComponentID != binding.AdapterRelease.ComponentID || file.SHA256 != input.SHA256 {
			return ErrUnqualified
		}
		seen[input.Path] = true
	}
	return nil
}

// CheckCooperativeHostReportRInventoryV3 authenticates a designated-host
// cooperative report and A reservation, then joins the report's adapter file
// hashes to the exact A-referenced R inventory sidecar. It is an offline
// diagnostic only: installed byte custody, release provenance and physical
// T21 results are still required before any positive qualification.
func CheckCooperativeHostReportRInventoryV3(hostEnvelope, reservationEnvelope,
	inventoryRaw []byte, policy VerifiedPolicy, machineKey ed25519.PublicKey,
	now time.Time) error {
	report, err := VerifyHostReportV3(hostEnvelope, policy, now)
	if err != nil || cooperativeReportJoinV3(report, reservationEnvelope, machineKey) != nil {
		return ErrUnqualified
	}
	payload, err := qSignedRecordV3(reservationEnvelope, cooperativeReservationPurposeV3, 3, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	fields, err := canonicalBytes(payload, 48<<10)
	if err != nil || fields["measurement_binding"] == nil {
		return ErrUnqualified
	}
	binding, err := parseHRMeasurementBindingV3(fields["measurement_binding"])
	if err != nil {
		return ErrUnqualified
	}
	return verifyRAdapterReportInventoryV3(report, inventoryRaw, binding)
}
