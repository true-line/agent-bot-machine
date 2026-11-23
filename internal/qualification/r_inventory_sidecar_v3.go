package qualification

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
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
