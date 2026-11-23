package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	stage2aDomainSnapshotParentV3     = "/private/var/db/managed-machine/soul-snapshots"
	stage2aHCodeInventoryPurposeV3    = "agent-bot/stage2a-h-code-inventory/v3"
	stage2aRRuntimeInventoryPurposeV3 = "agent-bot/stage2a-r-runtime-inventory/v3"
	stage2aV3MaxInventoryFileBytes    = 402653184
	stage2aV3MaxInventoryTotalBytes   = 1 << 30
	stage2aV3MaxJSONNodes             = 16384
)

// These POSIX paths are Machine's macOS targets even when a plan is rendered
// on another build OS. Distinct purposes keep H and R installation slots apart.
func stage2aDomainNamesV3(domain, installationID string) (namespace, snapshot, sidecar string, err error) {
	if !stage2aBindingID.MatchString(installationID) ||
		(domain != "H-code" && domain != "R-runtime") {
		return "", "", "", errors.New("invalid Stage 2a v3 domain slot")
	}
	slotSum := sha256.Sum256([]byte("agent-bot/stage2a-domain-slot/v3\x00" + domain + "\x00" + installationID))
	snapshotSum := sha256.Sum256([]byte("agent-bot/stage2a-domain-snapshot/v3\x00" + domain + "\x00" + installationID))
	prefix := "hq_"
	if domain == "R-runtime" {
		prefix = "r_"
	}
	stem := hex.EncodeToString(snapshotSum[:12])
	return path.Join(stage2aDomainSnapshotParentV3, prefix+hex.EncodeToString(slotSum[:10])),
		"snap_" + stem, "inventory_" + stem + ".jcs", nil
}

var stage2aV3InventoryPath = regexp.MustCompile(`^[A-Za-z0-9._+@/-]+$`)

type stage2aDomainInventoryLimitsV3 struct {
	MaxFiles      uint64 `json:"max_files"`
	MaxFileBytes  uint64 `json:"max_file_bytes"`
	MaxTotalBytes uint64 `json:"max_total_bytes"`
}

type stage2aDomainDirectoryV3 struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Mode string `json:"mode"`
}

type stage2aDomainFileV3 struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Mode        string `json:"mode"`
	SizeBytes   uint64 `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	ComponentID string `json:"component_id"`
	ReleasePath string `json:"release_path"`
}

// This is only the portable, owner-reviewable source inventory. Physical
// custody, exact release manifests, approved numeric policy and A's installed
// signature are separate checks. Parsing it cannot enable a protected start.
type stage2aDomainInventoryV3 struct {
	Contract       string                         `json:"contract"`
	Kind           string                         `json:"kind"`
	SchemaVersion  int                            `json:"schema_version"`
	Domain         string                         `json:"domain"`
	InstallationID string                         `json:"installation_id"`
	Limits         stage2aDomainInventoryLimitsV3 `json:"limits"`
	Directories    []stage2aDomainDirectoryV3     `json:"directories"`
	Files          []stage2aDomainFileV3          `json:"files"`
	TotalBytes     uint64                         `json:"total_bytes"`
}

func stage2aV3InventoryRecordPath(value string) bool {
	return len(value) <= 1024 && stage2aRecordPath(value) && stage2aV3InventoryPath.MatchString(value)
}

func stage2aDomainInventoryDigestV3(raw []byte) (stage2aDomainInventoryV3, string, error) {
	var inv stage2aDomainInventoryV3
	invalid := errors.New("invalid Stage 2a v3 domain inventory")
	if stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return inv, "", invalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return inv, "", invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&inv) != nil || decoder.Decode(new(any)) != io.EOF ||
		inv.Contract != "machine/v3" || inv.Kind != "stage2a-domain-inventory" ||
		inv.SchemaVersion != 3 || !stage2aBindingID.MatchString(inv.InstallationID) ||
		len(inv.Files) == 0 || len(inv.Files) > 512 || len(inv.Directories) > 1024 ||
		inv.Limits.MaxFiles == 0 || inv.Limits.MaxFiles > 512 ||
		inv.Limits.MaxFileBytes == 0 || inv.Limits.MaxFileBytes > stage2aV3MaxInventoryFileBytes ||
		inv.Limits.MaxTotalBytes == 0 || inv.Limits.MaxTotalBytes > stage2aV3MaxInventoryTotalBytes ||
		uint64(len(inv.Files)) > inv.Limits.MaxFiles {
		return inv, "", invalid
	}
	purpose := stage2aHCodeInventoryPurposeV3
	if inv.Domain == "R-runtime" {
		purpose = stage2aRRuntimeInventoryPurposeV3
	} else if inv.Domain != "H-code" {
		return inv, "", invalid
	}
	parents := make(map[string]bool, len(inv.Directories))
	seen := make(map[string]bool, len(inv.Directories)+len(inv.Files))
	released := make(map[string]bool, len(inv.Files))
	previous := ""
	for _, file := range inv.Files {
		folded := strings.ToLower(file.Path)
		if !stage2aV3InventoryRecordPath(file.Path) || strings.Count(file.Path, "/") > 16 ||
			file.Path <= previous || seen[folded] ||
			file.Kind != "regular" || file.Mode != "0440" && file.Mode != "0550" ||
			file.SizeBytes > inv.Limits.MaxFileBytes || !stage2aPrefixedDigest.MatchString(file.SHA256) ||
			!stage2aBindingID.MatchString(file.ComponentID) ||
			!stage2aV3InventoryRecordPath(file.ReleasePath) ||
			released[file.ComponentID+"\x00"+strings.ToLower(file.ReleasePath)] {
			return inv, "", invalid
		}
		previous = file.Path
		seen[folded] = true
		released[file.ComponentID+"\x00"+strings.ToLower(file.ReleasePath)] = true
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			parents[parent] = true
		}
	}
	if inv.TotalBytes > inv.Limits.MaxTotalBytes {
		return inv, "", invalid
	}
	var total uint64
	for _, file := range inv.Files {
		total += file.SizeBytes
	}
	if total != inv.TotalBytes || len(parents) != len(inv.Directories) {
		return inv, "", invalid
	}
	previous = ""
	for _, dir := range inv.Directories {
		folded := strings.ToLower(dir.Path)
		if !stage2aV3InventoryRecordPath(dir.Path) || dir.Path <= previous ||
			seen[folded] || !parents[dir.Path] || dir.Kind != "directory" ||
			dir.Mode != "0550" && dir.Mode != "0555" {
			return inv, "", invalid
		}
		previous = dir.Path
		seen[folded] = true
	}
	sum := sha256.Sum256(append([]byte(purpose+"\x00"), raw...))
	return inv, fmt.Sprintf("sha256:%x", sum), nil
}
