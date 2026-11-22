package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	stage2aDefinitionPurpose = "agent-bot/stage2a-definition-opt-closure/v1"
	stage2aMaxEntries        = 512
	stage2aMaxFileBytes      = 256 << 20
	stage2aMaxTotalBytes     = 1 << 30
)

// Stage2aDefinitionRecord is the portable part of one frozen snapshot entry.
// Custody facts and opened file bytes are checked by the future root-owned
// snapshot producer; this value is not evidence of either.
type Stage2aDefinitionRecord struct {
	Path   string  `json:"path"`
	Kind   string  `json:"kind"`
	Mode   string  `json:"mode"`
	Size   *uint64 `json:"size,omitempty"`
	SHA256 string  `json:"sha256,omitempty"`
}

func stage2aRecordPath(p string) bool {
	if len(p) == 0 || len(p) > 4096 || p[0] == '/' || p[len(p)-1] == '/' ||
		strings.Contains(p, "//") || strings.Contains(p, "\\") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false
		}
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func stage2aReadOnlyMode(mode string) bool {
	if len(mode) != 4 {
		return false
	}
	for i := range mode {
		if mode[i] < '0' || mode[i] > '7' {
			return false
		}
	}
	// Frozen source is read-only even for its root owner and carries no
	// set-ID or sticky bits. Physical custody still needs descriptor checks.
	return mode[0] == '0' && (mode[1]-'0')&2 == 0 &&
		(mode[2]-'0')&2 == 0 && (mode[3]-'0')&2 == 0
}

// Stage2aDefinitionDigest validates a portable record array and hashes its
// RFC 8785 JCS bytes in the Platform's distinct definition domain. A caller
// must independently prove the physical root-owned snapshot, exact opened
// bytes, absence of links/ACLs, and owner-approved inventory before use.
func Stage2aDefinitionDigest(records []Stage2aDefinitionRecord) (string, []byte, error) {
	invalid := errors.New("invalid Stage 2a frozen definition records")
	if len(records) < 5 || len(records) > stage2aMaxEntries {
		return "", nil, invalid
	}
	kinds := make(map[string]string, len(records))
	aliases := make(map[string]bool, len(records))
	var total uint64
	var previous string
	for i, r := range records {
		if !stage2aRecordPath(r.Path) || !stage2aReadOnlyMode(r.Mode) ||
			(i != 0 && r.Path <= previous) || aliases[strings.ToLower(r.Path)] {
			return "", nil, invalid
		}
		previous = r.Path
		aliases[strings.ToLower(r.Path)] = true
		if r.Path != "Contents" && !strings.HasPrefix(r.Path, "Contents/") {
			return "", nil, invalid
		}
		if r.Path != "Contents" && r.Path != "Contents/SoulInfo.json" &&
			r.Path != "Contents/SoulLock.json" && r.Path != "Contents/opt" &&
			r.Path != "Contents/primitives" &&
			!strings.HasPrefix(r.Path, "Contents/opt/") &&
			!strings.HasPrefix(r.Path, "Contents/primitives/") {
			return "", nil, invalid
		}
		if r.Path != "Contents" && kinds[path.Dir(r.Path)] != "directory" {
			return "", nil, invalid
		}
		switch r.Kind {
		case "directory":
			if r.Size != nil || r.SHA256 != "" {
				return "", nil, invalid
			}
		case "regular":
			if r.Size == nil || *r.Size > stage2aMaxFileBytes || !soulDigest.MatchString(r.SHA256) ||
				total > stage2aMaxTotalBytes-*r.Size {
				return "", nil, invalid
			}
			total += *r.Size
		default:
			return "", nil, invalid
		}
		kinds[r.Path] = r.Kind
	}
	for required, kind := range map[string]string{
		"Contents": "directory", "Contents/SoulInfo.json": "regular",
		"Contents/SoulLock.json": "regular", "Contents/opt": "directory",
		"Contents/primitives": "directory",
	} {
		if kinds[required] != kind {
			return "", nil, invalid
		}
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return "", nil, invalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", nil, invalid
	}
	preimage := append([]byte(stage2aDefinitionPurpose+"\x00"), canonical...)
	sum := sha256.Sum256(preimage)
	return fmt.Sprintf("sha256:%x", sum), canonical, nil
}

// CheckStage2aApprovedDefinition compares the complete observed array with
// the exact owner-approved array. Both must be independently sourced; passing
// the same caller-controlled records twice conveys no launch authority.
func CheckStage2aApprovedDefinition(observed, approved []Stage2aDefinitionRecord) (string, error) {
	got, gotBytes, err := Stage2aDefinitionDigest(observed)
	if err != nil {
		return "", err
	}
	_, approvedBytes, err := Stage2aDefinitionDigest(approved)
	if err != nil || !reflect.DeepEqual(observed, approved) || !bytes.Equal(gotBytes, approvedBytes) {
		return "", errors.New("Stage 2a definition differs from owner-approved inventory")
	}
	return got, nil
}
