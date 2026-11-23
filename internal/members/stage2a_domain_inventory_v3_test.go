package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func stage2aV3TestInventory() stage2aDomainInventoryV3 {
	return stage2aDomainInventoryV3{
		Contract: "machine/v3", Kind: "stage2a-domain-inventory", SchemaVersion: 3,
		Domain: "H-code", InstallationID: "hq-test-1",
		Limits:      stage2aDomainInventoryLimitsV3{MaxFiles: 512, MaxFileBytes: stage2aV3MaxInventoryFileBytes, MaxTotalBytes: stage2aV3MaxInventoryTotalBytes},
		Directories: []stage2aDomainDirectoryV3{{Path: "bin", Kind: "directory", Mode: "0550"}, {Path: "hq", Kind: "directory", Mode: "0550"}},
		Files: []stage2aDomainFileV3{
			{Path: "bin/node", Kind: "regular", Mode: "0550", SizeBytes: 100, SHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222", ComponentID: "node", ReleasePath: "bin/node"},
			{Path: "hq/index.mjs", Kind: "regular", Mode: "0440", SizeBytes: 21, SHA256: "sha256:3333333333333333333333333333333333333333333333333333333333333333", ComponentID: "hq", ReleasePath: "hq/index.mjs"},
		}, TotalBytes: 121,
	}
}

func stage2aV3TestCanonical(t *testing.T, inv stage2aDomainInventoryV3) []byte {
	t.Helper()
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestStage2aV3DomainInventoryDigestAndRefusals(t *testing.T) {
	base := stage2aV3TestInventory()
	hRaw := stage2aV3TestCanonical(t, base)
	_, hDigest, err := stage2aDomainInventoryDigestV3(hRaw)
	if err != nil {
		t.Fatal(err)
	}
	hSum := sha256.Sum256(append([]byte(stage2aHCodeInventoryPurposeV3+"\x00"), hRaw...))
	if hDigest != fmt.Sprintf("sha256:%x", hSum) {
		t.Fatalf("H digest = %s", hDigest)
	}
	base.Domain = "R-runtime"
	rRaw := stage2aV3TestCanonical(t, base)
	_, rDigest, err := stage2aDomainInventoryDigestV3(rRaw)
	if err != nil || rDigest == hDigest {
		t.Fatalf("R purpose-separated inventory digest = %s, err = %v", rDigest, err)
	}

	invalid := []struct {
		name string
		edit func(*stage2aDomainInventoryV3)
	}{
		{"missing parent", func(v *stage2aDomainInventoryV3) { v.Directories = v.Directories[:1] }},
		{"extra empty directory", func(v *stage2aDomainInventoryV3) {
			v.Directories = append(v.Directories, stage2aDomainDirectoryV3{Path: "unused", Kind: "directory", Mode: "0555"})
		}},
		{"file alias", func(v *stage2aDomainInventoryV3) { v.Files[1].Path = "bin" }},
		{"case alias", func(v *stage2aDomainInventoryV3) { v.Files[1].Path = "BIN/node" }},
		{"unsorted files", func(v *stage2aDomainInventoryV3) { v.Files[0], v.Files[1] = v.Files[1], v.Files[0] }},
		{"duplicate release row", func(v *stage2aDomainInventoryV3) {
			v.Files[1].ComponentID = "node"
			v.Files[1].ReleasePath = "bin/node"
		}},
		{"relative traversal", func(v *stage2aDomainInventoryV3) { v.Files[1].Path = "hq/../index.mjs" }},
		{"file exceeds limit", func(v *stage2aDomainInventoryV3) { v.Limits.MaxFileBytes = 20 }},
		{"incorrect total", func(v *stage2aDomainInventoryV3) { v.TotalBytes++ }},
		{"wrong domain", func(v *stage2aDomainInventoryV3) { v.Domain = "B-broker" }},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			v := stage2aV3TestInventory()
			tt.edit(&v)
			if _, _, err := stage2aDomainInventoryDigestV3(stage2aV3TestCanonical(t, v)); err == nil {
				t.Fatal("accepted invalid inventory")
			}
		})
	}
	if _, _, err := stage2aDomainInventoryDigestV3(append([]byte(" "), hRaw...)); err == nil {
		t.Fatal("accepted noncanonical bytes")
	}
	unknown := append(append([]byte(nil), hRaw[:len(hRaw)-1]...), []byte(`,"unreviewed":true}`)...)
	if _, _, err := stage2aDomainInventoryDigestV3(unknown); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestStage2aV3InventoryMaximumFileAndDirectoryClosure(t *testing.T) {
	inv := stage2aV3TestInventory()
	inv.Directories = nil
	inv.Files = nil
	inv.TotalBytes = 0
	inv.Limits.MaxFileBytes = 1
	for i := 0; i < 512; i++ {
		parent := fmt.Sprintf("d%03d", i)
		inv.Directories = append(inv.Directories,
			stage2aDomainDirectoryV3{Path: parent, Kind: "directory", Mode: "0550"},
			stage2aDomainDirectoryV3{Path: parent + "/a", Kind: "directory", Mode: "0550"})
		path := parent + "/a/f"
		inv.Files = append(inv.Files, stage2aDomainFileV3{Path: path, Kind: "regular", Mode: "0440",
			SizeBytes: 0, SHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			ComponentID: "max-fixture", ReleasePath: path})
	}
	raw := stage2aV3TestCanonical(t, inv)
	if len(raw) > 2<<20 || stage2aStrictJSON(raw) == nil {
		t.Fatalf("fixture did not exercise v3-only parser budget: bytes=%d", len(raw))
	}
	if _, _, err := stage2aDomainInventoryDigestV3(raw); err != nil {
		t.Fatalf("declared maximum closure refused: %v", err)
	}
	outer, err := json.Marshal(struct {
		Schema    string          `json:"schema"`
		Inventory json.RawMessage `json:"inventory"`
	}{Schema: "agent-bot-machine/stage2a-domain-install-seal/v3", Inventory: raw})
	if err != nil || stage2aStrictJSONBounded(outer, 3<<20, stage2aV3MaxJSONNodes) != nil {
		t.Fatalf("v3 outer handoff budget refused maximum inventory: %v", err)
	}
}
