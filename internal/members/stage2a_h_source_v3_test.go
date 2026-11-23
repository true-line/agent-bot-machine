package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func stage2aHSourceTestSelection(t *testing.T) (stage2aDomainInventoryV3, []stage2aHSourceManifestRowV3, []string, string) {
	t.Helper()
	inv := stage2aV3TestInventory()
	inv.Directories = []stage2aDomainDirectoryV3{
		{Path: "bin", Kind: "directory", Mode: "0550"},
		{Path: "governance", Kind: "directory", Mode: "0550"},
		{Path: "hq", Kind: "directory", Mode: "0550"},
	}
	metadata := stage2aDomainFileV3{Path: "governance/interim-release.json", Kind: "regular", Mode: "0440",
		SizeBytes: 10, SHA256: "sha256:" + strings.Repeat("4", 64), ComponentID: "hq",
		ReleasePath: "governance/interim-release.json"}
	contractsPin := stage2aDomainFileV3{Path: "governance/soul-contracts.json", Kind: "regular", Mode: "0440",
		SizeBytes: 10, SHA256: "sha256:" + strings.Repeat("7", 64), ComponentID: "hq",
		ReleasePath: "governance/soul-contracts.json"}
	inv.Files = append(inv.Files[:1], append([]stage2aDomainFileV3{metadata, contractsPin}, inv.Files[1:]...)...)
	inv.TotalBytes += metadata.SizeBytes + contractsPin.SizeBytes
	omitted := "vendor/soul-contracts/fixtures/negative/synthetic.bad.json"
	rows := []stage2aHSourceManifestRowV3{
		{Path: metadata.Path, SHA256: metadata.SHA256},
		{Path: contractsPin.Path, SHA256: contractsPin.SHA256},
		{Path: "hq/index.mjs", SHA256: inv.Files[3].SHA256},
		{Path: omitted, SHA256: "sha256:" + strings.Repeat("5", 64)},
	}
	return inv, rows, []string{omitted}, inv.Files[0].SHA256
}

func stage2aHSourceTestManifest(t *testing.T, rows []stage2aHSourceManifestRowV3) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return canonical, fmt.Sprintf("sha256:%x", sum)
}

func TestStage2aHSourceV3SelectedExcludedClosure(t *testing.T) {
	inv, rows, excluded, nodeDigest := stage2aHSourceTestSelection(t)
	if _, _, err := stage2aDomainInventoryDigestV3(stage2aV3TestCanonical(t, inv)); err != nil {
		t.Fatalf("fixture inventory invalid: %v", err)
	}
	raw, digest := stage2aHSourceTestManifest(t, rows)
	if err := stage2aValidateHSourceSelectionV3(inv, raw, digest, excluded, nodeDigest); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		change func(*stage2aDomainInventoryV3, *[]stage2aHSourceManifestRowV3, *[]string, *string)
	}{
		{"missing omitted row", func(_ *stage2aDomainInventoryV3, rows *[]stage2aHSourceManifestRowV3, _ *[]string, _ *string) {
			*rows = (*rows)[:3]
		}},
		{"changed installed source hash", func(inv *stage2aDomainInventoryV3, _ *[]stage2aHSourceManifestRowV3, _ *[]string, _ *string) {
			inv.Files[3].SHA256 = "sha256:" + strings.Repeat("6", 64)
		}},
		{"node artifact changed", func(_ *stage2aDomainInventoryV3, _ *[]stage2aHSourceManifestRowV3, _ *[]string, node *string) {
			*node = "sha256:" + strings.Repeat("6", 64)
		}},
		{"unreviewed component", func(inv *stage2aDomainInventoryV3, _ *[]stage2aHSourceManifestRowV3, _ *[]string, _ *string) {
			inv.Files[3].ComponentID = "other"
		}},
		{"omission not a fixture", func(_ *stage2aDomainInventoryV3, rows *[]stage2aHSourceManifestRowV3, excluded *[]string, _ *string) {
			(*rows)[3].Path = "hq/secret.mjs"
			(*excluded)[0] = "hq/secret.mjs"
		}},
		{"omission selected", func(_ *stage2aDomainInventoryV3, _ *[]stage2aHSourceManifestRowV3, excluded *[]string, _ *string) {
			(*excluded)[0] = "vendor/soul-contracts/fixtures/negative/other.bad.json"
		}},
		{"duplicate source path", func(_ *stage2aDomainInventoryV3, rows *[]stage2aHSourceManifestRowV3, _ *[]string, _ *string) {
			(*rows)[3].Path = (*rows)[2].Path
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := inv
			candidate.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
			candidateRows := append([]stage2aHSourceManifestRowV3(nil), rows...)
			candidateExcluded := append([]string(nil), excluded...)
			candidateNode := nodeDigest
			tt.change(&candidate, &candidateRows, &candidateExcluded, &candidateNode)
			raw, digest := stage2aHSourceTestManifest(t, candidateRows)
			if err := stage2aValidateHSourceSelectionV3(candidate, raw, digest, candidateExcluded, candidateNode); err == nil {
				t.Fatal("accepted changed H source selection")
			}
		})
	}
	if err := stage2aValidateHSourceSelectionV3(inv, raw, "sha256:"+strings.Repeat("0", 64), excluded, nodeDigest); err == nil {
		t.Fatal("accepted wrong manifest pin")
	}
	if err := stage2aValidateHSourceSelectionV3(inv, append([]byte(" "), raw...), digest, excluded, nodeDigest); err == nil {
		t.Fatal("accepted noncanonical manifest")
	}
}

func TestStage2aHSourceV3OmissionBound(t *testing.T) {
	inv, baseRows, _, nodeDigest := stage2aHSourceTestSelection(t)
	for _, count := range []int{192, 193} {
		rows := append([]stage2aHSourceManifestRowV3(nil), baseRows[:3]...)
		excluded := make([]string, 0, count)
		for i := range count {
			path := fmt.Sprintf("vendor/soul-contracts/fixtures/negative/synthetic-%03d.bad.json", i)
			rows = append(rows, stage2aHSourceManifestRowV3{Path: path, SHA256: "sha256:" + strings.Repeat("5", 64)})
			excluded = append(excluded, path)
		}
		raw, digest := stage2aHSourceTestManifest(t, rows)
		err := stage2aValidateHSourceSelectionV3(inv, raw, digest, excluded, nodeDigest)
		if count == 192 && err != nil {
			t.Fatalf("rejected 192 reviewed omissions: %v", err)
		}
		if count == 193 && err == nil {
			t.Fatal("accepted 193 omissions")
		}
	}
}
