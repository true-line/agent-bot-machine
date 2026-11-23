//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestCooperativeRuntimeEntrySelectionRequiresReviewedNodeAndSoulsBytes(t *testing.T) {
	p := SoulCooperativeLaunchPolicy{NodeSHA256: strings.Repeat("a", 64)}
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{
		{Path: "bin/agent-bot-souls.mjs", Kind: "regular", Mode: "0440", ComponentID: "souls",
			SHA256: "sha256:" + strings.Repeat("b", 64)},
		{Path: "bin/node", Kind: "regular", Mode: "0550",
			SHA256: "sha256:" + p.NodeSHA256},
		{Path: "package.json", Kind: "regular", Mode: "0440", ComponentID: "souls",
			SHA256: "sha256:" + strings.Repeat("d", 64)},
	}}
	if !cooperativeRuntimeEntriesMatch(inv, p) {
		t.Fatal("reviewed R entry rows refused")
	}
	withoutPackage := inv
	withoutPackage.Files = inv.Files[:2]
	if cooperativeRuntimeEntriesMatch(withoutPackage, p) {
		t.Fatal("Souls CLI without package metadata accepted")
	}
	inv.Files[1].SHA256 = "sha256:" + strings.Repeat("c", 64)
	if cooperativeRuntimeEntriesMatch(inv, p) {
		t.Fatal("changed Node row accepted")
	}
	inv.Files[1].SHA256 = "sha256:" + p.NodeSHA256
	inv.Files[0].Mode = "0660"
	if cooperativeRuntimeEntriesMatch(inv, p) {
		t.Fatal("writable Souls entry accepted")
	}
}
