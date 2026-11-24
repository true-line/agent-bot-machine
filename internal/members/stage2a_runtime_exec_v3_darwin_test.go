//go:build darwin

package members

import (
	"path/filepath"
	"testing"
)

func TestStage2aRunnerCodeRowsV3RequireSealedNodeAndEntry(t *testing.T) {
	ref := stage2aDomainInventoryRefV3{Snapshot: stage2aDomainNodeRefV3{Path: "/private/r-snapshot"}}
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{
		{Path: "runtime/bin/node", ComponentID: "node", Mode: "0550"},
		{Path: "runtime/bin/agent-bot-souls.mjs", ComponentID: "souls", Mode: "0440"},
	}}
	node := filepath.Join(ref.Snapshot.Path, inv.Files[0].Path)
	entry := filepath.Join(ref.Snapshot.Path, inv.Files[1].Path)
	if err := stage2aRunnerCodeRowsV3(ref, inv, node, entry); err != nil {
		t.Fatalf("sealed R code refused: %v", err)
	}
	for _, tc := range []struct {
		name, node, entry string
		mutate            func(*stage2aDomainInventoryV3)
	}{
		{"legacy node", "/private/legacy/bin/node", entry, nil},
		{"legacy entry", node, "/private/legacy/bin/agent-bot-souls.mjs", nil},
		{"wrong component", node, entry, func(x *stage2aDomainInventoryV3) { x.Files[0].ComponentID = "adapter" }},
		{"nonexecutable node", node, entry, func(x *stage2aDomainInventoryV3) { x.Files[0].Mode = "0440" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := inv
			changed.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
			if tc.mutate != nil {
				tc.mutate(&changed)
			}
			if stage2aRunnerCodeRowsV3(ref, changed, tc.node, tc.entry) == nil {
				t.Fatal("unsealed or unreviewed runner path accepted")
			}
		})
	}
}

func TestStage2aChildCodeRowsV3RequiresSealedAdapter(t *testing.T) {
	ref := stage2aDomainInventoryRefV3{Snapshot: stage2aDomainNodeRefV3{Path: "/private/r-snapshot"}}
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{
		{Path: "runtime/bin/claude-agent-acp", ComponentID: "adapter", Mode: "0550",
			SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		{Path: "runtime/bin/claude", ComponentID: "adapter", Mode: "0550",
			SHA256: "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
	}}
	executable := filepath.Join(ref.Snapshot.Path, inv.Files[0].Path)
	hash := inv.Files[0].SHA256
	if err := stage2aChildCodeRowsV3(ref, inv, executable, hash); err != nil {
		t.Fatalf("sealed stock child refused: %v", err)
	}
	if stage2aChildCodeRowsV3(ref, inv, "/private/legacy/claude-agent-acp", hash) == nil ||
		stage2aChildCodeRowsV3(ref, inv, executable, "sha256:2222222222222222222222222222222222222222222222222222222222222222") == nil {
		t.Fatal("unsealed or changed stock child accepted")
	}
	inv.Files[0].ComponentID = "souls"
	if stage2aChildCodeRowsV3(ref, inv, executable, hash) == nil {
		t.Fatal("nonadapter component accepted for stock child")
	}
	inv.Files[0].ComponentID = "adapter"
	inv.Files[1].Mode = "0440"
	if stage2aChildCodeRowsV3(ref, inv, executable, hash) == nil {
		t.Fatal("nonexecutable adjacent CLI accepted")
	}
	inv.Files = inv.Files[:1]
	if stage2aChildCodeRowsV3(ref, inv, executable, hash) == nil {
		t.Fatal("missing adjacent CLI accepted")
	}
}
