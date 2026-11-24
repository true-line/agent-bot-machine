//go:build darwin

package members

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStage2aProtectedV3PackageBindsFrozenDefinition(t *testing.T) {
	definition := stage2aSyntheticRecords()
	digest, _, err := Stage2aDefinitionDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	root := "/private/frozen-definition"
	p := stage2aInstalledPolicy{Definition: definition,
		Runner: SoulRunner{PackageRoot: root, PackageSHA256: strings.TrimPrefix(digest, "sha256:")},
		Binding: Stage2aMeasurementBinding{DefinitionMeasurement: digest,
			PackageSHA256:      strings.TrimPrefix(digest, "sha256:"),
			SoulArtifactSHA256: strings.Repeat("b", 64),
			Snapshots:          Stage2aBindingSnapshots{Definition: Stage2aSnapshotIdentity{RootPath: root}}}}
	if !stage2aProtectedPackageMeasurementV3(p) {
		t.Fatal("reviewed definition package was refused")
	}
	ref := stage2aDomainInventoryRefV3{Contract: "machine/v3", Domain: "R-runtime"}
	if !stage2aRunnerPackageMatchesRuntimeV3(ref, p.Runner, p.Binding, digest) {
		t.Fatal("v3 runner refused matching frozen package")
	}
	legacy := stage2aDomainInventoryRefV3{}
	if !stage2aRunnerPackageMatchesRuntimeV3(legacy, p.Runner,
		Stage2aMeasurementBinding{PackageSHA256: strings.Repeat("d", 64)}, digest) {
		t.Fatal("legacy runner acquired the v3 package interpretation")
	}
	for name, change := range map[string]func(*stage2aInstalledPolicy){
		"invented package":            func(v *stage2aInstalledPolicy) { v.Runner.PackageSHA256 = strings.Repeat("a", 64) },
		"archive digest substitution": func(v *stage2aInstalledPolicy) { v.Binding.PackageSHA256 = v.Binding.SoulArtifactSHA256 },
		"wrong selected root":         func(v *stage2aInstalledPolicy) { v.Runner.PackageRoot = "/private/other" },
		"changed source record": func(v *stage2aInstalledPolicy) {
			v.Definition = append([]Stage2aDefinitionRecord(nil), v.Definition...)
			v.Definition[1].SHA256 = strings.Repeat("c", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if stage2aProtectedPackageMeasurementV3(bad) {
				t.Fatal("unmeasured package accepted")
			}
			if stage2aRunnerPackageMatchesRuntimeV3(ref, bad.Runner, bad.Binding, digest) &&
				name != "changed source record" {
				t.Fatal("v3 runner accepted wrong package or root")
			}
		})
	}
}

func TestStage2aProtectedV3SelectedCommandUsesSealedR(t *testing.T) {
	ref := stage2aDomainInventoryRefV3{Snapshot: stage2aDomainNodeRefV3{Path: "/private/r-snapshot"}}
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{
		{Path: "runtime/bin/node", ComponentID: "node", Mode: "0550"},
		{Path: "runtime/bin/agent-bot-souls.mjs", ComponentID: "souls", Mode: "0440"},
	}}
	node := filepath.Join(ref.Snapshot.Path, inv.Files[0].Path)
	entry := filepath.Join(ref.Snapshot.Path, inv.Files[1].Path)
	p := stage2aInstalledPolicy{RuntimeV3: &ref, Node: node, Entry: entry,
		LaunchInputs: Stage2aLaunchInputRecords{SelectedCommand: node}}
	if !stage2aSelectedCommandRecordedV3(p, inv) {
		t.Fatal("selected Node in sealed R inventory was refused")
	}
	p.LaunchInputs.SelectedCommand = "/private/legacy/bin/node"
	if stage2aSelectedCommandRecordedV3(p, inv) {
		t.Fatal("legacy selected command escaped sealed R inventory")
	}
	p.LaunchInputs.SelectedCommand = node
	inv.Files[0].Mode = "0440"
	if stage2aSelectedCommandRecordedV3(p, inv) {
		t.Fatal("nonexecutable sealed R Node was accepted")
	}
}

func TestStage2aProtectedV3ApplyRejectsPackageBeforeInstall(t *testing.T) {
	p := stage2aInstalledPolicy{Binding: Stage2aMeasurementBinding{
		PackageSHA256: strings.Repeat("a", 64),
	}}
	request := &SoulProtectedLaunchInstall{RuntimeV3: &stage2aRuntimeV3Install{}}
	if err := stage2aInstallFiles(Saved{}, request, &p, 0, nil, nil, nil, nil); err != errStage2aReservationAuthority {
		t.Fatalf("unmeasured package reached protected install: %v", err)
	}
}

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
