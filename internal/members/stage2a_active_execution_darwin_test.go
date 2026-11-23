package members

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestStage2aActiveRuntimeV3RequiresSealedRows(t *testing.T) {
	launch, qualification := stage2aChildEnvFixture(t)
	legacyChild := launch.HostProjection.Adapters["fixture-adapter"].(map[string]any)["command"]
	const root = "/private/var/db/managed-machine/soul-snapshots/r_example/snap_test"
	ref := stage2aDomainInventoryRefV3{Domain: "R-runtime", InstallationID: "inst_0000000000000001",
		Snapshot: stage2aDomainNodeRefV3{Path: root}}
	const node = "runtime/bin/node"
	const entry = "runtime/bin/agent-bot-souls.mjs"
	const adapter = "runtime/bin/claude-agent-acp"
	const cli = "runtime/bin/claude"
	cliSize := uint64(42)
	cliHash := strings.Repeat("e", 64)
	launch.Files = append(launch.Files, Stage2aDefinitionRecord{
		Path: cli, Kind: "regular", Mode: "0550", Size: &cliSize, SHA256: cliHash,
	})
	sort.Slice(launch.Files, func(i, j int) bool { return launch.Files[i].Path < launch.Files[j].Path })
	row := stage2aDomainInventoryV3{Domain: ref.Domain, InstallationID: ref.InstallationID,
		Files: []stage2aDomainFileV3{
			{Path: node, Mode: "0550", ComponentID: "node"},
			{Path: entry, Mode: "0440", ComponentID: "souls"},
			{Path: adapter, Mode: "0550", ComponentID: "adapter", SHA256: launch.ComponentDigests["adapter"]},
			{Path: cli, Kind: "regular", Mode: "0550", ComponentID: "adapter", SizeBytes: cliSize, SHA256: "sha256:" + cliHash},
		}}
	policy := stage2aInstalledPolicy{LaunchInputs: launch, BridgeQualification: qualification,
		Node: filepath.Join(root, node), Entry: filepath.Join(root, entry)}
	command := launch.HostProjection.Adapters["fixture-adapter"].(map[string]any)
	command["command"] = []any{filepath.Join(root, adapter)}
	if err := stage2aValidateRuntimeExecutionRowsV3(policy, ref, row); err != nil {
		t.Fatal(err)
	}
	command["command"] = legacyChild
	if err := stage2aValidateRuntimeExecutionRowsV3(policy, ref, row); err == nil {
		t.Fatal("legacy child path authorized v3")
	}
	command["command"] = []any{filepath.Join(root, adapter)}
	policy.Node = "/private/stage2a/snapshot-launch/bin/node"
	if err := stage2aValidateRuntimeExecutionRowsV3(policy, ref, row); err == nil {
		t.Fatal("legacy Node path authorized v3")
	}
	if _, _, err := loadStage2aActiveExecutionPolicy(nil, 0, "", &stage2aLiveReservation{runtimeRefV3: ref}); err == nil {
		t.Fatal("unsigned legacy mode selected a v3 runtime")
	}
}
