//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func TestStage2aInstalledPolicyMustMatchReviewedTemplate(t *testing.T) {
	key := ed25519.PublicKey(strings.Repeat("k", ed25519.PublicKeySize))
	p := stage2aInstalledPolicy{
		Schema:       "agent-bot-machine/stage2a-installed-authority/v1",
		ArtifactPath: stage2aArtifactPath("install-one"),
		Binding:      Stage2aMeasurementBinding{InstallationID: "install-one"},
		LegacySpent:  []string{}, Node: "/reviewed/node",
	}
	template, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{SoulProtectedLaunch: &SoulProtectedLaunchInstall{
		Schema: stage2aInstallSchema, MachinePublicKey: hex.EncodeToString(key), Policy: template,
	}}
	p.Binding.PlanID, p.Binding.InstalledPlanDigest = "plan-one", strings.Repeat("a", 64)
	if !stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("exact reviewed template refused")
	}
	p.Node = "/unreviewed/node"
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("A policy replaced reviewed runtime path")
	}
	p.Node = "/reviewed/node"
	p.Binding.Snapshots.Definition.Inode = "123"
	if !stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("installer-generated inode was treated as request mutation")
	}
	plan.SoulProtectedLaunch.MachinePublicKey = hex.EncodeToString(ed25519.PublicKey(strings.Repeat("z", ed25519.PublicKeySize)))
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("wrong Machine key accepted")
	}
}

func TestStage2aProtectedInstallPreparedPolicyRoundTripsThroughBuild(t *testing.T) {
	const installation = "inst_0000000000000001"
	const owner = "owner"
	const machine = "_agent-bot-machine"
	key := ed25519.PublicKey(strings.Repeat("k", ed25519.PublicKeySize))
	runner, bridge := runnerFixture()[0], bridgeFixture()[0]
	runner.Account = soulRunnerName(installation)
	launch, qualification := stage2aChildEnvFixture(t)
	namespace, err := stage2aFrozenNamespace(installation)
	if err != nil {
		t.Fatal(err)
	}
	definitionRoot := namespace + "/" + stage2aInstallSnapshotName(installation, "definition")
	launchRoot := namespace + "/" + stage2aInstallSnapshotName(installation, "inputs")
	for i := range launch.Files {
		switch launch.Files[i].Path {
		case "bin/souls":
			launch.Files[i].Path = "runtime/bin/agent-bot-souls.mjs"
		case "bin/node":
			launch.Files[i].Path = "runtime/bin/node"
		case "policy/harness-egress.sb":
			launch.Files[i].Path = "policy/soul-runner-egress.sb"
			size := uint64(len(soulRunnerProfile))
			launch.Files[i].Size = &size
			launch.Files[i].SHA256 = harnessSHA(soulRunnerProfile)
		}
	}
	sort.Slice(launch.Files, func(i, j int) bool { return launch.Files[i].Path < launch.Files[j].Path })
	launch.SandboxPolicyDigest = "sha256:" + harnessSHA(soulRunnerProfile)
	node, entry := launchRoot+"/runtime/bin/node", launchRoot+"/runtime/bin/agent-bot-souls.mjs"
	launch.SelectedCommand = node
	launch.Argv = stage2aRunnerArgvTemplate(node, entry, definitionRoot, "managed-protected")
	adapter := launch.HostProjection.Adapters["fixture-adapter"].(map[string]any)
	adapter["command"] = []any{launchRoot + "/bin/claude-agent-acp"}
	definition := stage2aSyntheticRecords()
	definitionDigest, _, err := Stage2aDefinitionDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(launch)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(root string, group int) Stage2aSnapshotIdentity {
		return Stage2aSnapshotIdentity{RootPath: root, OwnerUID: 501, OwnerGID: uint32(group), Mode: "0555"}
	}
	policy := stage2aInstalledPolicy{
		Schema: "agent-bot-machine/stage2a-installed-authority/v1", MachineAccount: machine,
		MachineUID: 501, MachineGID: 20, PlanOwner: owner, HQUID: 309,
		ApprovedUntil: "2026-11-23T12:00:00Z", LegacySpent: []string{},
		ArtifactPath: stage2aArtifactPath(installation), Runner: runner, Bridge: bridge,
		Binding: Stage2aMeasurementBinding{
			Contract: "machine/v2", Kind: "stage2a-measurement-binding", SchemaVersion: 2,
			InstallationID: installation, SoulID: runner.SoulID, HostID: "fixture-host",
			HQEpoch: strings.Repeat("a", 64), PackageSHA256: runner.PackageSHA256,
			SoulArtifactSHA256: strings.Repeat("b", 64), ProfileInForce: "managed-protected",
			ClaimedDefinitionDigest: definitionDigest, DefinitionMeasurement: definitionDigest,
			LaunchInputMeasurement: launchDigest,
			Snapshots: Stage2aBindingSnapshots{
				Definition: claim(definitionRoot, runner.GID), LaunchInputs: claim(launchRoot, runner.GID),
			},
		},
		Definition: definition, LaunchInputs: launch, Node: node, Entry: entry,
		BridgeExecutable:    HarnessArtifact{Path: SoulBridgeBinary, SHA256: strings.TrimPrefix(launch.ComponentDigests["bridge"], "sha256:")},
		BridgeQualification: qualification,
	}
	policy.BridgeQualification.RequestSHA256 = definitionDigest
	policy.BridgeQualification.HeadersSHA256 = definitionDigest
	policy.BridgeQualification.ResponseText = "fixture"
	prepared, err := json.Marshal(policy)
	if err != nil || !strings.Contains(string(prepared), `"canonical_plan":null`) ||
		!strings.Contains(string(prepared), `"root_receipt":null`) {
		t.Fatalf("prepared policy lacks explicit empty installer-only fields: %s, %v", prepared, err)
	}
	request := &SoulProtectedLaunchInstall{
		Schema: stage2aInstallSchema, MachinePublicKey: hex.EncodeToString(key),
		ArtifactSource: "/private/tmp/fixture.soul", BridgeBinarySource: "/private/tmp/fixture-bridge",
		DefinitionSource: "/private/tmp/fixture-definition", LaunchInputsSource: "/private/tmp/fixture-inputs",
		Policy: prepared,
	}
	host := &fakeHost{accounts: map[string]Account{
		DarwinHQAccount: {Name: DarwinHQAccount, UID: 309, GID: 309},
		machine:         {Name: machine, UID: 501, GID: 20},
		runner.Account:  {Name: runner.Account, UID: runner.UID, GID: runner.GID},
		bridge.Account:  {Name: bridge.Account, UID: bridge.UID, GID: bridge.GID},
	}}
	plan, err := Build(Input{SoulProtectedLaunch: request, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, host)
	if err != nil {
		t.Fatalf("prepared protected install refused: %v", err)
	}
	if _, err := Build(Input{SoulProtectedLaunch: plan.SoulProtectedLaunch, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, host); err != nil {
		t.Fatalf("saved normalized request refused on rebuild: %v", err)
	}
	var installed stage2aInstalledPolicy
	if err := json.Unmarshal(plan.SoulProtectedLaunch.Policy, &installed); err != nil {
		t.Fatal(err)
	}
	installed.Binding.PlanID = "plan-20261122T120000Z-abcd"
	installed.Binding.InstalledPlanDigest = strings.Repeat("c", 64)
	if !stage2aInstalledPolicyMatchesPlan(installed, plan, key) {
		t.Fatal("installed authority does not match saved owner-reviewed template")
	}
	for name, changed := range map[string]json.RawMessage{
		"caller plan":    json.RawMessage(`{"purpose":"unreviewed"}`),
		"caller receipt": json.RawMessage(`{"result":"applied"}`),
	} {
		t.Run(name, func(t *testing.T) {
			unreviewed := policy
			if name == "caller plan" {
				unreviewed.Plan = changed
			} else {
				unreviewed.Receipt = changed
			}
			request := *request
			request.Policy, err = json.Marshal(unreviewed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Build(Input{SoulProtectedLaunch: &request, HQAccount: DarwinHQAccount,
				Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, host); err == nil {
				t.Fatal("caller supplied installer-only authority")
			}
		})
	}
}
