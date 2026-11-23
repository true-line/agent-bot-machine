//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/diag"
)

func TestStage2aV2ProtectedApplyAndStartStayClosed(t *testing.T) {
	called := false
	result := runSoulProtectedLaunchApply(Saved{}, Approval{}, "", nil, Deps{},
		func(Approval, func() error) error { called = true; return nil })
	if called || result.Diagnostic == nil || result.Diagnostic.ID != diag.MembersNotApproved ||
		!strings.Contains(result.Diagnostic.Message, "H/R code contract") {
		t.Fatalf("legacy v2 install entered protected apply: %+v, paired=%v", result.Diagnostic, called)
	}
	_, raw, err := loadStage2aInstalledPolicyWithLease(nil, 0, "", "", true)
	if err != errStage2aReservationAuthority || raw != nil {
		t.Fatalf("legacy v2 policy entered a protected start: %v, %q", err, raw)
	}
}

func TestStage2aOwnerReviewedMemberSetSelector(t *testing.T) {
	request := SoulProtectedLaunchInstall{
		Schema:           stage2aRuntimeInstallSchemaV3,
		MachinePublicKey: hex.EncodeToString(bytes.Repeat([]byte{'k'}, ed25519.PublicKeySize)),
		ArtifactSource:   "/reviewed/artifact", BridgeBinarySource: "/reviewed/bridge",
		DefinitionSource: "/reviewed/definition", LaunchInputsSource: "/reviewed/inputs",
		RuntimeV3: &stage2aRuntimeV3Install{}, Policy: json.RawMessage(`{}`),
		OwnerPlanMemberSetSHA256: "sha256:" + strings.Repeat("a", 64),
	}
	decode := func() error {
		raw, err := json.Marshal(request)
		if err != nil {
			return err
		}
		_, err = decodeSoulProtectedLaunch(raw)
		return err
	}
	if err := decode(); err != nil {
		t.Fatalf("reviewed member-set digest refused: %v", err)
	}
	request.OwnerPlanMemberSetSHA256 = strings.Repeat("a", 64)
	if decode() == nil {
		t.Fatal("unprefixed member-set digest accepted")
	}
	request.OwnerPlanMemberSetSHA256 = "sha256:" + strings.Repeat("a", 64)
	request.Schema, request.RuntimeV3 = stage2aInstallSchema, nil
	if decode() == nil {
		t.Fatal("legacy install accepted a two-member owner selector")
	}
}

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
	plan.SoulProtectedLaunch.MachinePublicKey = hex.EncodeToString(key)
	plan.SoulProtectedLaunch.Schema = stage2aRuntimeInstallSchemaV3
	plan.SoulProtectedLaunch.RuntimeV3 = &stage2aRuntimeV3Install{InventoryDigest: "sha256:" + strings.Repeat("1", 64)}
	p.RuntimeV3 = &stage2aDomainInventoryRefV3{Contract: "machine/v3", Domain: "R-runtime"}
	if !stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("installer-derived R reference was treated as an unreviewed template mutation")
	}
	plan.SoulProtectedLaunch.RuntimeV3 = nil
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("v3 install accepted no reviewed R source plan")
	}
	plan.SoulProtectedLaunch.RuntimeV3 = &stage2aRuntimeV3Install{InventoryDigest: "sha256:" + strings.Repeat("1", 64)}
	p.RuntimeV3 = nil
	if stage2aInstalledPolicyMatchesPlan(p, plan, key) {
		t.Fatal("v3 install accepted no derived R reference")
	}
}

func TestStage2aInstalledReceiptReloadMatchesProtectedRootBytes(t *testing.T) {
	root := encodeReceipt(Receipt{
		PlanID: "plan-20261122T120000Z-abcd", PlanDigest: strings.Repeat("c", 64),
		Owner: "owner", HQAccount: DarwinHQAccount, Dir: DarwinDir,
		StartedAt: "2026-11-22T12:00:00Z", FinishedAt: "2026-11-22T12:00:01Z", Result: "applied",
	})
	if !bytes.Contains(root, []byte{'\n'}) {
		t.Fatal("fixture lacks the root receipt's formatted JSON")
	}
	policy := stage2aInstalledPolicy{Receipt: root}
	serialized, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded stage2aInstalledPolicy
	if err := json.Unmarshal(serialized, &reloaded); err != nil ||
		bytes.Equal(reloaded.Receipt, root) || !stage2aInstalledReceiptMatchesRoot(reloaded.Receipt, root) {
		t.Fatalf("root applied receipt could not be reloaded: %v", err)
	}
	changed := bytes.Replace(root, []byte(`"applied"`), []byte(`"failed"`), 1)
	if stage2aInstalledReceiptMatchesRoot(reloaded.Receipt, changed) ||
		stage2aInstalledReceiptMatchesRoot(reloaded.Receipt, []byte(`{"result":"applied","result":"applied"}`)) {
		t.Fatal("different or ambiguous root receipt matched installed copy")
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
	// This under-limit reviewed v2 fixture can be planned, but cannot apply
	// or authorize a protected start until H's code closure is authenticated.
	blocked := runSoulProtectedLaunchApply(Saved{SoulProtectedLaunch: plan.SoulProtectedLaunch,
		Plan: plan}, Approval{}, owner, host, Deps{}, nil)
	if blocked.Diagnostic == nil || blocked.Diagnostic.ID != diag.MembersNotApproved ||
		!strings.Contains(blocked.Diagnostic.Message, "H/R code contract") {
		t.Fatalf("under-limit v2 plan reached protected apply: %+v", blocked.Diagnostic)
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
