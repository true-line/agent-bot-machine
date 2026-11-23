package members

import (
	"sort"
	"strings"
	"testing"
)

func stage2aChildEnvFixture(t *testing.T) (Stage2aLaunchInputRecords, Stage2aBridgeQualification) {
	t.Helper()
	input := stage2aLaunchFixture(t)
	root := "/private/stage2a/snapshot-launch"
	input.Files[0].Path = "bin/claude-agent-acp"
	childSize := uint64(len(soulChildProfile))
	input.Files = append(input.Files, Stage2aDefinitionRecord{
		Path: "policy/soul-child-egress.sb", Kind: "regular", Mode: "0444",
		Size: &childSize, SHA256: harnessSHA(soulChildProfile),
	})
	sort.Slice(input.Files, func(i, j int) bool { return input.Files[i].Path < input.Files[j].Path })
	input.SystemImages.Selected = append(input.SystemImages.Selected, Stage2aSystemImage{
		Path: "/usr/bin/sandbox-exec", SigningRequirement: "anchor apple",
		CDHash: "3333333333333333333333333333333333333333",
	})
	sort.Slice(input.SystemImages.Selected, func(i, j int) bool {
		return input.SystemImages.Selected[i].Path < input.SystemImages.Selected[j].Path
	})
	input.HostProjection.Adapters = map[string]any{
		"fixture-adapter": map[string]any{
			"command": []any{root + "/bin/claude-agent-acp"}, "env": map[string]any{},
		},
	}
	q := Stage2aBridgeQualification{
		Model: "pilot-model", HTTPHost: "fixture.invalid",
		ClientKeySHA256: stage2aFixtureClientKeySHA256,
		MessagesQuery:   "beta=true",
	}
	input.EffectiveConfig["adapter_child_env"] = map[string]any{
		"schema": stage2aAdapterChildEnvSchema, "provider": "anthropic-messages",
		"base_url": "http://fixture.invalid", "http_host": q.HTTPHost,
		"client_key_sha256": q.ClientKeySHA256, "model": q.Model,
		"messages_query": q.MessagesQuery, "disable_nonessential_traffic": true,
	}
	input.EffectiveConfig["adapter_child_sandbox"] = map[string]any{
		"path": SoulChildSandbox, "sha256": "sha256:" + harnessSHA(soulChildProfile),
	}
	return input, q
}

func TestStage2aProtectedAdapterChildEnvMatchesOwnerQualification(t *testing.T) {
	input, q := stage2aChildEnvFixture(t)
	const root = "/private/stage2a/snapshot-launch"
	if err := stage2aAdapterChildEnv(input, &q, root); err != nil {
		t.Fatal(err)
	}
	baseline, _, err := Stage2aLaunchInputDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Stage2aLaunchInputRecords, *Stage2aBridgeQualification){
		"different model": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["model"] = "other-model"
		},
		"different host": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["http_host"] = "other.invalid"
		},
		"different query": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["messages_query"] = "beta=false"
		},
		"different client key": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["client_key_sha256"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"different static base": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["base_url"] = "http://other.invalid"
		},
		"supplied relay": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["ANTHROPIC_UNIX_SOCKET"] = "/tmp/sibling.sock"
		},
		"supplied temp": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["TMPDIR"] = "/tmp"
		},
		"extra effective config": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["arbitrary"] = true
		},
		"child sandbox path": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_sandbox"].(map[string]any)["path"] = "/tmp/child.sb"
		},
		"child sandbox digest": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_sandbox"].(map[string]any)["sha256"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"child sandbox inventory": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			for i := range v.Files {
				if v.Files[i].Path == "policy/soul-child-egress.sb" {
					v.Files[i].SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				}
			}
		},
		"different B qualification": func(_ *Stage2aLaunchInputRecords, q *Stage2aBridgeQualification) {
			q.ClientKeySHA256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"disabled traffic false": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.EffectiveConfig["adapter_child_env"].(map[string]any)["disable_nonessential_traffic"] = false
		},
		"extra child argv": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.HostProjection.Adapters["fixture-adapter"].(map[string]any)["command"] = []any{root + "/bin/claude-agent-acp", "--unreviewed"}
		},
		"child outside snapshot": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.HostProjection.Adapters["fixture-adapter"].(map[string]any)["command"] = []any{"/tmp/claude-agent-acp"}
		},
		"adapter route env": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			v.HostProjection.Adapters["fixture-adapter"].(map[string]any)["env"] = map[string]any{"ANTHROPIC_UNIX_SOCKET": "/tmp/sibling.sock"}
		},
		"unmeasured child executable": func(v *Stage2aLaunchInputRecords, _ *Stage2aBridgeQualification) {
			for i := range v.Files {
				if v.Files[i].Path == "bin/claude-agent-acp" {
					v.Files[i].Path = "bin/other"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneStage2aLaunch(t, input)
			changedQ := q
			edit(&changed, &changedQ)
			if err := stage2aAdapterChildEnv(changed, &changedQ, root); err == nil {
				t.Fatal("changed child environment accepted")
			}
			if name != "different B qualification" {
				got, _, err := Stage2aLaunchInputDigest(changed)
				if err == nil && got == baseline {
					t.Fatal("changed child environment did not change measured launch inputs")
				}
			}
		})
	}
}

func TestStage2aV3AdapterChildEnvRequiresSealedRRow(t *testing.T) {
	input, q := stage2aChildEnvFixture(t)
	ref := stage2aDomainInventoryRefV3{Domain: "R-runtime", InstallationID: "install-one",
		Snapshot: stage2aDomainNodeRefV3{Path: "/private/sealed-r"}}
	executable := ref.Snapshot.Path + "/runtime/bin/claude-agent-acp"
	input.HostProjection.Adapters["fixture-adapter"].(map[string]any)["command"] = []any{executable}
	cliSize := uint64(42)
	cliHash := strings.Repeat("e", 64)
	input.Files = append(input.Files, Stage2aDefinitionRecord{
		Path: "runtime/bin/claude", Kind: "regular", Mode: "0550",
		Size: &cliSize, SHA256: cliHash,
	})
	sort.Slice(input.Files, func(i, j int) bool { return input.Files[i].Path < input.Files[j].Path })
	inv := stage2aDomainInventoryV3{Domain: "R-runtime", InstallationID: ref.InstallationID,
		Files: []stage2aDomainFileV3{
			{Path: "runtime/bin/claude-agent-acp", ComponentID: "adapter",
				Mode: "0550", SHA256: input.ComponentDigests["adapter"]},
			{Path: "runtime/bin/claude", ComponentID: "adapter", Kind: "regular",
				Mode: "0550", SizeBytes: cliSize, SHA256: "sha256:" + cliHash},
		}}
	if err := stage2aAdapterChildEnvV3(input, &q, ref, inv); err != nil {
		t.Fatalf("sealed R adapter refused: %v", err)
	}

	qualified := cloneStage2aLaunch(t, input)
	qualifiedInventory := inv
	qualifiedInventory.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	for i := range qualified.Files {
		if qualified.Files[i].Path == stage2aStockCLIPath {
			n := stage2aStockCLISizeBytes
			qualified.Files[i].Size = &n
			qualified.Files[i].SHA256 = stage2aStockCLISHA256
		}
	}
	qualifiedInventory.Files[1].SizeBytes = stage2aStockCLISizeBytes
	qualifiedInventory.Files[1].SHA256 = "sha256:" + stage2aStockCLISHA256
	if _, _, err := Stage2aLaunchInputDigest(qualified); err != nil {
		t.Fatalf("exact stock CLI external row refused: %v", err)
	}
	if err := stage2aAdapterChildEnvV3(qualified, &q, ref, qualifiedInventory); err != nil {
		t.Fatalf("exact stock CLI sealed R join refused: %v", err)
	}

	cooperative := cloneStage2aLaunch(t, input)
	cooperative.EffectiveConfig["profile"] = "managed-cooperative"
	if err := stage2aAdapterChildEnvV3(cooperative, &q, ref, inv); err != nil {
		t.Fatalf("separately sealed cooperative R adapter refused: %v", err)
	}
	if stage2aAdapterChildEnv(cooperative, &q, ref.Snapshot.Path) == nil {
		t.Fatal("legacy protected child path accepted cooperative profile")
	}
	withoutCLI := cloneStage2aLaunch(t, input)
	for i := range withoutCLI.Files {
		if withoutCLI.Files[i].Path == "runtime/bin/claude" {
			withoutCLI.Files = append(withoutCLI.Files[:i], withoutCLI.Files[i+1:]...)
			break
		}
	}
	if stage2aAdapterChildEnvV3(withoutCLI, &q, ref, inv) == nil {
		t.Fatal("omitted selected stock CLI accepted")
	}
	badInventory := inv
	badInventory.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	badInventory.Files[1].SHA256 = "sha256:" + strings.Repeat("f", 64)
	if stage2aAdapterChildEnvV3(input, &q, ref, badInventory) == nil {
		t.Fatal("changed sealed stock CLI accepted")
	}
	tooLarge := cloneStage2aLaunch(t, input)
	for i := range tooLarge.Files {
		if tooLarge.Files[i].Path == "runtime/bin/claude" {
			*tooLarge.Files[i].Size = 354630016
		}
	}
	if _, _, err := Stage2aLaunchInputDigest(tooLarge); err == nil {
		t.Fatal("stock CLI over current 256 MiB external limit accepted")
	}
	tooLargeInventory := inv
	tooLargeInventory.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	tooLargeInventory.Files[1].SizeBytes = 354630016
	if stage2aAdapterChildEnvV3(tooLarge, &q, ref, tooLargeInventory) == nil {
		t.Fatal("stock CLI over current 256 MiB external limit authorized")
	}
	if stage2aAdapterChildEnv(input, &q, "/private/stage2a/snapshot-launch") == nil {
		t.Fatal("legacy launch snapshot accepted the R-only child path")
	}
	inv.Files[0].ComponentID = "souls"
	if stage2aAdapterChildEnvV3(input, &q, ref, inv) == nil {
		t.Fatal("nonadapter sealed R row accepted")
	}
}
