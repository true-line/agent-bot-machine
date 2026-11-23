package members

import (
	"sort"
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
