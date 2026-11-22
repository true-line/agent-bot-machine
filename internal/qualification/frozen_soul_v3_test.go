package qualification

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFrozenSoulStatementPinsSeparateArtifactAndTemplate(t *testing.T) {
	w := &FrozenSoulBuildWorkflow{
		ID: "fixture-frozen-build", Repository: "true-line/soul-package",
		WorkflowPath: ".github/workflows/stage2a-frozen-soul-receipt.yml",
		SourceCommit: strings.Repeat("6", 40), SourceTree: strings.Repeat("7", 40),
		BuilderSHA256:        "sha256:" + strings.Repeat("9", 64),
		ToolchainSHA256:      "sha256:" + strings.Repeat("a", 64),
		ReceiptPredicateType: "https://true-line.ai/soul-contracts/package/v1/frozen-soul-build",
		ArtifactFormat:       "stage2a-frozen-hello-ustar/v1",
	}
	w.Template.Repository = "true-line/soul-conformance"
	w.Template.SourceCommit = "8e82f47781e583e4b09352cbfef5ca3bfefe45aa"
	w.Template.SourceTree = "5f3ab3acee16de02a38a51204fb9401c3566a6d0"
	w.Template.Path = "templates/hello.soul"
	w.Template.TemplateTree = "e944d40e5f495f6de395619b254ed890e36b53ee"
	m := &FrozenSoulMapping{
		SoulID:                  "agent_00000000-0000-0000-0000-000000000000",
		ArtifactSHA256:          strings.Repeat("c", 64),
		ReceiptSHA256:           "sha256:" + strings.Repeat("f", 64),
		ClaimedDefinitionDigest: "sha256:" + strings.Repeat("d", 64),
		DefinitionMeasurement:   "sha256:" + strings.Repeat("e", 64),
	}
	statement := map[string]any{
		"_type": statementType, "predicateType": w.ReceiptPredicateType,
		"subject": []any{map[string]any{"name": "sha256-" + m.ArtifactSHA256 + ".soul", "digest": map[string]any{"sha256": m.ArtifactSHA256}}},
		"predicate": map[string]any{
			"artifact_format": w.ArtifactFormat,
			"builder": map[string]any{
				"repository": w.Repository, "source_commit": w.SourceCommit,
				"source_tree": w.SourceTree, "workflow": w.WorkflowPath,
				"run_id": "12345", "run_attempt": 1, "builder_sha256": w.BuilderSHA256,
			},
			"toolchain_sha256": w.ToolchainSHA256,
			"template": map[string]any{
				"repository": w.Template.Repository, "source_commit": w.Template.SourceCommit,
				"source_tree": w.Template.SourceTree, "path": w.Template.Path,
				"template_tree": w.Template.TemplateTree,
			},
			"definition_measurement": m.DefinitionMeasurement,
		},
	}
	check := func(value map[string]any, want bool) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		accepted := fixedFrozenSoulStatement(raw, w, m) == nil
		if accepted != want {
			t.Fatalf("statement accepted=%v, want %v", accepted, want)
		}
	}
	check(statement, true)
	clone := func() map[string]any {
		raw, _ := json.Marshal(statement)
		var value map[string]any
		json.Unmarshal(raw, &value)
		return value
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"runtime tgz subject", func(s map[string]any) { s["subject"].([]any)[0].(map[string]any)["name"] = "souls-runtime.tgz" }},
		{"wrong artifact digest", func(s map[string]any) {
			s["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = strings.Repeat("f", 64)
		}},
		{"builder source", func(s map[string]any) {
			s["predicate"].(map[string]any)["builder"].(map[string]any)["source_commit"] = strings.Repeat("f", 40)
		}},
		{"builder run ID overflow", func(s map[string]any) {
			s["predicate"].(map[string]any)["builder"].(map[string]any)["run_id"] = "99999999999999999999"
		}},
		{"template tree", func(s map[string]any) {
			s["predicate"].(map[string]any)["template"].(map[string]any)["template_tree"] = strings.Repeat("f", 40)
		}},
		{"definition measurement", func(s map[string]any) {
			s["predicate"].(map[string]any)["definition_measurement"] = "sha256:" + strings.Repeat("f", 64)
		}},
		{"extra predicate", func(s map[string]any) { s["predicate"].(map[string]any)["approved"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) { value := clone(); tc.change(value); check(value, false) })
	}
}

func TestFrozenSoulReceiptPinsExactBundleBytesBeforeParsing(t *testing.T) {
	now := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	policy := VerifiedPolicy{verified: true, version: 3, at: now}
	policy.value.FrozenSoulBuildWorkflow = &FrozenSoulBuildWorkflow{TrustRootSHA256: digest([]byte("synthetic root"))}
	artifact := []byte("synthetic artifact")
	approved := []byte(`{"fixture":"unsigned-receipt"}`)
	reserialized := []byte(`{ "fixture" : "unsigned-receipt" }`)
	policy.value.FrozenSoulMapping = &FrozenSoulMapping{
		ArtifactSHA256: strings.TrimPrefix(digest(artifact), "sha256:"),
		ReceiptSHA256:  digest(approved),
	}
	if digest(approved) == digest(reserialized) {
		t.Fatal("reserialized bytes unexpectedly have the same digest")
	}
	if _, err := VerifyFrozenSoulReceiptV3(policy, []byte("synthetic root"), reserialized, artifact, now); err == nil {
		t.Fatal("reserialized receipt bypassed owner-signed exact byte identity")
	}
	if _, err := VerifyFrozenSoulReceiptV3(policy, []byte("synthetic root"), approved, artifact, now); err == nil {
		t.Fatal("unsigned receipt unexpectedly verified")
	}
	if _, err := VerifyFrozenSoulReceiptV3(policy, nil, nil, nil, now); err == nil {
		t.Fatal("missing local trust and artifact inputs minted receipt")
	}
}
