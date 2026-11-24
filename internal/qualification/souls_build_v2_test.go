package qualification

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSoulsBuildStatementPinsTreeAndPackage(t *testing.T) {
	qualification, err := os.ReadFile("testdata/bridge-v2-qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _, claim, err := qualificationObjectV2(qualification)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/bridge-v2-souls-build-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal([]byte(`{"souls_build_workflow":{"receipt_predicate_type":"https://true-line.ai/soul-contracts/adapter/v2/souls-build"}}`), &policy); err != nil {
		t.Fatal(err)
	}
	if err := fixedSoulsBuildStatement(statement, policy, claim, claim.PackageSHA); err != nil {
		t.Fatal("decoded contract build statement refused", err)
	}
	var changed map[string]any
	if err := json.Unmarshal(statement, &changed); err != nil {
		t.Fatal(err)
	}
	changed["predicate"].(map[string]any)["source_tree"] = "3333333333333333333333333333333333333333"
	wrongTree, _ := json.Marshal(changed)
	if fixedSoulsBuildStatement(wrongTree, policy, claim, claim.PackageSHA) == nil {
		t.Fatal("substituted source tree accepted")
	}
	if fixedSoulsBuildStatement(statement, policy, claim, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == nil {
		t.Fatal("substituted package digest accepted")
	}
	changed["predicate"].(map[string]any)["source_tree"] = claim.SourceTree
	changed["predicateType"] = predicateTypeV2
	wrongPurpose, _ := json.Marshal(changed)
	if fixedSoulsBuildStatement(wrongPurpose, policy, claim, claim.PackageSHA) == nil {
		t.Fatal("adapter predicate accepted as Souls build")
	}
}

func TestSoulsV3DerivativeStatementPinsSignedTarAndSource(t *testing.T) {
	qualification, err := os.ReadFile("testdata/bridge-v2-qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _, claim, err := qualificationObjectV2(qualification)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/bridge-v2-souls-build-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(statement, &value); err != nil {
		t.Fatal(err)
	}
	tarSHA := "sha256:" + strings.Repeat("b", 64)
	claim.PackageSHA = tarSHA
	value["subject"].([]any)[0].(map[string]any)["name"] = "sha256-" + tarSHA[7:] + ".tar"
	value["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = tarSHA[7:]
	predicate := value["predicate"].(map[string]any)
	predicate["source_npm_sha256"] = "sha256:" + strings.Repeat("a", 64)
	predicate["derivative_builder_sha256"] = "sha256:" + strings.Repeat("c", 64)
	predicate["selected_manifest_sha256"] = "sha256:" + strings.Repeat("d", 64)
	predicate["excluded_paths"] = []string{"README.md", "lib/helpers/member-peer.py"}
	var policy Policy
	if err := json.Unmarshal([]byte(`{"souls_build_workflow":{"receipt_predicate_type":"https://true-line.ai/soul-contracts/adapter/v2/souls-build","source_npm_sha256":"sha256:`+strings.Repeat("a", 64)+`","derivative_builder_sha256":"sha256:`+strings.Repeat("c", 64)+`","selected_manifest_sha256":"sha256:`+strings.Repeat("d", 64)+`"}}`), &policy); err != nil {
		t.Fatal(err)
	}
	encode := func() []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := encode()
	if err := fixedSoulsDerivativeStatementV3(good, policy, claim, tarSHA); err != nil {
		t.Fatalf("signed R derivative refused: %v", err)
	}
	if fixedSoulsBuildStatement(good, policy, claim, tarSHA) == nil {
		t.Fatal("v2 accepted derivative Statement")
	}
	withoutPin := policy
	withoutPin.SoulsBuildWorkflow = nil
	if fixedSoulsDerivativeStatementV3(good, withoutPin, claim, tarSHA) == nil {
		t.Fatal("unreviewed derivative policy accepted")
	}
	wrongPin := policy
	badWorkflow := *policy.SoulsBuildWorkflow
	badWorkflow.SelectedManifestSHA256 = "sha256:" + strings.Repeat("e", 64)
	wrongPin.SoulsBuildWorkflow = &badWorkflow
	if fixedSoulsDerivativeStatementV3(good, wrongPin, claim, tarSHA) == nil {
		t.Fatal("different owner-pinned selected manifest accepted")
	}
	for name, change := range map[string]func(){
		"wrong subject":    func() { value["subject"].([]any)[0].(map[string]any)["name"] = "souls-runtime.tar" },
		"wrong source npm": func() { predicate["source_npm_sha256"] = tarSHA },
		"missing manifest": func() { delete(predicate, "selected_manifest_sha256") },
		"unsafe exclusion": func() { predicate["excluded_paths"] = []string{"../extra"} },
	} {
		if err := json.Unmarshal(good, &value); err != nil {
			t.Fatal(err)
		}
		predicate = value["predicate"].(map[string]any)
		change()
		if fixedSoulsDerivativeStatementV3(encode(), policy, claim, tarSHA) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
