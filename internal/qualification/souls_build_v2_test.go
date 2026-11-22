package qualification

import (
	"encoding/json"
	"os"
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
