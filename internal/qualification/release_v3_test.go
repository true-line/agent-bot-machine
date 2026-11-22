package qualification

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMeasuredV3StatementAndQualificationParsing(t *testing.T) {
	now := time.Date(2026, 11, 22, 6, 3, 0, 0, time.UTC)
	policy, _, _ := fixturePolicy(t, now)
	policy.ReleaseWorkflow.SourceCommit = strings.Repeat("c", 40)
	qualification, err := os.ReadFile("testdata/measurement-v3-qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/measurement-v3-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	_, refs, build, recorded, err := qualificationObjectV3(qualification, now)
	if err != nil {
		t.Fatal("v3 qualification shape refused", err)
	}
	statementRefs, statementBuild, expires, err := fixedStatementV3(statement, policy, digest(qualification), recorded, now)
	if err != nil || !reflect.DeepEqual(refs, statementRefs) || build != statementBuild || !expires.After(now) {
		t.Fatal("v3 Statement and qualification mismatch", err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"old purpose", func(v map[string]any) {
			v["predicate"].(map[string]any)["host_reports"].(map[string]any)["cooperative_report"].(map[string]any)["signature_purpose"] = HostPurpose
		}},
		{"missing completed run", func(v map[string]any) {
			delete(v["predicate"].(map[string]any)["host_reports"].(map[string]any)["protected_report"].(map[string]any), "completed_run")
		}},
		{"reused completed run", func(v map[string]any) {
			reports := v["predicate"].(map[string]any)["host_reports"].(map[string]any)
			reports["cooperative_report"].(map[string]any)["completed_run"] = reports["protected_report"].(map[string]any)["completed_run"]
		}},
		{"reused completed run URI", func(v map[string]any) {
			reports := v["predicate"].(map[string]any)["host_reports"].(map[string]any)
			cooperative := reports["cooperative_report"].(map[string]any)["completed_run"].(map[string]any)
			protected := reports["protected_report"].(map[string]any)["completed_run"].(map[string]any)
			cooperative["uri"] = protected["uri"]
		}},
		{"expiry equality", func(v map[string]any) {
			v["predicate"].(map[string]any)["expires_at"] = now.Format(time.RFC3339)
		}},
		{"wrong subject", func(v map[string]any) {
			v["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"] = strings.Repeat("f", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var changed map[string]any
			if json.Unmarshal(statement, &changed) != nil {
				t.Fatal("invalid fixture")
			}
			tc.edit(changed)
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := fixedStatementV3(raw, policy, digest(qualification), recorded, now); err == nil {
				t.Fatal("invalid v3 Statement accepted")
			}
		})
	}
	var changed map[string]any
	if json.Unmarshal(qualification, &changed) != nil {
		t.Fatal("invalid fixture")
	}
	changed["recorded_at"] = now.Add(time.Second).Format(time.RFC3339)
	future, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := qualificationObjectV3(future, now); err == nil {
		t.Fatal("future-dated qualification accepted")
	}
	if json.Unmarshal(qualification, &changed) != nil {
		t.Fatal("invalid fixture")
	}
	delete(changed["conformance"].(map[string]any)["protected_report"].(map[string]any), "completed_run")
	missing, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := qualificationObjectV3(missing, now); err == nil {
		t.Fatal("missing completed-run reference accepted")
	}
}
