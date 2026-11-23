package members

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRetainedQualificationQPlanRequiresExactOwnerReview(t *testing.T) {
	request := validQualificationRequest()
	request.SchemaVersion = 2
	request.Candidate = &qualificationCandidatePlan{
		HostUUID: "A0000000-0000-0000-0000-000000000001", InstallationID: "inst_0000000000000001",
		InstalledPlanDigest: strings.Repeat("a", 64), RuntimeInventorySHA: strings.Repeat("b", 64),
		ComponentID: "codex", Manifest: qualificationFile{"/private/tmp/manifest", strings.Repeat("c", 64)},
		TestPlan: qualificationFile{"/private/tmp/test-plan", strings.Repeat("d", 64)},
	}
	run := &QualificationRun{RequestSHA256: strings.Repeat("e", 64), Request: request,
		MemberState: "disposable", OneUse: true, Gates: fixedQualificationGates()}
	savePlan := func(t *testing.T, run *QualificationRun) ([]byte, Saved) {
		t.Helper()
		plan, err := qualificationPlan(run)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := plan.Digest()
		if err != nil {
			t.Fatal(err)
		}
		saved := Saved{Plan: plan, QualificationRun: run, PlanID: "plan-20261122T141516Z-abcd", PlanDigest: digest}
		raw, err := json.MarshalIndent(saved, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return raw, saved
	}
	raw, saved := savePlan(t, run)
	install := stage2aQualificationQInstall{
		Source: qualificationFile{stage2aQualificationQHome + "/qualification-runner.mjs", request.Runner.BinarySHA},
		Review: stage2aQualificationQReview{
			Owner: "local-owner", PlanID: saved.PlanID, PlanDigest: saved.PlanDigest,
			HostUUID: request.Candidate.HostUUID, HostID: request.Host.ID,
			InstallationID: request.Candidate.InstallationID, InstalledPlanDigest: request.Candidate.InstalledPlanDigest,
			TestPlan: request.Candidate.TestPlan, Provider: qualificationFile{request.TestProvider.ConfigPath, request.TestProvider.ConfigSHA},
		},
	}
	got, err := decodeStage2aQualificationQPlan(raw, install)
	if err != nil || got.Adapter.Harness != request.Adapter.Harness || got.TestProvider != request.TestProvider {
		t.Fatalf("exact retained qualification pins did not resolve: %v", err)
	}

	replacement := *run
	replacement.Request.Adapter.Harness.BinarySHA = strings.Repeat("8", 64)
	_, forged := savePlan(t, &replacement)
	forged.PlanDigest = saved.PlanDigest
	forgedRaw, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStage2aQualificationQPlan(forgedRaw, install); err == nil {
		t.Fatal("replacement harness accepted under original plan digest")
	}
	invalidRun := *run
	invalidRun.Request.Adapter.Launch.Argv = nil
	invalidRaw, invalidSaved := savePlan(t, &invalidRun)
	invalidInstall := install
	invalidInstall.Review.PlanDigest = invalidSaved.PlanDigest
	if _, err := decodeStage2aQualificationQPlan(invalidRaw, invalidInstall); err == nil {
		t.Fatal("invalid request accepted under matching owner review digest")
	}
	for name, change := range map[string]func(*stage2aQualificationQInstall){
		"host":                   func(i *stage2aQualificationQInstall) { i.Review.HostID = "other-host" },
		"installed plan":         func(i *stage2aQualificationQInstall) { i.Review.InstalledPlanDigest = strings.Repeat("9", 64) },
		"test plan":              func(i *stage2aQualificationQInstall) { i.Review.TestPlan.Path += "-replacement" },
		"provider configuration": func(i *stage2aQualificationQInstall) { i.Review.Provider.SHA256 = strings.Repeat("9", 64) },
		"observer source":        func(i *stage2aQualificationQInstall) { i.Source.SHA256 = strings.Repeat("9", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := install
			change(&changed)
			if _, err := decodeStage2aQualificationQPlan(raw, changed); err == nil {
				t.Fatal("substituted pin accepted")
			}
		})
	}
}
