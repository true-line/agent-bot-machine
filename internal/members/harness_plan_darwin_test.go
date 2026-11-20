//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinHarnessPlanCommandBindsInstalledRolesAndCurrentBuild(t *testing.T) {
	h, in := brokerFixture()
	roles, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	// This is the in-memory host returned by deps. Neither account nor broker
	// directory is created on the running machine.
	if err := Apply(roles, h, newRoot(h.fakeHost)); err != nil {
		t.Fatal(err)
	}
	d, state := deps(t, h)
	const systemFixture = "/usr/bin/true"
	fileHash := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(b))
	}
	digest := fileHash(systemFixture)
	list := filepath.Join(t.TempDir(), "adapters.json")
	request := func(account, sum string) {
		raw, err := json.Marshal(map[string]any{"adapters": []map[string]any{
			{"adapter_id": "fixture", "account": account, "executable": systemFixture, "sha256": sum, "args": []string{}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(list, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	request("_lead", digest)
	args := []string{"plan", "--harness-launch-install", list}
	result := Command(d).Run(on("darwin/arm64"), args)
	if result.Diagnostic != nil {
		t.Fatalf("planning failed: %+v", result.Diagnostic)
	}
	if len(result.Records) != 3 {
		t.Fatalf("expected summary, policy and sudoers, got %d", len(result.Records))
	}
	applied, _ := result.Records[0].Get("applied")
	advice, _ := result.Records[0].Get("advice")
	if applied != false || !strings.Contains(fmt.Sprint(advice), "Regenerate") {
		t.Fatalf("unexpected review-only output: %v %v", applied, advice)
	}
	gotID, _ := result.Records[0].Get("plan_id")
	savedFile := filepath.Join(state, "members", "plans", gotID.(string)+".json")
	raw, err := os.ReadFile(savedFile)
	if err != nil {
		t.Fatal(err)
	}
	var s Saved
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	r := s.HarnessLaunch
	if r == nil || r.Launcher != (HarnessArtifact{HarnessLauncher, fileHash(executable)}) || r.Sandbox != (HarnessArtifact{HarnessSandbox, fileHash("darwin/harness-egress.sb")}) || r.HQUID != h.accounts[DarwinHQAccount].UID || len(r.Adapters) != 1 || r.Adapters[0].UID != h.accounts["_lead"].UID || r.Adapters[0].SHA256 != digest {
		t.Fatal("saved mapping did not bind current build, policy and real resolver results")
	}
	canonical, err := s.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != s.PlanDigest {
		t.Fatal("paired read cannot reproduce plan digest", err)
	}
	mixed := s
	mixed.UpgradeFrom = &priorServicePlan{}
	if _, err := mixed.CanonicalForReview(); err == nil {
		t.Fatal("reviewed a harness request with a service upgrade predecessor")
	}
	mixedInput := in
	mixedInput.HarnessLaunch, mixedInput.UpgradeFrom = s.HarnessLaunch, mixed.UpgradeFrom
	if _, err := Build(mixedInput, h); err == nil {
		t.Fatal("built a mixed harness and upgrade plan")
	}
	prior := installedHarness{s.PlanID, s.PlanDigest, *r}
	retire, err := retirementRequest(prior, s.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	removal, err := retire.plan()
	if err != nil {
		t.Fatal(err)
	}
	if removal.Steps[0].Action != ActionRemove || removal.Steps[1].Action != ActionRemove || removal.Steps[1].Content != s.Plan.Steps[1].Content || retire.InstalledDigest != s.PlanDigest {
		t.Fatal("retirement lost its originating receipt or exact rule")
	}
	if _, err := retirementRequest(prior, "plan-20261110T040000Z-bbbb"); err == nil {
		t.Fatal("accepted a different install receipt")
	}
	for _, tc := range []struct {
		label, account, hash string
		argv                 []string
	}{
		{"changed executable", "_lead", strings.Repeat("0", 64), args}, {"absent role", "_absent", digest, args},
		{"duplicate action", "_lead", digest, append(append([]string{}, args...), "--harness-launch-install", list)},
		{"mixed running service upgrade", "_lead", digest, append(append([]string{}, args...), "--upgrade-from", "plan-20261110T040000Z-bbbb")},
		{"empty running service upgrade", "_lead", digest, append(append([]string{}, args...), "--upgrade-from", "")},
		{"mixed ordinary members", "_lead", digest, append(append([]string{}, args...), "--members", "_lead")},
		{"empty action", "_lead", digest, []string{"plan", "--harness-launch-install", ""}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			request(tc.account, tc.hash)
			if r := Command(d).Run(on("darwin/arm64"), tc.argv); r.Diagnostic == nil {
				t.Fatal("request unexpectedly succeeded")
			}
			unchanged, err := os.ReadFile(savedFile)
			if err != nil || string(unchanged) != string(raw) {
				t.Fatal("failed request replaced prior saved plan")
			}
		})
	}
}
