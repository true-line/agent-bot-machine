//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type unreadableHarnessPolicy struct{ *brokerHost }

func (h unreadableHarnessPolicy) Lstat(path string) (Entry, bool, error) {
	if path == HarnessPolicy {
		return Entry{}, false, os.ErrPermission
	}
	return h.brokerHost.Lstat(path)
}

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
	if err := checkDarwinHarnessLaunch(s, HarnessInstall, in.Invoker, r.HQUID, h); err != nil {
		t.Fatal("current plan refused", err)
	}
	if err := checkDarwinHarnessLaunch(s, HarnessRetire, in.Invoker, r.HQUID, h); err == nil {
		t.Fatal("accepted wrong purpose")
	}
	if err := checkDarwinHarnessLaunch(s, HarnessInstall, in.Invoker, r.HQUID+1, h); err == nil {
		t.Fatal("accepted a different paired UID")
	}
	changed := s
	changed.PlanDigest = strings.Repeat("0", 64)
	if err := checkDarwinHarnessLaunch(changed, HarnessInstall, in.Invoker, r.HQUID, h); err == nil {
		t.Fatal("accepted a different saved digest")
	}
	h.entries[HarnessPolicy] = Entry{Regular: true, Owner: "root", Group: "wheel", Mode: 0644}
	if err := checkDarwinHarnessLaunch(s, HarnessInstall, in.Invoker, r.HQUID, h); err == nil {
		t.Fatal("issued consent after the install target became occupied")
	}
	delete(h.entries, HarnessPolicy)
	if err := checkDarwinHarnessLaunch(s, HarnessInstall, in.Invoker, r.HQUID, unreadableHarnessPolicy{h}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unreadable install target: %v", err)
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
