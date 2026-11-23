package members

import (
	"strings"
	"testing"
)

func TestDirectCooperativeQualificationJoinsIndependentQPlan(t *testing.T) {
	q := validQualificationRequest()
	q.Candidate = &qualificationCandidatePlan{
		RuntimeInventorySHA: strings.Repeat("8", 64),
		ComponentID:         "codex", Manifest: qualificationFile{"/private/tmp/manifest", strings.Repeat("c", 64)},
	}
	provider := Stage2aBridgeQualification{
		Model: "codex", RequestSHA256: "sha256:" + strings.Repeat("9", 64), ResponseText: "fixture",
	}
	_, configSHA, err := stage2aProviderConfig(provider)
	if err != nil {
		t.Fatal(err)
	}
	const owner = "local-owner"
	planDigest := strings.Repeat("a", 64)
	inventoryDigest := "sha256:" + q.Candidate.RuntimeInventorySHA
	harnessDigest := "sha256:" + q.Adapter.Harness.BinarySHA
	install := stage2aQualificationQInstall{
		AdminUID: 501, AdminGID: 20, HQUID: 309, RunnerGID: q.Target.UID,
		Review: stage2aQualificationQReview{
			Owner: owner, HostID: q.Host.ID, InstallationID: "inst_0000000000000001", InstalledPlanDigest: planDigest,
			Provider: qualificationFile{q.TestProvider.ConfigPath, configSHA},
		},
	}
	p := SoulCooperativeLaunchPolicy{
		HostID: q.Host.ID, HQUID: install.HQUID, MachineUID: install.AdminUID, MachineGID: install.AdminGID,
		Runner: SoulRunner{InstallationID: install.Review.InstallationID, Account: q.Target.Account, UID: q.Target.UID, GID: install.RunnerGID},
		AdapterRelease: &soulCooperativeAdapterV3{
			ComponentID: q.Candidate.ComponentID, ReleaseManifestSHA256: "sha256:" + q.Candidate.Manifest.SHA256,
			PackageSHA256: "sha256:" + q.Adapter.PackageSHA, ExecutablePath: q.Adapter.Launch.Executable,
			ExecutableSHA256: "sha256:" + q.Adapter.Launch.ExecutableSHA,
		},
		LaunchInputs: &Stage2aLaunchInputRecords{
			ComponentDigests: map[string]string{"harness": harnessDigest},
			EffectiveConfig:  map[string]any{"qualification_provider_config_sha256": "sha256:" + configSHA},
		},
		QualificationProvider: &provider,
	}
	got, err := cooperativeQualificationHarnessV3(install, q, p, owner, planDigest, inventoryDigest)
	if err != nil || got != harnessDigest {
		t.Fatalf("exact independent Q authority rejected: %s %v", got, err)
	}
	for _, c := range []struct {
		name  string
		check func() (string, error)
	}{
		{"other owner", func() (string, error) {
			return cooperativeQualificationHarnessV3(install, q, p, "other-owner", planDigest, inventoryDigest)
		}},
		{"other R seal", func() (string, error) {
			return cooperativeQualificationHarnessV3(install, q, p, owner, planDigest, "sha256:"+strings.Repeat("f", 64))
		}},
		{"different harness", func() (string, error) {
			replaced := q
			replaced.Adapter.Harness.BinarySHA = strings.Repeat("1", 64)
			return cooperativeQualificationHarnessV3(install, replaced, p, owner, planDigest, inventoryDigest)
		}},
		{"different provider configuration", func() (string, error) {
			replaced := install
			replaced.Review.Provider.SHA256 = strings.Repeat("1", 64)
			return cooperativeQualificationHarnessV3(replaced, q, p, owner, planDigest, inventoryDigest)
		}},
		{"other R", func() (string, error) {
			replaced := p
			replaced.Runner.UID++
			return cooperativeQualificationHarnessV3(install, q, replaced, owner, planDigest, inventoryDigest)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, err := c.check(); err == nil || got != "" {
				t.Fatal("substituted cooperative authority accepted")
			}
		})
	}
}

func TestDirectCooperativeProviderUsesMeasuredMachineCode(t *testing.T) {
	measured := "sha256:" + strings.Repeat("1", 64)
	other := "sha256:" + strings.Repeat("2", 64)
	for _, c := range []struct {
		name    string
		digests map[string]string
		want    bool
	}{
		{"ordinary", map[string]string{"machine": measured}, true},
		{"inline provider", map[string]string{"machine": measured, "test_provider": measured}, true},
		{"different provider", map[string]string{"machine": measured, "test_provider": other}, false},
		{"different Machine", map[string]string{"machine": other, "test_provider": measured}, false},
		{"shared unmeasured digest", map[string]string{"machine": other, "test_provider": other}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := cooperativeV3MachineComponentDigestsMatch(c.digests, measured); got != c.want {
				t.Fatalf("code digest match = %v, want %v", got, c.want)
			}
		})
	}
}
