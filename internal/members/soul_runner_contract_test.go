package members

import (
	"io"
	"strings"
	"testing"
)

func runnerFixture() []SoulRunner {
	return []SoulRunner{
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_0000000000000001", Account: "_abm-soul-a", UID: 331, GID: 331, PackageRoot: "/Library/Application Support/agent-bot/souls/a", PackageSHA256: strings.Repeat("a", 64)},
		{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", InstallationID: "inst_0000000000000002", Account: "_abm-soul-b", UID: 332, GID: 332, PackageRoot: "/Library/Application Support/agent-bot/souls/b", PackageSHA256: strings.Repeat("b", 64)},
	}
}

func TestSoulRunnerMappingRequiresOnePrincipalPerInstallation(t *testing.T) {
	base := runnerFixture()
	if err := ValidateSoulRunners(base, 309, []HarnessAdapter{{Account: "_abm-ci-a", UID: 330}}); err != nil {
		t.Fatalf("distinct runner principals: %v", err)
	}
	for name, edit := range map[string]func([]SoulRunner){
		"shared uid":     func(r []SoulRunner) { r[1].UID, r[1].GID = r[0].UID, r[0].GID },
		"shared account": func(r []SoulRunner) { r[1].Account = r[0].Account },
		"shared install": func(r []SoulRunner) { r[1].InstallationID = r[0].InstallationID },
		"harness role":   func(r []SoulRunner) { r[1].Account = "_abm-ci-a" },
		"harness uid":    func(r []SoulRunner) { r[1].UID, r[1].GID = 330, 330 },
		"hq uid":         func(r []SoulRunner) { r[1].UID, r[1].GID = 309, 309 },
		"parent path":    func(r []SoulRunner) { r[1].PackageRoot = "/Library/x/../agent-bot" },
		"digest":         func(r []SoulRunner) { r[1].PackageSHA256 = "unreviewed" },
	} {
		t.Run(name, func(t *testing.T) {
			r := append([]SoulRunner(nil), base...)
			edit(r)
			if ValidateSoulRunners(r, 309, []HarnessAdapter{{Account: "_abm-ci-a", UID: 330}}) == nil {
				t.Fatal("accepted an unisolated or unreviewed mapping")
			}
		})
	}
}

func TestSoulStartSelectsOnlyReviewedInstallationAndKernelUID(t *testing.T) {
	runners := runnerFixture()
	r := SoulRunRequest{PlanDigest: strings.Repeat("c", 64), InstallationID: runners[1].InstallationID, StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("d", 64)}
	got, err := SelectSoulRunner(runners, r.PlanDigest, r, 332)
	if err != nil || got.Account != "_abm-soul-b" {
		t.Fatalf("select reviewed runner = %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*SoulRunRequest){
		"unknown install": func(r *SoulRunRequest) { r.InstallationID = "inst_0000000000000003" },
		"bad start id":    func(r *SoulRunRequest) { r.StartID = "st_0" },
		"bad epoch":       func(r *SoulRunRequest) { r.HQEpoch = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if _, err := SelectSoulRunner(runners, r.PlanDigest, changed, 332); err == nil {
				t.Fatal("unreviewed start accepted")
			}
		})
	}
	if _, err := SelectSoulRunner(runners, r.PlanDigest, r, 331); err == nil {
		t.Fatal("cross-installation UID accepted")
	}
	if _, err := SelectSoulRunner(runners, strings.Repeat("e", 64), r, 332); err == nil {
		t.Fatal("changed installed policy accepted")
	}
}

func TestSoulRunRequestRejectsExtraAuthorityAndPreservesACP(t *testing.T) {
	header := `{"plan_digest":"` + strings.Repeat("c", 64) + `","installation_id":"inst_0000000000000002","start_id":"st_0123456789abcdef01234567","hq_epoch":"` + strings.Repeat("d", 64) + `"}`
	request, reader, err := ReadSoulRunRequest(strings.NewReader(header + "\nACP-start\n"))
	if err != nil || request.InstallationID != "inst_0000000000000002" {
		t.Fatalf("valid private header: %+v, %v", request, err)
	}
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != "ACP-start\n" {
		t.Fatalf("buffered ACP changed: %q, %v", remaining, err)
	}
	for name, header := range map[string]string{
		"unknown path":  strings.Replace(header, `}`, `,"package_path":"/tmp/other"}`, 1),
		"duplicate id":  strings.Replace(header, `}`, `,"installation_id":"inst_0000000000000001"}`, 1),
		"missing epoch": strings.Replace(header, `,"hq_epoch":"`+strings.Repeat("d", 64)+`"`, "", 1),
		"trailing json": header + ` {}`,
		"oversized":     header + strings.Repeat(" ", 2048),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ReadSoulRunRequest(strings.NewReader(header + "\n")); err == nil {
				t.Fatal("unreviewed launch input accepted")
			}
		})
	}
}
