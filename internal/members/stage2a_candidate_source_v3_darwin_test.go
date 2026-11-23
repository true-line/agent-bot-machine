//go:build darwin

package members

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aCandidateSavedPlanRequiresAOwnedPrivateStrictInput(t *testing.T) {
	if os.Getuid() < 400 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		t.Skip("requires a non-root Darwin test account")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "saved-plan.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if _, err := readStage2aCandidateSavedPlanV3(path, uid, gid); err != nil {
		t.Fatalf("private regular input refused: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readStage2aCandidateSavedPlanV3(path, uid, gid); err == nil {
		t.Fatal("group/other readable saved plan accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"plan_id":"one","plan_id":"two"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStage2aCandidateSavedPlanV3(path, uid, gid); err == nil {
		t.Fatal("ambiguous saved plan accepted")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readStage2aCandidateSavedPlanV3(link, uid, gid); err == nil {
		t.Fatal("saved plan symlink accepted")
	}
}

func TestStage2aCandidateRuntimePinsHQUIDAndDistinctGID(t *testing.T) {
	ref := stage2aDomainInventoryRefV3{}
	runtime := stage2aInstalledRuntimeV3{
		Policy: stage2aInstalledPolicy{
			MachineUID: 501, MachineGID: 20, HQUID: 309,
			Runner: SoulRunner{GID: 331}, Bridge: SoulBridge{GID: 333},
			Binding: Stage2aMeasurementBinding{
				InstallationID: "inst_0000000000000001", InstalledPlanDigest: "plan-digest", HostID: "host-a",
			},
			RuntimeV3: &ref,
		},
		VerifiedR: stage2aVerifiedDomainRefV3{verified: true},
	}
	install := stage2aQualificationQInstall{
		AdminUID: 501, AdminGID: 20, HQUID: 309, HQGID: 621,
		RunnerGID: 331, BridgeGID: 333,
		Review: stage2aQualificationQReview{
			InstallationID: "inst_0000000000000001", InstalledPlanDigest: "plan-digest", HostID: "host-a",
		},
	}
	if !stage2aCandidateInstallMatchesRuntimeWithHQV3(install, runtime, Account{UID: 309, GID: 621}) {
		t.Fatal("distinct installed HQ UID and GID were refused")
	}
	if stage2aCandidateInstallMatchesRuntimeWithHQV3(install, runtime, Account{UID: 309, GID: 309}) ||
		stage2aCandidateInstallMatchesRuntimeWithHQV3(install, runtime, Account{UID: 621, GID: 621}) {
		t.Fatal("wrong installed HQ kernel identity accepted")
	}
}
