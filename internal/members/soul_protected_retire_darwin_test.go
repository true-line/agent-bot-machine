//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestStage2aRetirementReviewsExactInstalledPlan(t *testing.T) {
	installation := "soul-one"
	runner, bridge := soulRunnerName(installation), SoulBridgeName(installation)
	policy := stage2aInstalledPolicy{PlanOwner: "reviewer", MachineAccount: "machine-admin",
		MachineUID: 501, MachineGID: 501, HQUID: 309,
		Runner:  SoulRunner{Account: runner, UID: 310, GID: 310},
		Bridge:  SoulBridge{Account: bridge, UID: 311, GID: 311},
		Binding: Stage2aMeasurementBinding{InstallationID: installation}}
	policyRaw, _ := json.Marshal(policy)
	original := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir,
		Purpose:             SoulProtectedLaunchInstallPurpose,
		SoulProtectedLaunch: &SoulProtectedLaunchInstall{Policy: policyRaw}}
	canonical, err := original.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	request := &SoulProtectedLaunchRetire{Schema: stage2aRetireSchema,
		InstalledPlanID:     "plan-20261122T120000Z-abcd",
		InstalledPlanDigest: fmt.Sprintf("%x", sha256.Sum256(canonical)), InstalledPlan: canonical}
	host := &fakeHost{accounts: map[string]Account{
		DarwinHQAccount: {Name: DarwinHQAccount, UID: 309, GID: 309},
		"machine-admin": {Name: "machine-admin", UID: 501, GID: 501},
		runner:          {Name: runner, UID: 310, GID: 310}, bridge: {Name: bridge, UID: 311, GID: 311},
	}}
	in := Input{SoulProtectedRetire: request, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: "reviewer"}
	plan, err := Build(in, host)
	if err != nil || plan.Purpose != SoulProtectedLaunchRetirePurpose || plan.Steps[0].Target != installation {
		t.Fatalf("retirement plan refused exact installation: %+v %v", plan, err)
	}
	request.InstalledPlanDigest = strings.Repeat("0", 64)
	if _, err := Build(in, host); err == nil {
		t.Fatal("changed original plan digest accepted for retirement")
	}
}

func TestStage2aRetirementPreservesAbandonedActiveClaim(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	installation := "soul-one"
	if err := spendStage2aAdminName(dir, stage2aActiveClaimName(installation), uid, gid); err != nil {
		t.Fatal(err)
	}
	retireID := "plan-20261122T130000Z-abcd"
	if err := stage2aRootRetireActive(dir, installation, retireID, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := requireUnspentStage2aReservation(dir, stage2aActiveClaimName(installation)); err != nil {
		t.Fatalf("active claim survived owner-reviewed retirement: %v", err)
	}
	name := ".stage2a-retired-" + soulEndpointInstallationSlot(installation) + "-" + retireID
	if err := stage2aCheckSpentClaim(dir, name, uid, gid); err != nil {
		t.Fatalf("abandoned claim was discarded: %v", err)
	}
}
