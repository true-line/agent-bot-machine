//go:build darwin && stage2a_guest

package members

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This fixture exercises the R producer's root source closure, private copy,
// and fixed offline A seal in a disposable guest. It has no owner proof,
// release provenance, HQ start or T-gate authority.
func TestStage2aV3GuestInstallRuntime(t *testing.T) {
	if os.Getenv("STAGE2A_V3_GUEST_SEAL") != "1" {
		t.Skip("disposable Stage 2a v3 guest only")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("guest R install fixture requires root")
	}
	aName, rName := os.Getenv("STAGE2A_V3_A_ACCOUNT"), os.Getenv("STAGE2A_V3_R_ACCOUNT")
	aUID, aGID := stage2aGuestAccount(t, aName)
	rUID, rGID := stage2aGuestAccount(t, rName)
	if aUID < 400 || aUID == rUID || verifyStage2aInstalledGroup(rName, rGID, aName, aUID, rName, rUID) != nil {
		t.Fatal("guest A/R accounts or dedicated group invalid")
	}
	if err := os.MkdirAll(filepath.Dir(stage2aDomainSnapshotParentV3), 0755); err != nil {
		t.Fatal(err)
	}
	launcher, err := os.ReadFile(SoulLauncher)
	if err != nil {
		t.Fatal(err)
	}
	launcherHash := harnessSHA(launcher)
	if launcherHash != os.Getenv("STAGE2A_V3_GUEST_LAUNCHER_SHA256") {
		t.Fatal("guest launcher hash differs from exact fixture")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	installationID := "guest-r-" + hex.EncodeToString(nonce[:])
	sourceRoot := filepath.Join(filepath.Dir(stage2aDomainSnapshotParentV3), "stage2a-r-source-"+hex.EncodeToString(nonce[:]))
	if err := os.Mkdir(sourceRoot, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sourceRoot) })
	for _, relative := range []string{"runtime", "runtime/bin"} {
		if err := os.Mkdir(filepath.Join(sourceRoot, relative), 0755); err != nil {
			t.Fatal(err)
		}
	}
	const relative = "runtime/bin/node"
	data := []byte("reviewed R runtime guest bytes\n")
	if err := os.WriteFile(filepath.Join(sourceRoot, relative), data, 0444); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	inv := stage2aDomainInventoryV3{Contract: "machine/v3", Kind: "stage2a-domain-inventory",
		SchemaVersion: 3, Domain: "R-runtime", InstallationID: installationID,
		Limits: stage2aDomainInventoryLimitsV3{MaxFiles: 512,
			MaxFileBytes: stage2aV3MaxInventoryFileBytes, MaxTotalBytes: stage2aV3MaxInventoryTotalBytes},
		Directories: []stage2aDomainDirectoryV3{{Path: "runtime", Kind: "directory", Mode: "0550"},
			{Path: "runtime/bin", Kind: "directory", Mode: "0550"}},
		Files: []stage2aDomainFileV3{{Path: relative, Kind: "regular", Mode: "0440",
			SizeBytes: uint64(len(data)), SHA256: fmt.Sprintf("sha256:%x", sum),
			ComponentID: "node", ReleasePath: relative}}, TotalBytes: uint64(len(data))}
	raw := stage2aV3TestCanonical(t, inv)
	_, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "unreviewed"), data, 0444); err != nil {
		t.Fatal(err)
	}
	if err := stage2aRuntimeSourceClosureV3(sourceRoot, "node", inv); err == nil {
		t.Fatal("accepted an unreviewed source file")
	}
	if err := os.Remove(filepath.Join(sourceRoot, "unreviewed")); err != nil {
		t.Fatal(err)
	}
	ref, err := stage2aInstallRuntimeV3AsAdmin(stage2aRuntimeStageV3{
		InstallationID: installationID, MachineAccount: aName, MachineUID: aUID, MachineGID: aGID,
		ReaderAccount: rName, ReaderUID: rUID, ReaderGID: rGID,
		PlanDigest: strings.Repeat("1", 64), InventoryDigest: digest,
		LauncherSHA256: launcherHash, Inventory: raw,
		SourceRoots: map[string]string{"node": sourceRoot},
	})
	if err != nil {
		t.Fatalf("R root-to-A install refused: %v", err)
	}
	namespace, _, _, _ := stage2aDomainNamesV3("R-runtime", installationID)
	t.Cleanup(func() { _ = os.RemoveAll(namespace) })
	observed, err := stage2aObserveInstalledDomainV3(ref.Snapshot.Path, ref.Sidecar.Path,
		uint32(aUID), uint32(rUID), uint32(rGID), ref.OwnerPlanDigest, digest)
	if err != nil || observed.ref != ref || ref.FileCount != 1 || ref.TotalBytes != uint64(len(data)) {
		t.Fatalf("installed R ref differs: %+v %v", ref, err)
	}
	t.Logf("COMPONENT_ONLY R root-to-A install sealed files=%d bytes=%d digest=%s", ref.FileCount, ref.TotalBytes, ref.InventoryDigest)
}
