//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestStage2aHDescriptorBindsReviewedPlanAndInstalledRowsV3(t *testing.T) {
	vector, key := stage2aLoadContractVectorV3(t)
	pub := key.Public().(ed25519.PublicKey)
	var p stage2aHServiceDescriptorPayloadV3
	if stage2aDecodeExact([]byte(vector.HPayloadJCS), &p) != nil {
		t.Fatal("invalid Contracts H payload")
	}
	var fixture struct {
		HInventoryJCS string `json:"h_inventory_jcs"`
	}
	raw, err := os.ReadFile("testdata/stage2a-machine-hr-v3-synthetic.json")
	if err != nil || json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid Contracts inventory vector")
	}
	inv, digest, err := stage2aDomainInventoryDigestV3([]byte(fixture.HInventoryJCS))
	if err != nil || digest != p.HInventory.InventoryDigest {
		t.Fatalf("invalid Contracts H inventory: %v", err)
	}
	plan := stage2aVerifiedHInstallPlanV3{
		verified: true, descriptor: p, machineGID: 20,
		authorityKeySHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(pub)),
	}
	if err := stage2aValidateHDescriptorV3(p, p.HInventory, plan, inv, pub); err != nil {
		t.Fatalf("reviewed H descriptor rejected: %v", err)
	}
	for name, mutate := range map[string]func(*stage2aHServiceDescriptorPayloadV3){
		"host": func(q *stage2aHServiceDescriptorPayloadV3) { q.HostID = "other-host" },
		"release attestation": func(q *stage2aHServiceDescriptorPayloadV3) {
			q.Components[0].ReleaseAttestationSHA256 = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
		},
		"guard file": func(q *stage2aHServiceDescriptorPayloadV3) {
			q.Runtime.GuardModuleSHA256 = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
		},
		"outer argv": func(q *stage2aHServiceDescriptorPayloadV3) { q.OuterLaunch.Argv[1] = "--enable-gems" },
	} {
		t.Run(name, func(t *testing.T) {
			var q stage2aHServiceDescriptorPayloadV3
			if stage2aDecodeExact([]byte(vector.HPayloadJCS), &q) != nil {
				t.Fatal("invalid fixture")
			}
			mutate(&q)
			if stage2aValidateHDescriptorV3(q, p.HInventory, plan, inv, pub) == nil {
				t.Fatal("accepted descriptor differing from reviewed plan or H inventory")
			}
		})
	}
	changedInventory := inv
	changedInventory.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	changedInventory.Files[0].SHA256 = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
	if stage2aValidateHDescriptorV3(p, p.HInventory, plan, changedInventory, pub) == nil {
		t.Fatal("accepted changed installed Node bytes")
	}
	unusedRelease := p
	unusedRelease.Components = append(append([]stage2aHReleaseComponentV3(nil), p.Components...),
		stage2aHReleaseComponentV3{ComponentID: "zz", ReleaseArtifactSHA256: p.Components[0].ReleaseArtifactSHA256,
			ReleaseAttestationSHA256: p.Components[0].ReleaseAttestationSHA256,
			ReleaseManifestSHA256:    p.Components[0].ReleaseManifestSHA256})
	unusedPlan := plan
	unusedPlan.descriptor = unusedRelease
	if stage2aValidateHDescriptorV3(unusedRelease, p.HInventory, unusedPlan, inv, pub) == nil {
		t.Fatal("accepted release component with no installed H row")
	}
	aliasedGuard := p
	aliasedGuard.Runtime.GuardModulePath = p.Runtime.EntryPath
	aliasedGuard.Runtime.GuardModuleSHA256 = p.Runtime.EntrySHA256
	aliasPlan := plan
	aliasPlan.descriptor = aliasedGuard
	if stage2aValidateHDescriptorV3(aliasedGuard, p.HInventory, aliasPlan, inv, pub) == nil {
		t.Fatal("accepted aliased H entry and guard module")
	}
	plan.verified = false
	if stage2aValidateHDescriptorV3(p, p.HInventory, plan, inv, pub) == nil {
		t.Fatal("accepted unverified owner plan")
	}
	plan.verified = true
	if stage2aValidateHDescriptorV3(p, p.HInventory, plan, inv, bytes.Repeat([]byte{0}, 32)) == nil {
		t.Fatal("accepted substituted Machine signing key")
	}
}
