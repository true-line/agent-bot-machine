package members

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestStage2aRuntimeManifestMatchesV3(t *testing.T) {
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{
		{ComponentID: "souls", ReleasePath: "runtime/bin/agent-bot-souls.mjs", SHA256: "sha256:" + strings.Repeat("1", 64)},
		{ComponentID: "node", ReleasePath: "runtime/bin/node", SHA256: "sha256:" + strings.Repeat("2", 64)},
	}}
	good := `[{"path":"runtime/bin/node","sha256":"sha256:` + strings.Repeat("2", 64) + `"}]`
	if err := stage2aRuntimeManifestMatchesV3([]byte(good), "node", inv); err != nil {
		t.Fatalf("exact Node manifest refused: %v", err)
	}
	for name, raw := range map[string]string{
		"extra row":     `[{"path":"runtime/bin/node","sha256":"sha256:` + strings.Repeat("2", 64) + `"},{"path":"runtime/bin/other","sha256":"sha256:` + strings.Repeat("2", 64) + `"}]`,
		"wrong digest":  `[{"path":"runtime/bin/node","sha256":"sha256:` + strings.Repeat("1", 64) + `"}]`,
		"noncanonical":  good + "\n",
		"duplicate key": `[{"path":"runtime/bin/node","path":"runtime/bin/node","sha256":"sha256:` + strings.Repeat("2", 64) + `"}]`,
	} {
		if err := stage2aRuntimeManifestMatchesV3([]byte(raw), "node", inv); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestStage2aRuntimeV3PlanRequiresExactComponentPins(t *testing.T) {
	manifest := []byte(`[{"path":"runtime/bin/node","sha256":"sha256:` + strings.Repeat("2", 64) + `"}]`)
	sum := sha256.Sum256(manifest)
	inv := stage2aDomainInventoryV3{Domain: "R-runtime", InstallationID: "install-one",
		Limits: stage2aDomainInventoryLimitsV3{MaxFiles: 1, MaxFileBytes: 100, MaxTotalBytes: 100},
		Files:  []stage2aDomainFileV3{{ComponentID: "node", ReleasePath: "runtime/bin/node", SHA256: "sha256:" + strings.Repeat("2", 64)}}}
	spec := stage2aRuntimeV3Install{InventorySource: "/private/var/db/r-inventory.jcs",
		InventoryDigest: "sha256:" + strings.Repeat("3", 64), Limits: inv.Limits,
		Components: []stage2aRuntimeV3ComponentPin{{ComponentID: "node", SourceRepository: "nodejs/node", ArtifactFormat: "raw",
			SourceCommit: strings.Repeat("4", 40), ArtifactSource: "/private/var/db/node.tar",
			ReleaseArtifactSHA256: "sha256:" + strings.Repeat("5", 64),
			ManifestSource:        "/private/var/db/node-manifest.jcs", ReleaseManifestSHA256: fmt.Sprintf("sha256:%x", sum)}},
		SourceRoots: map[string]string{"node": "/private/var/db/node-source"}}
	manifests := map[string][]byte{"node": manifest}
	if err := stage2aValidateRuntimeV3Plan(spec, inv, spec.InventoryDigest, manifests); err != nil {
		t.Fatalf("exact component plan refused: %v", err)
	}
	for name, change := range map[string]func(*stage2aRuntimeV3Install){
		"unreviewed limit": func(s *stage2aRuntimeV3Install) { s.Limits.MaxFiles++ },
		"wrong manifest hash": func(s *stage2aRuntimeV3Install) {
			s.Components[0].ReleaseManifestSHA256 = "sha256:" + strings.Repeat("6", 64)
		},
		"unreviewed source root": func(s *stage2aRuntimeV3Install) { s.SourceRoots["extra"] = "/private/var/db/extra" },
		"snapshot as source":     func(s *stage2aRuntimeV3Install) { s.SourceRoots["node"] = stage2aDomainSnapshotParentV3 + "/r_fake" },
	} {
		bad := spec
		bad.Components = append([]stage2aRuntimeV3ComponentPin(nil), spec.Components...)
		bad.SourceRoots = map[string]string{"node": spec.SourceRoots["node"]}
		change(&bad)
		if err := stage2aValidateRuntimeV3Plan(bad, inv, spec.InventoryDigest, manifests); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
