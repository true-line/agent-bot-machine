package members

import (
	"strings"
	"testing"
)

func TestStage2aOwnerCandidateComponentUsesExactApprovedZIPAndManifest(t *testing.T) {
	request := validQualificationRequest()
	request.Adapter.ID = "claude-code"
	request.Adapter.PackagePath = "/private/reviewed/stock.zip"
	request.Adapter.PackageSHA = strings.Repeat("a", 64)
	request.Candidate = &qualificationCandidatePlan{
		ComponentID: "adapter", Manifest: qualificationFile{"/private/reviewed/manifest.json", strings.Repeat("b", 64)},
	}
	component := stage2aRuntimeV3ComponentPin{
		ComponentID: "adapter", ArtifactFormat: "zip",
		ArtifactSource: request.Adapter.PackagePath, ReleaseArtifactSHA256: "sha256:" + request.Adapter.PackageSHA,
		ManifestSource: request.Candidate.Manifest.Path, ReleaseManifestSHA256: "sha256:" + request.Candidate.Manifest.SHA256,
	}
	installed := stage2aRuntimeV3Install{Components: []stage2aRuntimeV3ComponentPin{component}}
	got, err := stage2aOwnerCandidateComponentV3(installed, request)
	if err != nil || got.ComponentID != "adapter" || got.ArtifactSHA256 != component.ReleaseArtifactSHA256 {
		t.Fatalf("exact adapter mapping refused: %+v, %v", got, err)
	}
	for _, change := range []func(*stage2aRuntimeV3ComponentPin){
		func(c *stage2aRuntimeV3ComponentPin) { c.ArtifactFormat = "raw" },
		func(c *stage2aRuntimeV3ComponentPin) { c.ArtifactSource = "/private/reviewed/substitute.zip" },
		func(c *stage2aRuntimeV3ComponentPin) { c.ReleaseArtifactSHA256 = "sha256:" + strings.Repeat("c", 64) },
		func(c *stage2aRuntimeV3ComponentPin) { c.ManifestSource = "/private/reviewed/substitute.json" },
		func(c *stage2aRuntimeV3ComponentPin) { c.ReleaseManifestSHA256 = "sha256:" + strings.Repeat("c", 64) },
	} {
		changed := component
		change(&changed)
		installed.Components[0] = changed
		if _, err := stage2aOwnerCandidateComponentV3(installed, request); err == nil {
			t.Fatalf("unapproved installed component was accepted: %+v", changed)
		}
	}
}
