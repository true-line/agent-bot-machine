package members

import (
	"strings"
)

type stage2aVerifiedCandidateArchiveV3 struct {
	componentID, packageSHA256, manifestSHA256, inventoryDigest string
}

// component comes from the authenticated installed owner plan. SHA-256
// covers the exact vendor ZIP, including both stock executables.
// The separately pinned manifest maps its all-and-only rows to sealed R.
func verifyStage2aCandidateAdapterArchiveV3(component stage2aReleaseComponent,
	inv stage2aDomainInventoryV3) (stage2aVerifiedCandidateArchiveV3, error) {
	var empty stage2aVerifiedCandidateArchiveV3
	if !component.valid() || !strings.HasSuffix(component.ArtifactSource, ".zip") || inv.Domain != "R-runtime" ||
		trustedPath(OSHost{}, component.ArtifactSource, false) != nil ||
		checkDarwinACLs(pathAncestry(component.ArtifactSource)) != nil {
		return empty, errStage2aReservationAuthority
	}
	raw, err := marshalStage2aReservationJCS(inv)
	if err != nil {
		return empty, err
	}
	_, inventoryDigest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil {
		return empty, err
	}
	hashes := make(map[string]string)
	for _, row := range inv.Files {
		if row.ComponentID == component.ComponentID {
			hashes[row.ReleasePath] = row.SHA256
		}
	}
	manifest, err := stage2aReadRootFile(component.ManifestSource, 1<<20, 0444, 0644)
	if err != nil || checkHQStage2aManifestRows(manifest, component.ManifestSHA256, hashes) != nil {
		return empty, errStage2aReservationAuthority
	}
	if err := stage2aVerifyRuntimeV3Artifact(stage2aRuntimeV3ComponentPin{
		ComponentID: component.ComponentID, ArtifactFormat: "zip", ArtifactSource: component.ArtifactSource,
		ReleaseArtifactSHA256: component.ArtifactSHA256,
	}, 0, inv); err != nil {
		return empty, err
	}
	return stage2aVerifiedCandidateArchiveV3{
		componentID: component.ComponentID, packageSHA256: component.ArtifactSHA256,
		manifestSHA256: component.ManifestSHA256, inventoryDigest: inventoryDigest,
	}, nil
}
