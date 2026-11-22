package qualification

import (
	"regexp"
)

var frozenSoulID = regexp.MustCompile(`^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validFrozenSoulPolicy(policy Policy) bool {
	build, mapping := policy.FrozenSoulBuildWorkflow, policy.FrozenSoulMapping
	if build == nil || mapping == nil || !reportID.MatchString(build.ID) ||
		build.Repository != "true-line/soul-package" ||
		build.WorkflowPath != ".github/workflows/stage2a-frozen-soul-receipt.yml" ||
		!validHex(build.SourceCommit, 40) || !validHex(build.SourceTree, 40) ||
		!httpsURL(build.OIDCIssuer) || !httpsURL(build.CertificateIdentity) ||
		!validSHA(build.TrustRootSHA256) || !validSHA(build.BuilderSHA256) ||
		!validSHA(build.ToolchainSHA256) ||
		build.ReceiptPredicateType != "https://true-line.ai/soul-contracts/package/v1/frozen-soul-build" ||
		build.BundleMediaType != bundleMediaType || build.DSSEPayloadType != DSSEPayloadType ||
		build.ArtifactFormat != "stage2a-frozen-hello-ustar/v1" ||
		build.SubjectNameTemplate != "sha256-{artifact_sha256}.soul" ||
		!((build.RekorEntryKind == "dsse" && build.RekorEntryVersion == "0.0.1") ||
			(build.RekorEntryKind == "hashedrekord" && build.RekorEntryVersion == "0.0.2")) ||
		!validHex(build.TransparencyLogID, 64) ||
		build.Template.Repository != "true-line/soul-conformance" ||
		!validHex(build.Template.SourceCommit, 40) ||
		!validHex(build.Template.SourceTree, 40) ||
		build.Template.Path != "templates/hello.soul" ||
		!validHex(build.Template.TemplateTree, 40) ||
		!frozenSoulID.MatchString(mapping.SoulID) ||
		!validHex(mapping.ArtifactSHA256, 64) ||
		!validSHA(mapping.ClaimedDefinitionDigest) ||
		!validSHA(mapping.DefinitionMeasurement) {
		return false
	}
	seen := map[string]bool{}
	for _, item := range policy.RevocationSnapshot.RevokedFrozenSoulArtifactSHA256 {
		if !validHex(item, 64) || seen[item] {
			return false
		}
		seen[item] = true
	}
	for _, item := range policy.RevocationSnapshot.RevokedFrozenSoulBuildWorkflowIDs {
		if item == build.ID {
			return false
		}
	}
	for _, item := range policy.RevocationSnapshot.RevokedFrozenSoulArtifactSHA256 {
		if item == mapping.ArtifactSHA256 {
			return false
		}
	}
	return true
}
