package qualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type soulsBuildStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		SourceRepository string `json:"source_repository"`
		SourceCommit     string `json:"source_commit"`
		SourceTree       string `json:"source_tree"`
		BuilderSHA       string `json:"builder_sha256"`
		ToolchainSHA     string `json:"toolchain_sha256"`
		Workflow         string `json:"workflow"`
		RunID            string `json:"run_id"`
		RunAttempt       uint64 `json:"run_attempt"`
	} `json:"predicate"`
}

func fixedSoulsBuildStatement(raw []byte, policy Policy, claim soulsBuildRef, packageSHA string) error {
	if policy.SoulsBuildWorkflow == nil {
		return ErrUnqualified
	}
	if _, err := strictObject(raw, MaxReportBytes); err != nil {
		return ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement soulsBuildStatement
	if d.Decode(&statement) != nil {
		return ErrUnqualified
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrUnqualified
	}
	if statement.Type != statementType || statement.PredicateType != policy.SoulsBuildWorkflow.ReceiptPredicateType ||
		len(statement.Subject) != 1 || !validSoulsPackageName(statement.Subject[0].Name) ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != packageSHA[7:] ||
		statement.Predicate.SourceRepository != claim.SourceRepository ||
		statement.Predicate.SourceCommit != claim.SourceCommit ||
		statement.Predicate.SourceTree != claim.SourceTree ||
		statement.Predicate.BuilderSHA != claim.BuilderSHA ||
		statement.Predicate.ToolchainSHA != claim.ToolchainSHA ||
		statement.Predicate.Workflow != claim.Workflow ||
		statement.Predicate.RunID != claim.RunID ||
		statement.Predicate.RunAttempt != claim.RunAttempt {
		return ErrUnqualified
	}
	return nil
}

func validSoulsPackageName(name string) bool {
	if len(name) < 5 || !strings.HasSuffix(name, ".tgz") {
		return false
	}
	for _, c := range strings.TrimSuffix(name, ".tgz") {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// VerifySoulsBuildReceiptV2 authenticates a distinct local Sigstore bundle
// under the owner-pinned Souls workflow, source tree, builder and toolchain.
// packageSHA must be computed from the exact delivered tgz bytes by the caller.
func VerifySoulsBuildReceiptV2(policy VerifiedPolicy, trustedRootJSON, bundleJSON, qualificationJSON []byte, packageSHA string, now time.Time) (VerifiedSoulsBuild, error) {
	_, _, claim, parseErr := qualificationObjectV2(qualificationJSON)
	if !policy.verified || policy.version != 2 || policy.value.SoulsBuildWorkflow == nil ||
		parseErr != nil || now.IsZero() || !policy.at.Equal(now) || !validSoulsBuild(claim) ||
		!validSHA(packageSHA) || packageSHA != claim.PackageSHA ||
		len(trustedRootJSON) == 0 || len(trustedRootJSON) > maxTrustedRoot ||
		len(bundleJSON) == 0 || len(bundleJSON) > maxReleaseBundle ||
		digest(trustedRootJSON) != policy.value.SoulsBuildWorkflow.TrustRootSHA256 ||
		digest(bundleJSON) != claim.Receipt.SHA256 {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	w := policy.value.SoulsBuildWorkflow
	if claim.SourceRepository != w.Repository || claim.SourceCommit != w.SourceCommit ||
		claim.SourceTree != w.SourceTree || claim.BuilderSHA != w.BuilderSHA256 ||
		claim.ToolchainSHA != w.ToolchainSHA256 || claim.Workflow != w.WorkflowPath {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	for _, revoked := range policy.value.RevocationSnapshot.RevokedSoulsBuildReceiptSHA256 {
		if revoked == claim.Receipt.SHA256 {
			return VerifiedSoulsBuild{}, ErrUnqualified
		}
	}
	trust, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	var b bundle.Bundle
	if b.UnmarshalJSON(bundleJSON) != nil || b.GetMediaType() != w.BundleMediaType || b.GetDsseEnvelope() == nil ||
		b.GetDsseEnvelope().GetPayloadType() != w.DSSEPayloadType || len(b.GetDsseEnvelope().GetSignatures()) != 1 {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) != 1 || entries[0].GetInclusionProof() == nil || entries[0].GetInclusionProof().GetCheckpoint() == nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	identity, err := verify.NewShortCertificateIdentity(w.OIDCIssuer, "", w.CertificateIdentity, "")
	if err != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	v, err := verify.NewVerifier(trust, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	packageDigest, err := hex.DecodeString(packageSHA[7:])
	if err != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	result, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", packageDigest), verify.WithCertificateIdentity(identity)))
	if err != nil || result == nil || result.Statement == nil || result.Signature == nil || result.Signature.Certificate == nil || len(result.VerifiedTimestamps) == 0 {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	cert := result.Signature.Certificate
	if cert.SourceRepositoryURI != "https://github.com/"+w.Repository || cert.SourceRepositoryDigest != w.SourceCommit {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	for _, timestamp := range result.VerifiedTimestamps {
		if timestamp.Timestamp.After(now) {
			return VerifiedSoulsBuild{}, ErrUnqualified
		}
	}
	if fixedSoulsBuildStatement(b.GetDsseEnvelope().GetPayload(), policy.value, claim, packageSHA) != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	return VerifiedSoulsBuild{verified: true, build: claim}, nil
}
