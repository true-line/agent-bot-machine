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

type soulsDerivativeBuildStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		SourceRepository     string   `json:"source_repository"`
		SourceCommit         string   `json:"source_commit"`
		SourceTree           string   `json:"source_tree"`
		BuilderSHA           string   `json:"builder_sha256"`
		ToolchainSHA         string   `json:"toolchain_sha256"`
		Workflow             string   `json:"workflow"`
		RunID                string   `json:"run_id"`
		RunAttempt           uint64   `json:"run_attempt"`
		SourceNPMSHA         string   `json:"source_npm_sha256"`
		DerivativeBuilderSHA string   `json:"derivative_builder_sha256"`
		SelectedManifestSHA  string   `json:"selected_manifest_sha256"`
		ExcludedPaths        []string `json:"excluded_paths"`
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

// The v3 selected R runtime is a separately signed tar derivative of the npm
// source package. Its digest is the subject and the qualification package pin;
// the source npm digest and derivation metadata remain inside the signed claim.
// The installed R manifest and bytes still need their separate Machine checks.
func fixedSoulsDerivativeStatementV3(raw []byte, policy Policy, claim soulsBuildRef, packageSHA string) error {
	if policy.SoulsBuildWorkflow == nil || !validSHA(packageSHA) {
		return ErrUnqualified
	}
	if _, err := strictObject(raw, MaxReportBytes); err != nil {
		return ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement soulsDerivativeBuildStatement
	if d.Decode(&statement) != nil || d.Decode(new(any)) != io.EOF {
		return ErrUnqualified
	}
	p := statement.Predicate
	if statement.Type != statementType || statement.PredicateType != policy.SoulsBuildWorkflow.ReceiptPredicateType ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != "sha256-"+packageSHA[7:]+".tar" ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != packageSHA[7:] ||
		p.SourceRepository != claim.SourceRepository || p.SourceCommit != claim.SourceCommit ||
		p.SourceTree != claim.SourceTree || p.BuilderSHA != claim.BuilderSHA ||
		p.ToolchainSHA != claim.ToolchainSHA || p.Workflow != claim.Workflow ||
		p.RunID != claim.RunID || p.RunAttempt != claim.RunAttempt ||
		!validSHA(p.SourceNPMSHA) || p.SourceNPMSHA == packageSHA ||
		!validSHA(p.DerivativeBuilderSHA) || !validSHA(p.SelectedManifestSHA) ||
		p.SourceNPMSHA != policy.SoulsBuildWorkflow.SourceNPMSHA256 ||
		p.DerivativeBuilderSHA != policy.SoulsBuildWorkflow.DerivativeBuilderSHA256 ||
		p.SelectedManifestSHA != policy.SoulsBuildWorkflow.SelectedManifestSHA256 ||
		!validSoulsDerivativeExclusions(p.ExcludedPaths) {
		return ErrUnqualified
	}
	return nil
}

// A v3 policy without derivative pins retains the signed npm package path.
// The owner opts into the selected tar derivative by signing all three pins;
// an unpinned policy cannot authorize that derivative.
func fixedSoulsStatementForPolicy(raw []byte, policy Policy, claim soulsBuildRef, packageSHA string, version int) error {
	if policy.SoulsBuildWorkflow == nil {
		return ErrUnqualified
	}
	w := policy.SoulsBuildWorkflow
	if version == 2 || version == 3 && w.SourceNPMSHA256 == "" &&
		w.DerivativeBuilderSHA256 == "" && w.SelectedManifestSHA256 == "" {
		return fixedSoulsBuildStatement(raw, policy, claim, packageSHA)
	}
	if version == 3 {
		return fixedSoulsDerivativeStatementV3(raw, policy, claim, packageSHA)
	}
	return ErrUnqualified
}

func validSoulsDerivativeExclusions(paths []string) bool {
	if len(paths) == 0 || len(paths) > 32 {
		return false
	}
	previous := ""
	for _, path := range paths {
		if path <= previous || len(path) > 256 || strings.HasPrefix(path, "/") ||
			strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			return false
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return false
			}
			for _, c := range segment {
				if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
					(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
					return false
				}
			}
		}
		previous = path
	}
	return true
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
	return verifySoulsBuildReceipt(policy, trustedRootJSON, bundleJSON, claim, packageSHA, now, parseErr, 2)
}

// VerifySoulsBuildReceiptV3 authenticates the same separately signed Souls
// build claim in a v3 qualification. It does not verify the host reports,
// Machine completed runs, or installed R inputs. The caller must hash the
// exact delivered, signed Souls package to supply packageSHA.
func VerifySoulsBuildReceiptV3(policy VerifiedPolicy, trustedRootJSON, bundleJSON, qualificationJSON []byte, packageSHA string, now time.Time) (VerifiedSoulsBuild, error) {
	_, _, claim, _, parseErr := qualificationObjectV3(qualificationJSON, now)
	return verifySoulsBuildReceipt(policy, trustedRootJSON, bundleJSON, claim, packageSHA, now, parseErr, 3)
}

func verifySoulsBuildReceipt(policy VerifiedPolicy, trustedRootJSON, bundleJSON []byte, claim soulsBuildRef, packageSHA string, now time.Time, parseErr error, version int) (VerifiedSoulsBuild, error) {
	if !policy.verified || policy.version != version || policy.value.SoulsBuildWorkflow == nil ||
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
	statement := b.GetDsseEnvelope().GetPayload()
	if fixedSoulsStatementForPolicy(statement, policy.value, claim, packageSHA, version) != nil {
		return VerifiedSoulsBuild{}, ErrUnqualified
	}
	return VerifiedSoulsBuild{verified: true, build: claim}, nil
}
