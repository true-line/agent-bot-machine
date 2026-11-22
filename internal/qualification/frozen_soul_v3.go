package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var positiveRunID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// VerifiedFrozenSoul is minted only after offline signature, transparency,
// workflow, Statement and artifact-byte verification. The caller must supply
// independently measured, root-owned installed bytes at the acceptance gate.
type VerifiedFrozenSoul struct {
	verified       bool
	artifactSHA256 string
	receiptSHA256  string
}

type frozenSoulStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		ArtifactFormat string `json:"artifact_format"`
		Builder        struct {
			Repository    string `json:"repository"`
			SourceCommit  string `json:"source_commit"`
			SourceTree    string `json:"source_tree"`
			Workflow      string `json:"workflow"`
			RunID         string `json:"run_id"`
			RunAttempt    uint64 `json:"run_attempt"`
			BuilderSHA256 string `json:"builder_sha256"`
		} `json:"builder"`
		ToolchainSHA256 string `json:"toolchain_sha256"`
		Template        struct {
			Repository   string `json:"repository"`
			SourceCommit string `json:"source_commit"`
			SourceTree   string `json:"source_tree"`
			Path         string `json:"path"`
			TemplateTree string `json:"template_tree"`
		} `json:"template"`
		DefinitionMeasurement string `json:"definition_measurement"`
	} `json:"predicate"`
}

func fixedFrozenSoulStatement(raw []byte, workflow *FrozenSoulBuildWorkflow, mapping *FrozenSoulMapping) error {
	if workflow == nil || mapping == nil {
		return ErrUnqualified
	}
	if _, err := strictObject(raw, MaxReportBytes); err != nil {
		return ErrUnqualified
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var statement frozenSoulStatement
	if d.Decode(&statement) != nil {
		return ErrUnqualified
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrUnqualified
	}
	if statement.Type != statementType || statement.PredicateType != workflow.ReceiptPredicateType ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != "sha256-"+mapping.ArtifactSHA256+".soul" ||
		len(statement.Subject[0].Digest) != 1 || statement.Subject[0].Digest["sha256"] != mapping.ArtifactSHA256 ||
		statement.Predicate.ArtifactFormat != workflow.ArtifactFormat ||
		statement.Predicate.ToolchainSHA256 != workflow.ToolchainSHA256 ||
		statement.Predicate.DefinitionMeasurement != mapping.DefinitionMeasurement {
		return ErrUnqualified
	}
	b := statement.Predicate.Builder
	if _, err := strconv.ParseUint(b.RunID, 10, 64); err != nil {
		return ErrUnqualified
	}
	if b.Repository != workflow.Repository || b.SourceCommit != workflow.SourceCommit ||
		b.SourceTree != workflow.SourceTree || b.Workflow != workflow.WorkflowPath ||
		b.BuilderSHA256 != workflow.BuilderSHA256 || !positiveRunID.MatchString(b.RunID) ||
		b.RunAttempt == 0 || b.RunAttempt > 999_999_999 {
		return ErrUnqualified
	}
	t := statement.Predicate.Template
	if t.Repository != workflow.Template.Repository || t.SourceCommit != workflow.Template.SourceCommit ||
		t.SourceTree != workflow.Template.SourceTree || t.Path != workflow.Template.Path ||
		t.TemplateTree != workflow.Template.TemplateTree {
		return ErrUnqualified
	}
	return nil
}

// VerifyFrozenSoulReceiptV3 uses only supplied local bytes. It requires a
// release-pinned owner root (already used to mint policy), the policy-pinned
// exact trusted-root bytes and Rekor log, and a real Sigstore v0.3 DSSE bundle.
// artifactBytes must be the exact independently measured installed .soul bytes.
func VerifyFrozenSoulReceiptV3(policy VerifiedPolicy, trustedRootJSON, bundleJSON, artifactBytes []byte, now time.Time) (VerifiedFrozenSoul, error) {
	refused := func() (VerifiedFrozenSoul, error) { return VerifiedFrozenSoul{}, ErrUnqualified }
	if !policy.verified || policy.version != 3 || !policy.at.Equal(now) || now.IsZero() ||
		policy.value.FrozenSoulReleaseProvenanceEnabled == nil || !*policy.value.FrozenSoulReleaseProvenanceEnabled || policy.value.FrozenSoulBuildWorkflow == nil || policy.value.FrozenSoulMapping == nil ||
		len(trustedRootJSON) == 0 || len(trustedRootJSON) > maxTrustedRoot ||
		len(bundleJSON) == 0 || len(bundleJSON) > MaxReportBytes ||
		len(artifactBytes) == 0 || len(artifactBytes) > MaxReportBytes {
		return refused()
	}
	w, mapping := policy.value.FrozenSoulBuildWorkflow, policy.value.FrozenSoulMapping
	artifactDigest := sha256.Sum256(artifactBytes)
	artifactSHA := hex.EncodeToString(artifactDigest[:])
	bundleSHA := digest(bundleJSON)
	if artifactSHA != mapping.ArtifactSHA256 || bundleSHA != mapping.ReceiptSHA256 ||
		digest(trustedRootJSON) != w.TrustRootSHA256 {
		return refused()
	}
	for _, revoked := range policy.value.RevocationSnapshot.RevokedFrozenSoulReceiptSHA256 {
		if revoked == bundleSHA {
			return refused()
		}
	}
	trust, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return refused()
	}
	if _, ok := trust.RekorLogs()[w.TransparencyLogID]; !ok {
		return refused()
	}
	var b bundle.Bundle
	if b.UnmarshalJSON(bundleJSON) != nil || b.GetMediaType() != w.BundleMediaType ||
		b.GetDsseEnvelope() == nil || b.GetDsseEnvelope().GetPayloadType() != w.DSSEPayloadType ||
		len(b.GetDsseEnvelope().GetSignatures()) != 1 {
		return refused()
	}
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) != 1 || entries[0].GetInclusionProof() == nil ||
		entries[0].GetInclusionProof().GetCheckpoint() == nil ||
		hex.EncodeToString(entries[0].GetLogId().GetKeyId()) != w.TransparencyLogID ||
		entries[0].GetKindVersion().GetKind() != w.RekorEntryKind ||
		entries[0].GetKindVersion().GetVersion() != w.RekorEntryVersion {
		return refused()
	}
	if w.RekorEntryKind == "dsse" {
		if len(entries[0].GetInclusionPromise().GetSignedEntryTimestamp()) == 0 {
			return refused()
		}
	} else if len(b.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()) != 1 {
		return refused()
	}
	identity, err := verify.NewShortCertificateIdentity(w.OIDCIssuer, "", w.CertificateIdentity, "")
	if err != nil {
		return refused()
	}
	v, err := verify.NewVerifier(trust, verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return refused()
	}
	result, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", artifactDigest[:]),
		verify.WithCertificateIdentity(identity)))
	if err != nil || result == nil || result.Statement == nil || result.Signature == nil ||
		result.Signature.Certificate == nil {
		return refused()
	}
	cert := result.Signature.Certificate
	if cert.SourceRepositoryURI != "https://github.com/"+w.Repository || cert.SourceRepositoryDigest != w.SourceCommit {
		return refused()
	}
	trustedTime := false
	for _, timestamp := range result.VerifiedTimestamps {
		if timestamp.Timestamp.After(now) {
			return refused()
		}
		if w.RekorEntryKind == "dsse" && timestamp.Type == "Tlog" ||
			w.RekorEntryKind == "hashedrekord" && timestamp.Type == "TimestampAuthority" {
			trustedTime = true
		}
	}
	if !trustedTime || fixedFrozenSoulStatement(b.GetDsseEnvelope().GetPayload(), w, mapping) != nil {
		return refused()
	}
	return VerifiedFrozenSoul{verified: true, artifactSHA256: artifactSHA, receiptSHA256: bundleSHA}, nil
}
