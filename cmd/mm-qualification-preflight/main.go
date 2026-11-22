// Command mm-qualification-preflight checks signed qualification inputs before
// a release workflow signs its statement. It is not an adapter launch gate.
// Build this command from an exact reviewed Machine commit and supply the
// owner root from that release's pinned trust material.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/qwts/managed-machine/internal/qualification"
)

const usage = "usage: mm-qualification-preflight [-bridge-v2 -souls-build-bundle FILE -souls-package FILE -souls-trusted-root FILE] -owner-root FILE -owner-key-id ID -policy-envelope FILE -qualification FILE -protected-envelope FILE -cooperative-envelope FILE"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, qualification.ErrUnqualified
	}
	return data, nil
}

func hashPackage(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	if err != nil || n == (256<<20)+1 || n == 0 {
		return "", qualification.ErrUnqualified
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mm-qualification-preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bridgeV2 := fs.Bool("bridge-v2", false, "require the bridge-aware v2 protected report and qualification")
	soulsBundlePath := fs.String("souls-build-bundle", "", "local signed Souls build receipt bundle")
	soulsPackagePath := fs.String("souls-package", "", "exact delivered Souls package tgz")
	soulsRootPath := fs.String("souls-trusted-root", "", "owner-policy-pinned Souls Sigstore trusted root")
	rootPath := fs.String("owner-root", "", "reviewed owner Ed25519 root as lowercase hex")
	ownerKeyID := fs.String("owner-key-id", "", "owner root identifier")
	policyPath := fs.String("policy-envelope", "", "owner-signed policy envelope")
	qualificationPath := fs.String("qualification", "", "exact qualification.json")
	protectedPath := fs.String("protected-envelope", "", "protected host report envelope")
	cooperativePath := fs.String("cooperative-envelope", "", "cooperative host report envelope")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *rootPath == "" || *ownerKeyID == "" ||
		*policyPath == "" || *qualificationPath == "" || *protectedPath == "" || *cooperativePath == "" ||
		(*bridgeV2 && (*soulsBundlePath == "" || *soulsPackagePath == "" || *soulsRootPath == "")) ||
		(!*bridgeV2 && (*soulsBundlePath != "" || *soulsPackagePath != "" || *soulsRootPath != "")) {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	rootHex, e1 := readBounded(*rootPath, 65)
	root, e2 := hex.DecodeString(strings.TrimSuffix(string(rootHex), "\n"))
	if e1 != nil || e2 != nil || len(root) != ed25519.PublicKeySize ||
		hex.EncodeToString(root) != strings.TrimSuffix(string(rootHex), "\n") {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	policyEnvelope, e1 := readBounded(*policyPath, 2*qualification.MaxReportBytes)
	qualificationJSON, e2 := readBounded(*qualificationPath, qualification.MaxReportBytes)
	protectedEnvelope, e3 := readBounded(*protectedPath, 2*qualification.MaxReportBytes)
	cooperativeEnvelope, e4 := readBounded(*cooperativePath, 2*qualification.MaxReportBytes)
	if errors.Join(e1, e2, e3, e4) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	var soulsBundle, soulsRoot []byte
	var soulsPackageSHA string
	if *bridgeV2 {
		soulsBundle, e1 = readBounded(*soulsBundlePath, 4<<20)
		soulsRoot, e2 = readBounded(*soulsRootPath, 1<<20)
		soulsPackageSHA, e3 = hashPackage(*soulsPackagePath)
		if errors.Join(e1, e2, e3) != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
	}
	now := time.Now().UTC()
	// The producer has no Machine persisted revision state. Machine checks
	// rollback independently when it consumes the eventual release bundle.
	var policy qualification.VerifiedPolicy
	var err error
	if *bridgeV2 {
		policy, err = qualification.VerifyOwnerPolicyV2(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	} else {
		policy, err = qualification.VerifyOwnerPolicy(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	}
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	var protectedSHA, cooperativeSHA, protectedEnvelopeSHA, cooperativeEnvelopeSHA string
	if *bridgeV2 {
		build, err := qualification.VerifySoulsBuildReceiptV2(policy, soulsRoot, soulsBundle, qualificationJSON, soulsPackageSHA, now)
		if err != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		refs, err := qualification.VerifyHostReportsForReleaseV2(policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, build, now)
		if err != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		protectedSHA, cooperativeSHA = refs.ProtectedReport.Payload.SHA256, refs.CooperativeReport.Payload.SHA256
		protectedEnvelopeSHA, cooperativeEnvelopeSHA = refs.ProtectedReport.Signature.SHA256, refs.CooperativeReport.Signature.SHA256
	} else {
		var err error
		protectedSHA, cooperativeSHA, err = qualification.VerifyHostReportsForRelease(policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, now)
		if err != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
	}
	result := struct {
		SchemaVersion          int    `json:"schema_version"`
		QualificationSHA       string `json:"qualification_sha256"`
		ProtectedProfile       string `json:"protected_profile"`
		ProtectedSHA           string `json:"protected_report_sha256"`
		ProtectedEnvelopeSHA   string `json:"protected_envelope_sha256,omitempty"`
		CooperativeProfile     string `json:"cooperative_profile"`
		CooperativeSHA         string `json:"cooperative_report_sha256"`
		CooperativeEnvelopeSHA string `json:"cooperative_envelope_sha256,omitempty"`
		PolicySHA              string `json:"policy_sha256,omitempty"`
		PolicyEnvelopeSHA      string `json:"policy_envelope_sha256,omitempty"`
		SoulsBuildBundleSHA    string `json:"souls_build_bundle_sha256,omitempty"`
		SoulsPackageSHA        string `json:"souls_package_sha256,omitempty"`
		SoulsSourceTree        string `json:"souls_source_tree,omitempty"`
	}{SchemaVersion: 1, ProtectedProfile: "managed-protected", ProtectedSHA: protectedSHA, ProtectedEnvelopeSHA: protectedEnvelopeSHA, CooperativeProfile: "managed-cooperative", CooperativeSHA: cooperativeSHA, CooperativeEnvelopeSHA: cooperativeEnvelopeSHA}
	if *bridgeV2 {
		result.SchemaVersion = 2
		var envelope qualification.Envelope
		if json.Unmarshal(policyEnvelope, &envelope) != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		result.PolicySHA = envelope.PolicySHA256
		policyEnvelopeDigest := sha256.Sum256(policyEnvelope)
		result.PolicyEnvelopeSHA = "sha256:" + hex.EncodeToString(policyEnvelopeDigest[:])
		soulsBundleDigest := sha256.Sum256(soulsBundle)
		result.SoulsBuildBundleSHA = "sha256:" + hex.EncodeToString(soulsBundleDigest[:])
		result.SoulsPackageSHA = soulsPackageSHA
		result.SoulsSourceTree = policy.SoulsSourceTree()
	}
	qualificationDigest := sha256.Sum256(qualificationJSON)
	result.QualificationSHA = "sha256:" + hex.EncodeToString(qualificationDigest[:])
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	return 0
}
