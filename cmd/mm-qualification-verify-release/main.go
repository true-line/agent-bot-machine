// Command mm-qualification-verify-release checks a delivered qualification
// bundle and its host evidence entirely offline. It does not measure installed
// adapter files or authorize a protected launch.
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

const usage = "usage: mm-qualification-verify-release [-bridge-v2 | -host-v3 -machine-root FILE -protected-execution FILE -cooperative-execution FILE -protected-commitment FILE -cooperative-commitment FILE] [-souls-build-bundle FILE -souls-package FILE -souls-trusted-root FILE] -owner-root FILE -owner-key-id ID -policy-envelope FILE -trusted-root FILE -bundle FILE -bundle-sha256 SHA256 -qualification FILE -protected-envelope FILE -cooperative-envelope FILE"

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
	fs := flag.NewFlagSet("mm-qualification-verify-release", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bridgeV2 := fs.Bool("bridge-v2", false, "require the bridge-aware v2 protected release")
	hostV3 := fs.Bool("host-v3", false, "require a v3 release and two Machine-signed completed-run chains")
	machineRootPath := fs.String("machine-root", "", "independently reviewed enrolled Machine Ed25519 public key as lowercase hex")
	protectedExecutionPath := fs.String("protected-execution", "", "protected pre-sign completion envelope")
	cooperativeExecutionPath := fs.String("cooperative-execution", "", "cooperative pre-sign completion envelope")
	protectedCommitmentPath := fs.String("protected-commitment", "", "protected post-sign report commitment")
	cooperativeCommitmentPath := fs.String("cooperative-commitment", "", "cooperative post-sign report commitment")
	soulsBundlePath := fs.String("souls-build-bundle", "", "local signed Souls build receipt bundle")
	soulsPackagePath := fs.String("souls-package", "", "exact delivered Souls package tgz")
	soulsRootPath := fs.String("souls-trusted-root", "", "owner-policy-pinned Souls Sigstore trusted root")
	rootPath := fs.String("owner-root", "", "reviewed owner Ed25519 root as lowercase hex")
	ownerKeyID := fs.String("owner-key-id", "", "owner root identifier")
	policyPath := fs.String("policy-envelope", "", "owner-signed policy envelope")
	trustedRootPath := fs.String("trusted-root", "", "owner-policy-pinned Sigstore trusted root")
	bundlePath := fs.String("bundle", "", "local Sigstore v0.3 release bundle")
	bundleSHA := fs.String("bundle-sha256", "", "exact installed qualification reference digest")
	qualificationPath := fs.String("qualification", "", "exact qualification.json")
	protectedPath := fs.String("protected-envelope", "", "protected host report envelope")
	cooperativePath := fs.String("cooperative-envelope", "", "cooperative host report envelope")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *rootPath == "" || *ownerKeyID == "" ||
		*policyPath == "" || *trustedRootPath == "" || *bundlePath == "" || *bundleSHA == "" ||
		*qualificationPath == "" || *protectedPath == "" || *cooperativePath == "" ||
		(*bridgeV2 && *hostV3) ||
		((*bridgeV2 || *hostV3) && (*soulsBundlePath == "" || *soulsPackagePath == "" || *soulsRootPath == "")) ||
		(!*bridgeV2 && !*hostV3 && (*soulsBundlePath != "" || *soulsPackagePath != "" || *soulsRootPath != "")) ||
		(*hostV3 && (*machineRootPath == "" || *protectedExecutionPath == "" || *cooperativeExecutionPath == "" || *protectedCommitmentPath == "" || *cooperativeCommitmentPath == "")) ||
		(!*hostV3 && (*machineRootPath != "" || *protectedExecutionPath != "" || *cooperativeExecutionPath != "" || *protectedCommitmentPath != "" || *cooperativeCommitmentPath != "")) {
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
	trustedRootJSON, e2 := readBounded(*trustedRootPath, 1<<20)
	bundleJSON, e3 := readBounded(*bundlePath, 4<<20)
	qualificationJSON, e4 := readBounded(*qualificationPath, qualification.MaxReportBytes)
	protectedEnvelope, e5 := readBounded(*protectedPath, 2*qualification.MaxReportBytes)
	cooperativeEnvelope, e6 := readBounded(*cooperativePath, 2*qualification.MaxReportBytes)
	if errors.Join(e1, e2, e3, e4, e5, e6) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	var soulsBundle, soulsRoot []byte
	var soulsPackageSHA string
	if *bridgeV2 || *hostV3 {
		soulsBundle, e1 = readBounded(*soulsBundlePath, 4<<20)
		soulsRoot, e2 = readBounded(*soulsRootPath, 1<<20)
		soulsPackageSHA, e3 = hashPackage(*soulsPackagePath)
		if errors.Join(e1, e2, e3) != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
	}
	now := time.Now().UTC()
	// The diagnostic command has no protected persisted policy state. The
	// live Machine acceptance path must separately enforce rollback and
	// independently measure installed inputs before any launch decision.
	var policy qualification.VerifiedPolicy
	var err error
	if *hostV3 {
		policy, err = qualification.VerifyOwnerPolicyV3(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	} else if *bridgeV2 {
		policy, err = qualification.VerifyOwnerPolicyV2(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	} else {
		policy, err = qualification.VerifyOwnerPolicy(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	}
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	var release qualification.VerifiedRelease
	var protectedExecution, cooperativeExecution, protectedCommitment, cooperativeCommitment []byte
	if *hostV3 {
		machineRootHex, readErr := readBounded(*machineRootPath, 65)
		machineRoot, decodeErr := hex.DecodeString(strings.TrimSuffix(string(machineRootHex), "\n"))
		if readErr != nil || decodeErr != nil || len(machineRoot) != ed25519.PublicKeySize ||
			hex.EncodeToString(machineRoot) != strings.TrimSuffix(string(machineRootHex), "\n") {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		protectedExecution, e1 = readBounded(*protectedExecutionPath, 2*qualification.MaxReportBytes)
		cooperativeExecution, e2 = readBounded(*cooperativeExecutionPath, 2*qualification.MaxReportBytes)
		protectedCommitment, e3 = readBounded(*protectedCommitmentPath, 2*qualification.MaxReportBytes)
		cooperativeCommitment, e4 = readBounded(*cooperativeCommitmentPath, 2*qualification.MaxReportBytes)
		if errors.Join(e1, e2, e3, e4) != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		_, buildErr := qualification.VerifySoulsBuildReceiptV3(policy, soulsRoot, soulsBundle, qualificationJSON, soulsPackageSHA, now)
		if buildErr != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		release, err = qualification.VerifyReleaseAttestationV3(policy, trustedRootJSON, bundleJSON, qualificationJSON, *bundleSHA, now)
		if err == nil {
			err = qualification.VerifyReleasedReportsV3(release, policy, qualificationJSON,
				protectedEnvelope, cooperativeEnvelope, protectedExecution, cooperativeExecution,
				protectedCommitment, cooperativeCommitment, machineRoot, now)
		}
	} else if *bridgeV2 {
		build, buildErr := qualification.VerifySoulsBuildReceiptV2(policy, soulsRoot, soulsBundle, qualificationJSON, soulsPackageSHA, now)
		if buildErr != nil {
			fmt.Fprintln(stderr, qualification.ErrUnqualified)
			return 1
		}
		release, err = qualification.VerifyReleaseAttestationV2(policy, trustedRootJSON, bundleJSON, qualificationJSON, *bundleSHA, now)
		if err == nil {
			err = qualification.VerifyReleasedReportsV2(release, policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, build, now)
		}
	} else {
		release, err = qualification.VerifyReleaseAttestation(policy, trustedRootJSON, bundleJSON, qualificationJSON, *bundleSHA, now)
		if err == nil {
			err = qualification.VerifyReleasedReports(release, policy, qualificationJSON, [][]byte{protectedEnvelope, cooperativeEnvelope}, now)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	qualificationDigest := sha256.Sum256(qualificationJSON)
	result := struct {
		SchemaVersion              int      `json:"schema_version"`
		BundleSHA256               string   `json:"bundle_sha256"`
		QualificationSHA           string   `json:"qualification_sha256"`
		HostReportSHA256s          []string `json:"host_report_sha256s"`
		HostEnvelopeSHA256s        []string `json:"host_envelope_sha256s,omitempty"`
		PolicySHA                  string   `json:"policy_sha256,omitempty"`
		PolicyEnvelopeSHA          string   `json:"policy_envelope_sha256,omitempty"`
		SoulsBuildBundleSHA        string   `json:"souls_build_bundle_sha256,omitempty"`
		SoulsPackageSHA            string   `json:"souls_package_sha256,omitempty"`
		SoulsSourceTree            string   `json:"souls_source_tree,omitempty"`
		ExecutionCompletionSHA256s []string `json:"execution_completion_sha256s,omitempty"`
		CompletedRunSHA256s        []string `json:"completed_run_sha256s,omitempty"`
	}{SchemaVersion: 1, BundleSHA256: *bundleSHA, QualificationSHA: "sha256:" + hex.EncodeToString(qualificationDigest[:]), HostReportSHA256s: release.HostReportDigests()}
	if *bridgeV2 || *hostV3 {
		if *hostV3 {
			result.SchemaVersion = 3
			sha := func(raw []byte) string { sum := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(sum[:]) }
			result.ExecutionCompletionSHA256s = []string{sha(protectedExecution), sha(cooperativeExecution)}
			result.CompletedRunSHA256s = []string{sha(protectedCommitment), sha(cooperativeCommitment)}
		} else {
			result.SchemaVersion = 2
		}
		result.HostEnvelopeSHA256s = release.HostEnvelopeDigests()
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
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	return 0
}
