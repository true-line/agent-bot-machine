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

const usage = "usage: mm-qualification-verify-release -owner-root FILE -owner-key-id ID -policy-envelope FILE -trusted-root FILE -bundle FILE -bundle-sha256 SHA256 -qualification FILE -protected-envelope FILE -cooperative-envelope FILE"

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

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mm-qualification-verify-release", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
		*qualificationPath == "" || *protectedPath == "" || *cooperativePath == "" {
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
	now := time.Now().UTC()
	// The diagnostic command has no protected persisted policy state. The
	// live Machine acceptance path must separately enforce rollback and
	// independently measure installed inputs before any launch decision.
	policy, err := qualification.VerifyOwnerPolicy(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	release, err := qualification.VerifyReleaseAttestation(policy, trustedRootJSON, bundleJSON, qualificationJSON, *bundleSHA, now)
	if err != nil || qualification.VerifyReleasedReports(release, policy, qualificationJSON, [][]byte{protectedEnvelope, cooperativeEnvelope}, now) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	qualificationDigest := sha256.Sum256(qualificationJSON)
	result := struct {
		SchemaVersion     int      `json:"schema_version"`
		BundleSHA256      string   `json:"bundle_sha256"`
		QualificationSHA  string   `json:"qualification_sha256"`
		HostReportSHA256s []string `json:"host_report_sha256s"`
	}{1, *bundleSHA, "sha256:" + hex.EncodeToString(qualificationDigest[:]), release.HostReportDigests()}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	return 0
}
