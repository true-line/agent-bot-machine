// Command mm-qualification-preflight checks signed qualification inputs before
// a release workflow signs its statement. It is not an adapter launch gate.
// Build this command from an exact reviewed Machine commit and supply the
// owner root from that release's pinned trust material.
package main

import (
	"crypto/ed25519"
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

const usage = "usage: mm-qualification-preflight -owner-root FILE -owner-key-id ID -policy-envelope FILE -qualification FILE -protected-envelope FILE -cooperative-envelope FILE"

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
	fs := flag.NewFlagSet("mm-qualification-preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rootPath := fs.String("owner-root", "", "reviewed owner Ed25519 root as lowercase hex")
	ownerKeyID := fs.String("owner-key-id", "", "owner root identifier")
	policyPath := fs.String("policy-envelope", "", "owner-signed policy envelope")
	qualificationPath := fs.String("qualification", "", "exact qualification.json")
	protectedPath := fs.String("protected-envelope", "", "protected host report envelope")
	cooperativePath := fs.String("cooperative-envelope", "", "cooperative host report envelope")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *rootPath == "" || *ownerKeyID == "" ||
		*policyPath == "" || *qualificationPath == "" || *protectedPath == "" || *cooperativePath == "" {
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
	now := time.Now().UTC()
	// The producer has no Machine persisted revision state. Machine checks
	// rollback independently when it consumes the eventual release bundle.
	policy, err := qualification.VerifyOwnerPolicy(policyEnvelope, *ownerKeyID, ed25519.PublicKey(root), 0, "", now)
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	protectedSHA, cooperativeSHA, err := qualification.VerifyHostReportsForRelease(policy, qualificationJSON, protectedEnvelope, cooperativeEnvelope, now)
	if err != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	result := struct {
		SchemaVersion      int    `json:"schema_version"`
		ProtectedProfile   string `json:"protected_profile"`
		ProtectedSHA       string `json:"protected_report_sha256"`
		CooperativeProfile string `json:"cooperative_profile"`
		CooperativeSHA     string `json:"cooperative_report_sha256"`
	}{1, "managed-protected", protectedSHA, "managed-cooperative", cooperativeSHA}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, qualification.ErrUnqualified)
		return 1
	}
	return 0
}
