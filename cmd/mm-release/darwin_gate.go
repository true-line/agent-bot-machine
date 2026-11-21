package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
)

var releaseRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

// writeDarwinGateLink renders the relationship only after verifySignedCmd has
// established that the archives match outside the permitted signing changes.
func writeDarwinGateLink(w io.Writer, gatePath, revision, version, unsignedArchive, signedArchive string, unsignedCLI, signedCLI archiveEntry) error {
	if gatePath == "" || !releaseRevision.MatchString(revision) {
		return fmt.Errorf("-darwin-gate requires -source-revision with the full tagged commit SHA")
	}
	raw, err := os.ReadFile(gatePath)
	if err != nil {
		return err
	}
	var gate struct {
		SchemaVersion                 int `json:"schema_version"`
		Kind, Version, Target, Result string
		Emulated                      *bool
		SourceRevision                string `json:"source_revision"`
		BinarySHA256                  string `json:"binary_sha256"`
		Artifact                      struct{ Name, SHA256 string }
	}
	if err := json.Unmarshal(raw, &gate); err != nil {
		return fmt.Errorf("Darwin gate receipt: %w", err)
	}
	if gate.SchemaVersion != 1 || gate.Kind != "s6-release-gate" || gate.Result != "pass" ||
		gate.Target != "darwin/arm64" || gate.Emulated == nil || *gate.Emulated {
		return fmt.Errorf("expected a passing native Darwin arm64 release gate")
	}
	if gate.Version != version || gate.SourceRevision != revision {
		return fmt.Errorf("Darwin gate version or source revision differs from the tagged build")
	}
	if gate.Artifact.Name != darwinArchiveName(version) || gate.Artifact.SHA256 != unsignedArchive ||
		gate.BinarySHA256 != sha256Hex(unsignedCLI.Data) {
		return fmt.Errorf("Darwin gate archive or executable differs from the verified pre-sign build")
	}

	_, err = fmt.Fprintf(w, "\n## Darwin arm64 signed download\n\n"+
		"The native release gate ran the pre-sign build at `%s`. The release verifier compared the signed archive with that build.\n\n"+
		"| SHA-256 | Pre-sign build tested by the native gate | Signed download |\n"+
		"| --- | --- | --- |\n"+
		"| `%s` | `%s` | `%s` |\n"+
		"| `managed-machine` | `%s` | `%s` |\n\n"+
		"Original `release-gate-darwin-arm64.json` SHA-256 `%s`.\n",
		revision, gate.Artifact.Name, unsignedArchive, signedArchive, gate.BinarySHA256, sha256Hex(signedCLI.Data), sha256Hex(raw))
	return err
}
