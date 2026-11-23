//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

// This optional compatibility replay uses a private source-stage ZIP map.
// It does not authenticate a release, approve an install, or qualify T03.
func TestStage2aRuntimeV3StockZipCompatibility(t *testing.T) {
	path := os.Getenv("STAGE2A_V3_STOCK_ZIP_MAPPING")
	if path == "" {
		t.Skip("private stock ZIP source-stage map not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var mapping struct {
		ArtifactFormat        string                `json:"artifact_format"`
		ComponentID           string                `json:"component_id"`
		MemberCount           int                   `json:"member_count"`
		ReleaseArtifactPath   string                `json:"release_artifact_path"`
		ReleaseArtifactHash   string                `json:"release_artifact_sha256"`
		ProposedInstalledRows []stage2aDomainFileV3 `json:"proposed_installed_files"`
	}
	if json.Unmarshal(raw, &mapping) != nil || mapping.ArtifactFormat != "zip" ||
		mapping.ComponentID != "adapter" || mapping.MemberCount != 2 ||
		len(mapping.ProposedInstalledRows) != 2 {
		t.Fatal("stock adapter ZIP source-stage mapping is not the expected two-file component")
	}
	file, err := os.Open(mapping.ReleaseArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != mapping.ReleaseArtifactHash {
		t.Fatal("stock adapter ZIP bytes differ from the source-stage pin")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Zip(file, st.Size(), mapping.ComponentID,
		stage2aDomainInventoryV3{Files: mapping.ProposedInstalledRows}); err != nil {
		t.Fatalf("stock adapter ZIP does not map to reviewed R rows: %v", err)
	}
	t.Logf("COMPONENT_ONLY stock ZIP mapped %d members, artifact=%s", mapping.MemberCount, mapping.ReleaseArtifactHash)
}
