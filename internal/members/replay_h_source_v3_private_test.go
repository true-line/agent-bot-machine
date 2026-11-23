package members

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aHSourceV3PrivateReplay(t *testing.T) {
	root := os.Getenv("STAGE2A_H_REPLAY_ROOT")
	if root == "" {
		t.Skip("private H source not supplied")
	}
	raw, err := os.ReadFile(filepath.Join(root, "mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Excluded   []string `json:"excluded_hq_release_paths"`
		Components []struct {
			ID     string `json:"component_id"`
			Path   string `json:"release_artifact_path"`
			SHA256 string `json:"release_artifact_sha256"`
		} `json:"components"`
		HQCommit         string `json:"hq_source_commit"`
		ContractsTag     string `json:"contracts_tag"`
		PrivateCandidate bool   `json:"private_candidate"`
		ContractsCommit  string `json:"contracts_commit"`
		FullDigest       string `json:"contracts_full_digest"`
		FullFiles        int    `json:"contracts_full_files"`
		RuntimeDigest    string `json:"contracts_runtime_subset_digest"`
		RuntimeFiles     int    `json:"contracts_runtime_files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	invRaw, err := os.ReadFile(filepath.Join(root, "h-code-inventory.candidate.jcs.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, invDigest, err := stage2aDomainInventoryDigestV3(invRaw)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "hq-source-manifest.jcs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hq, node *os.File
	var hqDigest, nodeDigest string
	for _, c := range m.Components {
		f, err := os.Open(c.Path)
		if err != nil {
			t.Fatal(err)
		}
		switch c.ID {
		case "hq":
			hq, hqDigest = f, c.SHA256
		case "node":
			node, nodeDigest = f, c.SHA256
		default:
			t.Fatal("bad component")
		}
	}
	defer hq.Close()
	defer node.Close()
	hs, err := hq.Stat()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := node.Stat()
	if err != nil {
		t.Fatal(err)
	}
	pins := stage2aHSourceReleasePinsV3{InstallationID: inv.InstallationID, InventoryDigest: invDigest, Limits: inv.Limits,
		HQCommit: m.HQCommit, HQArtifactSHA256: hqDigest, NodeArtifactSHA256: nodeDigest,
		SourceManifestSHA256: stage2aHSourceTestDigestV3(manifest), ContractsTag: m.ContractsTag, PrivateCandidate: m.PrivateCandidate, ContractsCommit: m.ContractsCommit,
		ContractsFullDigest: m.FullDigest, ContractsFullFiles: m.FullFiles, ContractsRuntimeDigest: m.RuntimeDigest,
		ContractsRuntimeFiles: m.RuntimeFiles, Excluded: m.Excluded}
	if err := stage2aVerifyHSourceBytesV3(invRaw, manifest, hq, hs.Size(), node, ns.Size(), pins); err != nil {
		t.Fatal(err)
	}
}
