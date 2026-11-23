package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func stage2aHSourceTestDigestV3(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

func stage2aHSourceTestCanonicalV3(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func stage2aHSourceTestTarV3(t *testing.T, files map[string][]byte, link bool) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, dir := range []string{"hq/", "hq/governance/", "hq/hq/", "hq/vendor/",
		"hq/vendor/soul-contracts/", "hq/vendor/soul-contracts/fixtures/",
		"hq/vendor/soul-contracts/fixtures/negative/", "hq/vendor/soul-contracts/schemas/"} {
		if err := w.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir,
			Mode: 0755, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"governance/interim-release.json", "governance/soul-contracts.json", "hq/index.mjs",
		"vendor/soul-contracts/fixtures/negative/synthetic.bad.json",
		"vendor/soul-contracts/schemas/synthetic.json"} {
		data := files[path]
		if err := w.WriteHeader(&tar.Header{Name: "hq/" + path,
			Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0644,
			Uid: 0, Gid: 0, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if link {
		if err := w.WriteHeader(&tar.Header{Name: "hq/unreviewed-link", Typeflag: tar.TypeSymlink,
			Linkname: "hq/index.mjs", Mode: 0777, Uid: 0, Gid: 0,
			ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestStage2aHSourceV3RawArtifactClosure(t *testing.T) {
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const contractsCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const fixturePath = "vendor/soul-contracts/fixtures/negative/synthetic.bad.json"
	const schemaPath = "vendor/soul-contracts/schemas/synthetic.json"
	fixture, schema, entry, node := []byte(`{"bad":true}`), []byte(`{"type":"object"}`),
		[]byte("export default 1;\n"), []byte("node-binary")
	fullContracts := map[string]stage2aHSourceContractRowV3{
		"fixtures/negative/synthetic.bad.json": {SHA256: stage2aHSourceTestDigestV3(fixture)[7:], Size: int64(len(fixture)), Mode: "100644"},
		"schemas/synthetic.json":               {SHA256: stage2aHSourceTestDigestV3(schema)[7:], Size: int64(len(schema)), Mode: "100644"},
	}
	runtimeContracts := map[string]stage2aHSourceContractRowV3{
		"schemas/synthetic.json": fullContracts["schemas/synthetic.json"],
	}
	fullDigest, _ := stage2aHSourceManifestDigestV3(fullContracts)
	runtimeDigest, _ := stage2aHSourceManifestDigestV3(runtimeContracts)
	metadata := stage2aHSourceTestCanonicalV3(t, map[string]any{
		"schema_version": 1, "hq_commit": commit, "contracts_commit": contractsCommit,
		"contracts_digest": fullDigest, "target_platform": "darwin",
		"owner_control_capability": "darwin-owner-control/v2",
		"contracts_runtime": map[string]any{"digest_algorithm": "sha256-manifest-v1",
			"digest": runtimeDigest, "files": 1, "excluded_hq_release_paths": []string{fixturePath}},
	})
	contractsPin := stage2aHSourceTestCanonicalV3(t, stage2aHSourcePinFileV3{
		SchemaVersion: 1, Repository: "https://github.com/true-line/soul-contracts.git",
		Tag: "v0.10.0", Commit: contractsCommit, Paths: []string{"errors", "fixtures", "schemas"},
		DigestAlgorithm: "sha256-manifest-v1", Digest: fullDigest, Files: 2,
	})
	files := map[string][]byte{"governance/interim-release.json": metadata,
		"governance/soul-contracts.json": contractsPin, "hq/index.mjs": entry,
		fixturePath: fixture, schemaPath: schema}
	sourceRows := []stage2aHSourceManifestRowV3{
		{Path: "governance/interim-release.json", SHA256: stage2aHSourceTestDigestV3(metadata)},
		{Path: "governance/soul-contracts.json", SHA256: stage2aHSourceTestDigestV3(contractsPin)},
		{Path: "hq/index.mjs", SHA256: stage2aHSourceTestDigestV3(entry)},
		{Path: fixturePath, SHA256: stage2aHSourceTestDigestV3(fixture)},
		{Path: schemaPath, SHA256: stage2aHSourceTestDigestV3(schema)},
	}
	sourceManifest := stage2aHSourceTestCanonicalV3(t, sourceRows)
	inv := stage2aDomainInventoryV3{Contract: "machine/v3", Kind: "stage2a-domain-inventory",
		SchemaVersion: 3, Domain: "H-code", InstallationID: "hq-test-1",
		Limits: stage2aDomainInventoryLimitsV3{MaxFiles: 512,
			MaxFileBytes: stage2aV3MaxInventoryFileBytes, MaxTotalBytes: stage2aV3MaxInventoryTotalBytes},
		Directories: []stage2aDomainDirectoryV3{
			{Path: "bin", Kind: "directory", Mode: "0550"},
			{Path: "governance", Kind: "directory", Mode: "0550"},
			{Path: "hq", Kind: "directory", Mode: "0550"},
			{Path: "vendor", Kind: "directory", Mode: "0550"},
			{Path: "vendor/soul-contracts", Kind: "directory", Mode: "0550"},
			{Path: "vendor/soul-contracts/schemas", Kind: "directory", Mode: "0550"},
		},
		Files: []stage2aDomainFileV3{
			{Path: "bin/node", Kind: "regular", Mode: "0550", SizeBytes: uint64(len(node)), SHA256: stage2aHSourceTestDigestV3(node), ComponentID: "node", ReleasePath: "bin/node"},
			{Path: "governance/interim-release.json", Kind: "regular", Mode: "0440", SizeBytes: uint64(len(metadata)), SHA256: stage2aHSourceTestDigestV3(metadata), ComponentID: "hq", ReleasePath: "governance/interim-release.json"},
			{Path: "governance/soul-contracts.json", Kind: "regular", Mode: "0440", SizeBytes: uint64(len(contractsPin)), SHA256: stage2aHSourceTestDigestV3(contractsPin), ComponentID: "hq", ReleasePath: "governance/soul-contracts.json"},
			{Path: "hq/index.mjs", Kind: "regular", Mode: "0440", SizeBytes: uint64(len(entry)), SHA256: stage2aHSourceTestDigestV3(entry), ComponentID: "hq", ReleasePath: "hq/index.mjs"},
			{Path: schemaPath, Kind: "regular", Mode: "0440", SizeBytes: uint64(len(schema)), SHA256: stage2aHSourceTestDigestV3(schema), ComponentID: "hq", ReleasePath: schemaPath},
		},
	}
	for _, file := range inv.Files {
		inv.TotalBytes += file.SizeBytes
	}
	invRaw := stage2aHSourceTestCanonicalV3(t, inv)
	_, invDigest, err := stage2aDomainInventoryDigestV3(invRaw)
	if err != nil {
		t.Fatalf("fixture inventory invalid: %v", err)
	}
	archive := stage2aHSourceTestTarV3(t, files, false)
	pins := stage2aHSourceReleasePinsV3{InstallationID: inv.InstallationID,
		InventoryDigest: invDigest, Limits: inv.Limits, HQCommit: commit,
		HQArtifactSHA256:     stage2aHSourceTestDigestV3(archive),
		NodeArtifactSHA256:   stage2aHSourceTestDigestV3(node),
		SourceManifestSHA256: stage2aHSourceTestDigestV3(sourceManifest),
		ContractsTag:         "v0.10.0", ContractsCommit: contractsCommit, ContractsFullDigest: fullDigest,
		ContractsFullFiles: 2, ContractsRuntimeDigest: runtimeDigest,
		ContractsRuntimeFiles: 1, Excluded: []string{fixturePath}}
	check := func(raw []byte, nodeBytes []byte, p stage2aHSourceReleasePinsV3) error {
		return stage2aVerifyHSourceBytesV3(invRaw, sourceManifest,
			bytes.NewReader(raw), int64(len(raw)), bytes.NewReader(nodeBytes), int64(len(nodeBytes)), p)
	}
	if err := check(archive, node, pins); err != nil {
		t.Fatalf("authentic H source refused: %v", err)
	}
	// A full release digest does not justify omitting a runtime schema from H.
	// Even a mutually repinned inventory and source manifest must refuse it.
	if inv.Files[len(inv.Files)-1].Path != schemaPath || sourceRows[len(sourceRows)-1].Path != schemaPath {
		t.Fatal("schema must be the final synthetic source row")
	}
	missingSchemaInv := inv
	missingSchemaInv.Directories = append([]stage2aDomainDirectoryV3(nil), inv.Directories[:3]...)
	missingSchemaInv.Files = append([]stage2aDomainFileV3(nil), inv.Files[:len(inv.Files)-1]...)
	missingSchemaInv.TotalBytes -= uint64(len(schema))
	missingSchemaInvRaw := stage2aHSourceTestCanonicalV3(t, missingSchemaInv)
	_, missingSchemaInvDigest, err := stage2aDomainInventoryDigestV3(missingSchemaInvRaw)
	if err != nil {
		t.Fatalf("missing-schema inventory must be valid by itself: %v", err)
	}
	missingSchemaManifest := stage2aHSourceTestCanonicalV3(t, sourceRows[:len(sourceRows)-1])
	missingSchemaPins := pins
	missingSchemaPins.InventoryDigest = missingSchemaInvDigest
	missingSchemaPins.SourceManifestSHA256 = stage2aHSourceTestDigestV3(missingSchemaManifest)
	if err := stage2aVerifyHSourceBytesV3(missingSchemaInvRaw, missingSchemaManifest,
		bytes.NewReader(archive), int64(len(archive)), bytes.NewReader(node), int64(len(node)), missingSchemaPins); err == nil {
		t.Fatal("accepted a missing runtime Contracts schema under repinned inventory and manifest")
	}
	// The release also must not silently omit an HQ runtime module from
	// both the reviewed source projection and the installed inventory.
	if inv.Files[3].Path != "hq/index.mjs" || sourceRows[2].Path != "hq/index.mjs" {
		t.Fatal("HQ module must be the selected synthetic source row")
	}
	missingHQInv := inv
	missingHQInv.Files = append(append([]stage2aDomainFileV3(nil), inv.Files[:3]...), inv.Files[4:]...)
	missingHQInv.Directories = append(append([]stage2aDomainDirectoryV3(nil), inv.Directories[:2]...), inv.Directories[3:]...)
	missingHQInv.TotalBytes -= uint64(len(entry))
	missingHQInvRaw := stage2aHSourceTestCanonicalV3(t, missingHQInv)
	_, missingHQInvDigest, err := stage2aDomainInventoryDigestV3(missingHQInvRaw)
	if err != nil {
		t.Fatalf("missing-HQ inventory must be valid by itself: %v", err)
	}
	missingHQRows := append(append([]stage2aHSourceManifestRowV3(nil), sourceRows[:2]...), sourceRows[3:]...)
	missingHQManifest := stage2aHSourceTestCanonicalV3(t, missingHQRows)
	missingHQPins := pins
	missingHQPins.InventoryDigest = missingHQInvDigest
	missingHQPins.SourceManifestSHA256 = stage2aHSourceTestDigestV3(missingHQManifest)
	if err := stage2aVerifyHSourceBytesV3(missingHQInvRaw, missingHQManifest,
		bytes.NewReader(archive), int64(len(archive)), bytes.NewReader(node), int64(len(node)), missingHQPins); err == nil {
		t.Fatal("accepted a missing HQ module under repinned inventory and manifest")
	}
	changed := map[string][]byte{}
	for path, raw := range files {
		changed[path] = raw
	}
	changed[fixturePath] = []byte(`{"bad":false}`)
	changedArchive := stage2aHSourceTestTarV3(t, changed, false)
	changedPins := pins
	changedPins.HQArtifactSHA256 = stage2aHSourceTestDigestV3(changedArchive)
	if err := check(changedArchive, node, changedPins); err == nil {
		t.Fatal("accepted a changed omitted fixture under a repinned archive hash")
	}
	linkedArchive := stage2aHSourceTestTarV3(t, files, true)
	linkedPins := pins
	linkedPins.HQArtifactSHA256 = stage2aHSourceTestDigestV3(linkedArchive)
	if err := check(linkedArchive, node, linkedPins); err == nil {
		t.Fatal("accepted a symlink under a repinned archive hash")
	}
	withTrailer := append(append([]byte(nil), archive...), byte(1))
	trailerPins := pins
	trailerPins.HQArtifactSHA256 = stage2aHSourceTestDigestV3(withTrailer)
	if err := check(withTrailer, node, trailerPins); err == nil {
		t.Fatal("accepted nonzero trailing archive bytes")
	}
	changedCommit := pins
	changedCommit.HQCommit = "cccccccccccccccccccccccccccccccccccccccc"
	if err := check(archive, node, changedCommit); err == nil {
		t.Fatal("accepted metadata from a different HQ commit")
	}
	changedInventory := pins
	changedInventory.InventoryDigest = "sha256:" + fmt.Sprintf("%064x", 1)
	if err := check(archive, node, changedInventory); err == nil {
		t.Fatal("accepted a different H inventory pin")
	}
	changedRuntime := pins
	changedRuntime.ContractsRuntimeDigest = "sha256:" + fmt.Sprintf("%064x", 2)
	if err := check(archive, node, changedRuntime); err == nil {
		t.Fatal("accepted a different selected Contracts digest")
	}
	changedTag := pins
	changedTag.ContractsTag = "v0.11.0"
	if err := check(archive, node, changedTag); err == nil {
		t.Fatal("accepted a different Contracts tag")
	}
	changedExclusion := pins
	changedExclusion.Excluded = nil
	if err := check(archive, node, changedExclusion); err == nil {
		t.Fatal("accepted a missing reviewed omission")
	}
	if err := check(archive, []byte("changed node"), pins); err == nil {
		t.Fatal("accepted changed Node bytes")
	}
}
