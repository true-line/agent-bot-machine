//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/qualification"
	"golang.org/x/sys/unix"
)

func stage2aInventoryFixtureV3(t *testing.T) (stage2aAdminSnapshots,
	Stage2aMeasurementBinding, []Stage2aDefinitionRecord, Stage2aLaunchInputRecords) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("A inventory producer requires nonroot effective UID")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	namespace := filepath.Join(base, "snapshots")
	if err := os.Mkdir(namespace, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(namespace, 0750); err != nil {
		t.Fatal(err)
	}
	var ns unix.Stat_t
	if err := unix.Stat(namespace, &ns); err != nil {
		t.Fatal(err)
	}
	a := stage2aAdminSnapshots{uid: ns.Uid, runnerReadGID: ns.Gid, namespace: namespace,
		namespaceDev: ns.Dev, namespaceInode: ns.Ino, namespaceBirth: ns.Btim,
		verifyInstalledGroup: func() error { return nil }}
	source, definition := stage2aObservedFixture(t)
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	definitionID, definitionDigest, err := publishStage2aAdminSnapshot(a, source, ns.Uid, ns.Gid,
		"snap_111111111111111111111111", definition)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage2aCleanPrivateStage(definitionID.RootPath) })
	launch := stage2aLaunchFixture(t)
	runtimeRoot := filepath.Join(namespace, "snap_222222222222222222222222")
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	oldToNew := map[string]string{}
	for i := range launch.Files {
		file := &launch.Files[i]
		var body []byte
		switch file.Path {
		case "host/adapters.json":
			body = []byte(`{"selected":"fixture-adapter"}`)
		case "host/installation.json":
			body = []byte(`{"id":"fixture-installation"}`)
		default:
			body = []byte("installed-" + file.Path)
		}
		path := filepath.Join(runtimeRoot, file.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		parsedMode, err := strconv.ParseUint(file.Mode, 8, 32)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(parsedMode)); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		newDigest := fmt.Sprintf("sha256:%x", sum)
		oldToNew["sha256:"+file.SHA256] = newDigest
		size := uint64(len(body))
		file.Size = &size
		file.SHA256 = strings.TrimPrefix(newDigest, "sha256:")
	}
	for key, value := range launch.ComponentDigests {
		launch.ComponentDigests[key] = oldToNew[value]
	}
	launch.SandboxPolicyDigest = oldToNew[launch.SandboxPolicyDigest]
	for _, dir := range []string{"bin", "host", "policy", ""} {
		if err := os.Chmod(filepath.Join(runtimeRoot, dir), 0555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { stage2aCleanPrivateStage(runtimeRoot) })
	fd, err := unix.Open(runtimeRoot, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	launchID, _, err := stage2aSnapshotIdentity(fd, ns.Uid, ns.Gid)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	launch.SelectedCommand = filepath.Join(runtimeRoot, "bin/node")
	launch.Argv[0] = launch.SelectedCommand
	launch.Argv[1] = filepath.Join(definitionID.RootPath, "Contents/opt/quickstart-check.mjs")
	launchDigest, _, err := Stage2aLaunchInputDigest(launch)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := stage2aBindingFixture(t)
	binding.Contract, binding.SchemaVersion = "machine/v2", 2
	binding.SoulArtifactSHA256 = strings.Repeat("b", 64)
	binding.Snapshots.Definition, binding.Snapshots.LaunchInputs = definitionID, launchID
	binding.DefinitionMeasurement, binding.LaunchInputMeasurement = definitionDigest, launchDigest
	return a, binding, definition, launch
}

func TestStage2aInstalledInventoryProducerMatchesOfflineConsumerV3(t *testing.T) {
	a, binding, definition, launch := stage2aInventoryFixtureV3(t)
	stoppedAt := time.Now().Add(-time.Second)
	got, err := buildStage2aInstalledInputEvidenceV3(a, binding, definition, launch)
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Now()
	if len(got.blobs) != 4 || len(got.inventory) == 0 || got.sha256 != stage2aQualificationSHA256(got.inventory) {
		t.Fatal("producer omitted a nested blob or inventory digest")
	}
	root := t.TempDir()
	for _, raw := range got.blobs {
		sum := sha256.Sum256(raw)
		name := fmt.Sprintf("%x", sum)
		dir := filepath.Join(root, "objects", "sha256", name[:2])
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, bindingRaw, err := stage2aBindingDigestForOwner(binding, a.uid)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := qualification.ResolveInstalledInputInventoryV3(root, got.inventory,
		bindingRaw, stoppedAt, signedAt, time.Now().Add(time.Second))
	if err != nil || verified.InventorySHA256 != got.sha256 || verified.FileCount != 17 {
		t.Fatalf("A bytes do not verify offline: %+v %v", verified, err)
	}
	definitionCommand := cloneStage2aLaunch(t, launch)
	definitionCommand.SelectedCommand = filepath.Join(binding.Snapshots.Definition.RootPath,
		"Contents/opt/quickstart-check.mjs")
	definitionCommand.Argv[0] = definitionCommand.SelectedCommand
	definitionBinding := cloneStage2aBinding(t, binding)
	definitionBinding.LaunchInputMeasurement, _, err = Stage2aLaunchInputDigest(definitionCommand)
	if err != nil {
		t.Fatal(err)
	}
	definitionStoppedAt := time.Now().Add(-time.Second)
	definitionEvidence, err := buildStage2aInstalledInputEvidenceV3(a,
		definitionBinding, definition, definitionCommand)
	if err != nil {
		t.Fatalf("A refused approved frozen-definition command: %v", err)
	}
	definitionSignedAt := time.Now()
	for _, raw := range definitionEvidence.blobs {
		sum := sha256.Sum256(raw)
		name := fmt.Sprintf("%x", sum)
		dir := filepath.Join(root, "objects", "sha256", name[:2])
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, definitionBindingRaw, err := stage2aBindingDigestForOwner(definitionBinding, a.uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qualification.ResolveInstalledInputInventoryV3(root, definitionEvidence.inventory,
		definitionBindingRaw, definitionStoppedAt, definitionSignedAt, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("offline verifier refused approved frozen-definition command: %v", err)
	}
	var changed map[string]any
	if err := json.Unmarshal(got.inventory, &changed); err != nil {
		t.Fatal(err)
	}
	rows := changed["opened_files"].([]any)
	rows[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	tampered, _ := json.Marshal(changed)
	if _, err := qualification.ResolveInstalledInputInventoryV3(root, tampered,
		bindingRaw, stoppedAt, signedAt, time.Now().Add(time.Second)); err == nil {
		t.Fatal("offline verifier accepted changed A file hash")
	}
	wrong := a
	wrong.uid++
	if _, err := buildStage2aInstalledInputEvidenceV3(wrong, binding, definition, launch); err == nil {
		t.Fatal("producer accepted a wrong A account")
	}
	node := filepath.Join(binding.Snapshots.LaunchInputs.RootPath, "bin/node")
	if err := os.Chmod(node, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(node, 0555)
	if _, err := buildStage2aInstalledInputEvidenceV3(a, binding, definition, launch); err == nil {
		t.Fatal("producer accepted a writable selected executable")
	}
}

func TestStage2aInstalledInventoryPrivateArchiveV3(t *testing.T) {
	a, binding, definition, launch := stage2aInventoryFixtureV3(t)
	evidence, err := buildStage2aInstalledInputEvidenceV3(a, binding, definition, launch)
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(base, "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(claims, &stat); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{path: claims, uid: stat.Uid, gid: stat.Gid,
		device: stat.Dev, inode: stat.Ino, birthtime: stat.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	uri, sha, err := publishStage2aInstalledInputEvidenceV3(store, evidence)
	if err != nil || sha != evidence.sha256 ||
		uri != "qualification://stage2a/blob/"+strings.TrimPrefix(sha, "sha256:") {
		t.Fatalf("A archive publication failed: %q %q %v", uri, sha, err)
	}
	for _, item := range []struct {
		role string
		raw  []byte
	}{
		{"definition_records", evidence.blobs["definition_records"]},
		{"launch_input_records", evidence.blobs["launch_input_records"]},
		{"host_adapters_json", evidence.blobs["host_adapters_json"]},
		{"host_installation_json", evidence.blobs["host_installation_json"]},
		{"installed_inputs", evidence.inventory},
	} {
		ref := stage2aInstalledInputRef(item.role, item.raw)
		observed, err := qualification.ResolveGateObjectV3(claims, ref.URI, ref.SHA256, 4<<20)
		if err != nil || string(observed) != string(item.raw) {
			t.Fatalf("A archive object %s differs: %v", item.role, err)
		}
		name := strings.TrimPrefix(ref.SHA256, "sha256:")
		path := filepath.Join(claims, "objects", "sha256", name[:2], name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode() != 0600 {
			t.Fatalf("archive object %s lacks private regular mode: %v", item.role, err)
		}
	}
	if _, _, err := publishStage2aInstalledInputEvidenceV3(store, evidence); err != nil {
		t.Fatalf("identical content-addressed replay refused: %v", err)
	}
	definitionRaw := evidence.blobs["definition_records"]
	definitionName := strings.TrimPrefix(stage2aQualificationSHA256(definitionRaw), "sha256:")
	definitionPath := filepath.Join(claims, "objects", "sha256", definitionName[:2], definitionName)
	changed := append([]byte(nil), definitionRaw...)
	changed[0] ^= 1
	if err := os.WriteFile(definitionPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publishStage2aInstalledInputEvidenceV3(store, evidence); err == nil {
		t.Fatal("A archive reused a changed same-name object")
	}
	wrong := store
	wrong.uid++
	if _, _, err := publishStage2aInstalledInputEvidenceV3(wrong, evidence); err == nil {
		t.Fatal("archive publisher accepted the wrong A account")
	}
	symlinked := filepath.Join(base, "symlinked-claims")
	if err := os.Mkdir(symlinked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(claims, filepath.Join(symlinked, "objects")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(symlinked, &stat); err != nil {
		t.Fatal(err)
	}
	symlinkStore := stage2aAdminClaimStore{path: symlinked, uid: stat.Uid, gid: stat.Gid,
		device: stat.Dev, inode: stat.Ino, birthtime: stat.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	if _, _, err := publishStage2aInstalledInputEvidenceV3(symlinkStore, evidence); err == nil {
		t.Fatal("archive publisher followed a substituted objects directory")
	}
}
