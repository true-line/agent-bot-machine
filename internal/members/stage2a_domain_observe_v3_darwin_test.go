//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aObserveDomainV3At(t *testing.T) {
	if os.Getuid() < 400 {
		t.Skip("requires a nonroot test UID")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "snap_aaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"bin", "hq"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	inv := stage2aV3TestInventory()
	for i := range inv.Files {
		file := &inv.Files[i]
		data := []byte("reviewed " + file.Path)
		file.SizeBytes = uint64(len(data))
		file.SHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
		if err := os.WriteFile(filepath.Join(root, file.Path), data, 0600); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0440)
		if file.Mode == "0550" {
			mode = 0550
		}
		if err := os.Chmod(filepath.Join(root, file.Path), mode); err != nil {
			t.Fatal(err)
		}
	}
	inv.TotalBytes = inv.Files[0].SizeBytes + inv.Files[1].SizeBytes
	for _, dir := range inv.Directories {
		if err := os.Chmod(filepath.Join(root, dir.Path), 0550); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parent, 0700)
		_ = os.Chmod(root, 0700)
		for _, dir := range inv.Directories {
			_ = os.Chmod(filepath.Join(root, dir.Path), 0700)
		}
		for _, file := range inv.Files {
			_ = os.Chmod(filepath.Join(root, file.Path), 0600)
		}
	})
	raw := stage2aV3TestCanonical(t, inv)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if private, _, err := stage2aObserveDomainV3AtMode(root, uint32(os.Getuid()),
		uint32(os.Getgid()), raw, true); err != nil || private.Mode != "0700" {
		t.Fatalf("valid private staging root refused: %+v %v", private, err)
	}
	if err := os.Chmod(root, 0555); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(parent, "inventory.jcs")
	if err := os.WriteFile(sidecar, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sidecar, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	identity, digest, err := stage2aObserveDomainV3At(root, uint32(os.Getuid()), uint32(os.Getgid()), raw)
	if err != nil || identity.RootPath != root || identity.Mode != "0555" || digest == "" {
		t.Fatalf("valid frozen domain refused: identity=%+v digest=%q err=%v", identity, digest, err)
	}
	_, err = stage2aObserveInstalledDomainV3(root, sidecar, uint32(os.Getuid()),
		uint32(os.Getuid()+1), uint32(os.Getgid()),
		"sha256:1111111111111111111111111111111111111111111111111111111111111111", digest)
	if err == nil {
		t.Fatal("unprovisioned reader group was accepted as an installed domain")
	}
	if err := os.Chmod(filepath.Join(root, "hq"), 0750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stage2aObserveDomainV3At(root, uint32(os.Getuid()), uint32(os.Getgid()), raw); err == nil {
		t.Fatal("accepted changed directory mode")
	}
}

func TestStage2aDomainNamesV3SeparateHAndR(t *testing.T) {
	hParent, hRoot, hSidecar, err := stage2aDomainNamesV3("H-code", "install-one")
	if err != nil || hParent == "" || len(hRoot) != len("snap_")+24 ||
		hSidecar == hRoot || filepath.Dir(hParent) != stage2aFrozenSnapshotParent {
		t.Fatalf("invalid H domain paths: %q %q %q %v", hParent, hRoot, hSidecar, err)
	}
	rParent, rRoot, rSidecar, err := stage2aDomainNamesV3("R-runtime", "install-one")
	if err != nil || hParent == rParent || hRoot == rRoot || hSidecar == rSidecar {
		t.Fatalf("H and R paths overlap: %q %q %q %v", rParent, rRoot, rSidecar, err)
	}
	if _, _, _, err := stage2aDomainNamesV3("H-code", "../escape"); err == nil {
		t.Fatal("accepted path traversal installation ID")
	}
}

func TestStage2aPreparedV3SidecarExactBytes(t *testing.T) {
	if os.Getuid() < 400 {
		t.Skip("requires a nonroot test UID")
	}
	wrapper, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(wrapper, "inventory")
	raw := stage2aV3TestCanonical(t, stage2aV3TestInventory())
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	parentFD, err := unix.Open(wrapper, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	fd, err := stage2aOpenPreparedV3Sidecar(parentFD, path, uint32(os.Getuid()), uint32(os.Getgid()), raw)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	if fd, err := stage2aOpenPreparedV3Sidecar(parentFD, path, uint32(os.Getuid()),
		uint32(os.Getgid()), append(append([]byte(nil), raw...), ' ')); err == nil {
		unix.Close(fd)
		t.Fatal("accepted changed staged sidecar bytes")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if fd, err := stage2aOpenPreparedV3Sidecar(parentFD, path, uint32(os.Getuid()),
		uint32(os.Getgid()), raw); err == nil {
		unix.Close(fd)
		t.Fatal("accepted staged sidecar with final mode")
	}
}

func TestStage2aDomainSealRequestV3UsesInstalledLauncherDigest(t *testing.T) {
	inv := stage2aV3TestInventory()
	raw := stage2aV3TestCanonical(t, inv)
	_, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	namespace, _, _, err := stage2aDomainNamesV3(inv.Domain, inv.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(namespace, ".stage2a-aaaaaaaaaaaaaaaaaaaaaaaa")
	r := stage2aDomainSealRequestV3{
		Schema: stage2aDomainSealSchemaV3, Domain: inv.Domain, InstallationID: inv.InstallationID,
		MachineAccount: "_machine_a", MachineUID: 620, MachineGID: 620,
		ReaderAccount: "_hq_h", ReaderUID: 621, ReaderGID: 621,
		OwnerPlanDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		ReviewedDigest:  digest,
		Namespace:       stage2aInstalledDirectory{Path: namespace, Device: 1, Inode: "1", BirthSeconds: 1},
		LauncherSHA256:  "2222222222222222222222222222222222222222222222222222222222222222",
		Prepared: stage2aPreparedSnapshot{WrapperPath: wrapper,
			Wrapper: Stage2aSnapshotIdentity{RootPath: wrapper, OwnerUID: 620, OwnerGID: 621, Mode: "0700"},
			Stage:   Stage2aSnapshotIdentity{RootPath: filepath.Join(wrapper, "snapshot"), OwnerUID: 620, OwnerGID: 621, Mode: "0700"},
			Digest:  digest},
		Inventory: raw,
	}
	if err := r.validate(); err != nil {
		t.Fatalf("unprefixed installed launcher digest refused: %v", err)
	}
	rawRequest, err := json.Marshal(r)
	if err != nil || stage2aStrictJSONBounded(rawRequest, 3<<20, stage2aV3MaxJSONNodes) != nil {
		t.Fatalf("valid A handoff JSON refused: %v", err)
	}
	var decoded stage2aDomainSealRequestV3
	if err := json.Unmarshal(rawRequest, &decoded); err != nil || decoded.validate() != nil {
		t.Fatalf("A handoff round-trip refused: %v", err)
	}
	r.LauncherSHA256 = "sha256:" + r.LauncherSHA256
	if err := r.validate(); err == nil {
		t.Fatal("accepted incompatible prefixed launcher digest")
	}
}

func TestStage2aDomainSealReplyV3RoundTrip(t *testing.T) {
	ref := stage2aDomainInventoryRefV3{Contract: "machine/v3", Kind: "stage2a-inventory-ref",
		SchemaVersion: 3, Domain: "H-code", InstallationID: "hq-test-1",
		Snapshot: stage2aDomainNodeRefV3{Path: "/private/test/snap_aaa", Device: "1", Inode: "2",
			Generation: "3", BirthtimeNS: "4", OwnerUID: 620, OwnerGID: 621, Mode: "0555"},
		Sidecar: stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{
			Path: "/private/test/inventory.jcs", Device: "1", Inode: "5", Generation: "6",
			BirthtimeNS: "7", OwnerUID: 620, OwnerGID: 621, Mode: "0440"}, SizeBytes: 100,
			SHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
	}
	raw, err := json.Marshal(stage2aInstallSealReply{DomainV3: &ref})
	if err != nil {
		t.Fatal(err)
	}
	var decoded stage2aInstallSealReply
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.DomainV3 == nil ||
		*decoded.DomainV3 != ref || decoded.DomainV3.Sidecar.Path != ref.Sidecar.Path {
		t.Fatalf("A reply lost v3 sidecar identity: %s %v", raw, err)
	}
}

func TestStage2aAdminDirectoryTraverseOnlyParent(t *testing.T) {
	if os.Getuid() < 400 {
		t.Skip("requires nonroot test UID")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "namespace")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
	fd, err := unix.Open(parent, stage2aDirectoryOpenFlags, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatal("read-only descriptor unexpectedly opened execute-only parent")
	}
	dir, err := openStage2aAdminDirectory(child, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("A could not traverse execute-only ancestor: %v", err)
	}
	dir.Close()
}
