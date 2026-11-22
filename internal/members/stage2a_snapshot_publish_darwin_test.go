//go:build darwin

package members

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aFrozenNamespaceSeparatesInstallations(t *testing.T) {
	a, err := stage2aFrozenNamespace("fixture-installation-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := stage2aFrozenNamespace("fixture-installation-b")
	if err != nil || a == b || filepath.Dir(a) != stage2aFrozenSnapshotParent ||
		filepath.Dir(b) != stage2aFrozenSnapshotParent {
		t.Fatalf("two installations share a snapshot namespace: %q, %q, %v", a, b, err)
	}
	if _, err := stage2aFrozenNamespace("../other"); err == nil {
		t.Fatal("unreviewed namespace traversal accepted")
	}
	parent := t.TempDir()
	fd, err := unix.Open(parent, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, mode := range []os.FileMode{0700, 0755, 0750} {
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		err := stage2aPrivateSnapshotParent(fd, uint32(os.Getuid()), uint32(os.Getgid()))
		if (mode == 0750) != (err == nil) {
			t.Fatalf("namespace mode %#o unexpectedly accepted/refused: %v", mode, err)
		}
	}
}

func TestStage2aFrozenSnapshotPublishesExactBytesOnce(t *testing.T) {
	source, approved := stage2aObservedFixture(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	name := "snap_111111111111111111111111"
	want, _, err := Stage2aDefinitionDigest(approved)
	if err != nil {
		t.Fatal(err)
	}
	identity, got, err := publishStage2aFrozenAt(source, parent, name,
		uint32(os.Getuid()), uint32(os.Getgid()),
		uint32(os.Getuid()), uint32(os.Getgid()), approved)
	if err != nil || got != want || identity.Mode != "0555" || identity.Inode == "" {
		t.Fatalf("published snapshot mismatch: %s, %v, %+v", got, err, identity)
	}
	if observed, digest, err := observeStage2aFrozenAt(filepath.Join(parent, name),
		uint32(os.Getuid()), uint32(os.Getgid()), approved); err != nil || observed != identity || digest != want {
		t.Fatalf("published snapshot failed descriptor recheck: %s, %v", digest, err)
	}
	if _, _, err := publishStage2aFrozenAt(source, parent, name,
		uint32(os.Getuid()), uint32(os.Getgid()),
		uint32(os.Getuid()), uint32(os.Getgid()), approved); err == nil {
		t.Fatal("exclusive snapshot name reused")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != name {
		t.Fatalf("failed publication left a staging tree: %v, %v", entries, err)
	}
	t.Cleanup(func() {
		for _, dir := range []string{
			filepath.Join(parent, name), filepath.Join(parent, name, "Contents"),
			filepath.Join(parent, name, "Contents/opt"), filepath.Join(parent, name, "Contents/primitives"),
		} {
			_ = os.Chmod(dir, 0700)
		}
	})
}

func TestStage2aFrozenSnapshotRefusesChangedSourceBeforePublish(t *testing.T) {
	source, approved := stage2aObservedFixture(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(source, "Contents/opt/quickstart-check.mjs")
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("CHECKER"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0555); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publishStage2aFrozenAt(source, parent,
		"snap_222222222222222222222222", uint32(os.Getuid()), uint32(os.Getgid()),
		uint32(os.Getuid()), uint32(os.Getgid()), approved); err == nil {
		t.Fatal("changed source published")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("changed source left a published or staged name: %v, %v", entries, err)
	}
}

func TestStage2aFrozenSnapshotRefusesRunnerInaccessibleModes(t *testing.T) {
	for _, tc := range []struct {
		path string
		mode os.FileMode
	}{
		{"Contents/opt", 0500},
		{"Contents/SoulInfo.json", 0400},
	} {
		t.Run(tc.path, func(t *testing.T) {
			source, approved := stage2aObservedFixture(t)
			if err := os.Chmod(filepath.Join(source, tc.path), tc.mode); err != nil {
				t.Fatal(err)
			}
			for i := range approved {
				if approved[i].Path == tc.path {
					approved[i].Mode = fmt.Sprintf("%04o", tc.mode)
				}
			}
			parent := t.TempDir()
			if err := os.Chmod(parent, 0750); err != nil {
				t.Fatal(err)
			}
			if _, _, err := publishStage2aFrozenAt(source, parent,
				"snap_444444444444444444444444", uint32(os.Getuid()), uint32(os.Getgid()),
				uint32(os.Getuid()), uint32(os.Getgid()), approved); err == nil {
				t.Fatal("runner-inaccessible approved mode published")
			}
		})
	}
}

func TestStage2aFrozenSnapshotRejectsUnreviewedNameAndUserEntry(t *testing.T) {
	source, approved := stage2aObservedFixture(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", "snap_ABCDEF", "snap_111111111111111111111111/other"} {
		if _, _, err := publishStage2aFrozenAt(source, parent, name,
			uint32(os.Getuid()), uint32(os.Getgid()),
			uint32(os.Getuid()), uint32(os.Getgid()), approved); err == nil {
			t.Fatalf("unreviewed snapshot name accepted: %q", name)
		}
	}
	if os.Geteuid() != 0 {
		if _, _, err := PublishStage2aFrozenSnapshot(source, SoulRunner{},
			"snap_333333333333333333333333", approved); err == nil {
			t.Fatal("ordinary account entered Machine root publisher")
		}
	}
}
