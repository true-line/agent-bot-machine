//go:build darwin

package members

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func stage2aObservedFixture(t *testing.T) (string, []Stage2aDefinitionRecord) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"Contents", "Contents/opt", "Contents/primitives"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := []struct {
		path string
		mode fs.FileMode
		data string
	}{
		{"Contents/SoulInfo.json", 0444, "{}"},
		{"Contents/SoulLock.json", 0444, "{}"},
		{"Contents/opt/quickstart-adapter.mjs", 0555, "adapter"},
		{"Contents/opt/quickstart-check.mjs", 0555, "checker"},
		{"Contents/primitives/quickstart-task.json", 0444, "{}"},
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(root, file.path), []byte(file.data), file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, file.path), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"Contents/opt", "Contents/primitives", "Contents", ""} {
		if err := os.Chmod(filepath.Join(root, dir), 0555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, dir := range []string{"", "Contents", "Contents/opt", "Contents/primitives"} {
			_ = os.Chmod(filepath.Join(root, dir), 0700)
		}
	})
	records := []Stage2aDefinitionRecord{
		{Path: "Contents", Kind: "directory", Mode: "0555"},
		{Path: "Contents/SoulInfo.json", Kind: "regular", Mode: "0444"},
		{Path: "Contents/SoulLock.json", Kind: "regular", Mode: "0444"},
		{Path: "Contents/opt", Kind: "directory", Mode: "0555"},
		{Path: "Contents/opt/quickstart-adapter.mjs", Kind: "regular", Mode: "0555"},
		{Path: "Contents/opt/quickstart-check.mjs", Kind: "regular", Mode: "0555"},
		{Path: "Contents/primitives", Kind: "directory", Mode: "0555"},
		{Path: "Contents/primitives/quickstart-task.json", Kind: "regular", Mode: "0444"},
	}
	indexed := map[string]string{}
	for _, file := range files {
		indexed[file.path] = file.data
	}
	for i := range records {
		if data, ok := indexed[records[i].Path]; ok {
			size := uint64(len(data))
			sum := sha256.Sum256([]byte(data))
			records[i].Size = &size
			records[i].SHA256 = fmt.Sprintf("%x", sum)
		}
	}
	return root, records
}

func TestStage2aRuntimeSnapshotPublishesImplicitDirectories(t *testing.T) {
	source := t.TempDir()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{
		"host/adapters.json":              `{}`,
		"host/installation.json":          `{}`,
		"runtime/bin/node":                "node",
		"runtime/bin/agent-bot-souls.mjs": "souls",
	}
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	records := make([]Stage2aDefinitionRecord, 0, len(paths))
	for _, path := range paths {
		full := filepath.Join(source, path)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		mode := fs.FileMode(0444)
		if filepath.Base(path) == "node" || filepath.Base(path) == "agent-bot-souls.mjs" {
			mode = 0555
		}
		body := []byte(contents[path])
		if err := os.WriteFile(full, body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
		size := uint64(len(body))
		records = append(records, Stage2aDefinitionRecord{
			Path: path, Kind: "regular", Mode: fmt.Sprintf("%04o", mode),
			Size: &size, SHA256: fmt.Sprintf("%x", sha256.Sum256(body)),
		})
	}
	for _, dir := range []string{"host", "runtime/bin", "runtime", ""} {
		if err := os.Chmod(filepath.Join(source, dir), 0555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, dir := range []string{"", "host", "runtime", "runtime/bin"} {
			_ = os.Chmod(filepath.Join(source, dir), 0700)
		}
	})
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	identity, _, err := publishStage2aRuntimeAt(source, parent,
		"snap_0123456789abcdef01234567", uid, gid, uid, gid, records, false)
	if err != nil {
		t.Fatalf("runtime snapshot could not be published: %v", err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(identity.RootPath, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	if identity.Mode != "0555" || stage2aCheckRuntimeSnapshot(identity, records) != nil {
		t.Fatal("published runtime snapshot failed installed-byte observation")
	}
	if _, _, err := publishStage2aSourceAt(source, parent,
		"snap_0123456789abcdef01234568", uid, gid, uid, gid, records, false); err == nil {
		t.Fatal("definition-only publisher accepted a runtime inventory")
	}
}

func TestStage2aFrozenDescriptorObservation(t *testing.T) {
	root, approved := stage2aObservedFixture(t)
	want, _, err := Stage2aDefinitionDigest(approved)
	if err != nil {
		t.Fatal(err)
	}
	identity, got, err := observeStage2aFrozenAt(root, uint32(os.Getuid()), uint32(os.Getgid()), approved)
	if err != nil || got != want || identity.Inode == "" || identity.Mode != "0555" {
		t.Fatalf("descriptor observation differs: %s, %v, %+v", got, err, identity)
	}
	if os.Geteuid() != 0 {
		if _, err := ObserveStage2aFrozenSnapshot(identity, approved); err == nil {
			t.Fatal("ordinary account observed as Machine root")
		}
	}
}

func TestStage2aFrozenObservationRefusesChangedSource(t *testing.T) {
	for name, change := range map[string]func(string) error{
		"extra root entry": func(root string) error {
			if err := os.Chmod(root, 0700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "unreviewed.mjs"), []byte("code"), 0444)
		},
		"changed bytes": func(root string) error {
			file := filepath.Join(root, "Contents/opt/quickstart-check.mjs")
			if err := os.Chmod(file, 0644); err != nil {
				return err
			}
			if err := os.WriteFile(file, []byte("CHECKER"), 0644); err != nil {
				return err
			}
			return os.Chmod(file, 0555)
		},
		"writable mode": func(root string) error {
			return os.Chmod(filepath.Join(root, "Contents/opt/quickstart-check.mjs"), 0644)
		},
		"unreviewed file": func(root string) error {
			if err := os.Chmod(filepath.Join(root, "Contents/opt"), 0700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "Contents/opt/extra.mjs"), []byte("extra"), 0444)
		},
		"symlink": func(root string) error {
			if err := os.Chmod(filepath.Join(root, "Contents/opt"), 0700); err != nil {
				return err
			}
			path := filepath.Join(root, "Contents/opt/quickstart-check.mjs")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink("quickstart-adapter.mjs", path)
		},
		"hard link": func(root string) error {
			if err := os.Chmod(filepath.Join(root, "Contents/opt"), 0700); err != nil {
				return err
			}
			return os.Link(filepath.Join(root, "Contents/opt/quickstart-check.mjs"),
				filepath.Join(root, "Contents/opt/extra.mjs"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, approved := stage2aObservedFixture(t)
			if err := change(root); err != nil {
				t.Fatal(err)
			}
			if _, _, err := observeStage2aFrozenAt(root, uint32(os.Getuid()), uint32(os.Getgid()), approved); err == nil {
				t.Fatal("changed frozen source accepted")
			}
		})
	}
}
