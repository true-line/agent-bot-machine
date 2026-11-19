package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHQDeviceDarwinCodeRequirement(t *testing.T) {
	dir, err := os.Open("/bin")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	ref, err := deviceDirectoryReference(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = verifyDeviceCode(ctx, ref, "echo", "anchor apple"); err != nil {
		t.Fatal("Apple signature requirement was not evaluated", err)
	}
	if verifyDeviceCode(ctx, ref, "echo", deviceKeydRequirement) == nil {
		t.Fatal("system executable accepted as keyd")
	}
}

func TestHQDeviceDarwinParentReferenceSurvivesMove(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "bin")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	ref, err := deviceDirectoryReference(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, filepath.Join(base, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(ref, "fixture"))
	if err != nil || string(raw) != "original" {
		t.Fatal("directory reference followed replacement")
	}
}
