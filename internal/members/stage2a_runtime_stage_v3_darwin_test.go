//go:build darwin

package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aRuntimeV3TarMustMapEveryReleasedFile(t *testing.T) {
	data := []byte("selected runtime bytes")
	sum := sha256.Sum256(data)
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{{
		ComponentID: "souls", ReleasePath: "runtime/bin/agent-bot-souls.mjs",
		SizeBytes: uint64(len(data)), SHA256: fmt.Sprintf("sha256:%x", sum), Mode: "0550"}},
		Directories: []stage2aDomainDirectoryV3{{Path: "runtime", Mode: "0550"},
			{Path: "runtime/bin", Mode: "0550"}}}
	makeArchive := func(extra bool) string {
		t.Helper()
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, name := range []string{"runtime/", "runtime/bin/"} {
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0550, Typeflag: tar.TypeDir}); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.WriteHeader(&tar.Header{Name: "runtime/bin/agent-bot-souls.mjs", Mode: 0550,
			Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if extra {
			if err := writer.WriteHeader(&tar.Header{Name: "runtime/bin/unreviewed", Mode: 0440,
				Typeflag: tar.TypeReg, Size: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "component.tar")
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good, err := os.Open(makeArchive(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(good, "souls", inv); err != nil {
		t.Fatalf("exact tar refused: %v", err)
	}
	good.Close()
	bad, err := os.Open(makeArchive(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(bad, "souls", inv); err == nil {
		t.Fatal("unreviewed tar member accepted")
	}
	bad.Close()
}
