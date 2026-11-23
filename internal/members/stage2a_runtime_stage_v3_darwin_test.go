//go:build darwin

package members

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aRuntimeV3TarMustMapEveryReleasedFile(t *testing.T) {
	data := []byte("selected runtime bytes")
	sum := sha256.Sum256(data)
	inv := stage2aDomainInventoryV3{Files: []stage2aDomainFileV3{{
		ComponentID: "souls", ReleasePath: "runtime/bin/agent-bot-souls.mjs", Path: "runtime/bin/agent-bot-souls.mjs",
		SizeBytes: uint64(len(data)), SHA256: fmt.Sprintf("sha256:%x", sum), Mode: "0550"}},
		Directories: []stage2aDomainDirectoryV3{{Path: "runtime", Mode: "0550"},
			{Path: "runtime/bin", Mode: "0550"}}}
	makeArchive := func(extra bool, prefix string) string {
		t.Helper()
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		if prefix != "" {
			if err := writer.WriteHeader(&tar.Header{Name: prefix + "/", Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
				t.Fatal(err)
			}
			prefix += "/"
		}
		for _, name := range []string{"runtime/", "runtime/bin/"} {
			if err := writer.WriteHeader(&tar.Header{Name: prefix + name, Mode: 0550, Typeflag: tar.TypeDir}); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.WriteHeader(&tar.Header{Name: prefix + "runtime/bin/agent-bot-souls.mjs", Mode: 0550,
			Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if extra {
			if err := writer.WriteHeader(&tar.Header{Name: prefix + "runtime/bin/unreviewed", Mode: 0440,
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
	good, err := os.Open(makeArchive(false, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(good, "souls", inv); err != nil {
		t.Fatalf("exact tar refused: %v", err)
	}
	good.Close()
	relocated := inv
	relocated.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	relocated.Files[0].Path = "sealed/runtime/bin/agent-bot-souls.mjs"
	relocated.Directories = []stage2aDomainDirectoryV3{
		{Path: "sealed", Mode: "0550"}, {Path: "sealed/runtime", Mode: "0550"},
		{Path: "sealed/runtime/bin", Mode: "0550"},
	}
	shifted, err := os.Open(makeArchive(false, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(shifted, "souls", relocated); err != nil {
		t.Fatalf("exact relocated tar refused: %v", err)
	}
	shifted.Close()
	stripped := inv
	stripped.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
	stripped.Files[0].ReleasePath = "package/" + inv.Files[0].ReleasePath
	packaged, err := os.Open(makeArchive(false, "package"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(packaged, "souls", stripped); err != nil {
		t.Fatalf("exact stripped-prefix tar refused: %v", err)
	}
	packaged.Close()
	bad, err := os.Open(makeArchive(true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage2aVerifyRuntimeV3Tar(bad, "souls", inv); err == nil {
		t.Fatal("unreviewed tar member accepted")
	}
	bad.Close()
}

func TestStage2aRuntimeV3StageRespectsDescriptorLimit(t *testing.T) {
	const childEnv = "STAGE2A_V3_FD_LIMIT_CHILD"
	if os.Getenv(childEnv) != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestStage2aRuntimeV3StageRespectsDescriptorLimit$")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("staging above the soft descriptor limit failed: %v: %s", err, output)
		}
		return
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur > 64 {
		limit.Cur = 64
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
	}
	const source = "/private/etc/hosts"
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	inv := stage2aDomainInventoryV3{Contract: "machine/v3", Kind: "stage2a-domain-inventory",
		SchemaVersion: 3, Domain: "R-runtime", InstallationID: "fd-bound-test",
		Limits: stage2aDomainInventoryLimitsV3{MaxFiles: 512,
			MaxFileBytes: stage2aV3MaxInventoryFileBytes, MaxTotalBytes: stage2aV3MaxInventoryTotalBytes}}
	sources := make(map[string]string, 300)
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf("d%03d", i)
		component := fmt.Sprintf("component%03d", i)
		inv.Directories = append(inv.Directories, stage2aDomainDirectoryV3{
			Path: name, Kind: "directory", Mode: "0550"})
		inv.Files = append(inv.Files, stage2aDomainFileV3{Path: name + "/hosts",
			Kind: "regular", Mode: "0440", SizeBytes: uint64(len(data)),
			SHA256: fmt.Sprintf("sha256:%x", sum), ComponentID: component, ReleasePath: "hosts"})
		sources[component] = "/private/etc"
	}
	inv.TotalBytes = uint64(len(data)) * uint64(len(inv.Files))
	raw := stage2aV3TestCanonical(t, inv)
	_, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	parentPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	staged, err := stage2aStageRuntimeV3(parent, inv, digest, raw, sources,
		uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatalf("valid 300-directory inventory refused with soft fd limit %d: %v", limit.Cur, err)
	}
	t.Cleanup(func() { stage2aCleanPrivateStage(staged.WrapperPath) })
}

func TestStage2aRuntimeV3ZipRequiresExactStockPackageMembers(t *testing.T) {
	contents := map[string][]byte{
		"claude-agent-acp": []byte("reviewed ACP adapter"),
		"claude":           []byte("reviewed adjacent CLI"),
	}
	inv := stage2aDomainInventoryV3{}
	for name, data := range contents {
		sum := sha256.Sum256(data)
		inv.Files = append(inv.Files, stage2aDomainFileV3{
			ComponentID: "adapter", ReleasePath: name, Path: "runtime/bin/" + name,
			SizeBytes: uint64(len(data)), SHA256: fmt.Sprintf("sha256:%x", sum), Mode: "0550",
		})
	}
	makeArchive := func(extra bool, changed bool) string {
		t.Helper()
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		for _, name := range []string{"claude-agent-acp", "claude"} {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetMode(0755)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			data := contents[name]
			if changed && name == "claude" {
				data = bytes.Repeat([]byte{'x'}, len(data))
			}
			if _, err := entry.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if extra {
			entry, err := writer.Create("unreviewed")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "adapter.zip")
		if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name, path string
		accept     bool
	}{
		{"exact", makeArchive(false, false), true},
		{"extra", makeArchive(true, false), false},
		{"changed", makeArchive(false, true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.Open(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			st, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if accepted := stage2aVerifyRuntimeV3Zip(file, st.Size(), "adapter", inv) == nil; accepted != tc.accept {
				t.Fatalf("ZIP acceptance=%v, wanted %v", accepted, tc.accept)
			}
		})
	}
}
