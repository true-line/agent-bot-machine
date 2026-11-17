package members

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxReleaseBytes = 256 << 20

type installedHQEntry struct {
	Entry
	path string // discovered from the installed tree before reading the archive
}

// macOS ships bsdtar. Check the approved archive directly against every file
// of its extraction. An installer never extracts or executes a file as root.
func verifyDarwinRelease(s HQService, h Host) error {
	if err := s.validate(); err != nil {
		return err
	}
	if s.Archive == "" {
		return refuse(RefusedList, "macOS requires archive to name the retained approved Darwin tar")
	}
	for _, p := range []string{s.Archive, s.Node, s.ReleaseDir} {
		if err := trustedPath(h, p, p == s.ReleaseDir); err != nil {
			return err
		}
	}
	paths := []string{"/", "/private", "/private/var", "/Library", "/Library/LaunchDaemons"}
	for _, p := range []string{s.Archive, s.Node, s.ReleaseDir} {
		for {
			paths = append(paths, p)
			if p == "/" {
				break
			}
			p = filepath.Dir(p)
		}
	}
	remaining := make(map[string]installedHQEntry)
	var size int64
	err := filepath.WalkDir(s.ReleaseDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.ContainsAny(p, "\r\n") {
			return refuse(RefusedPath, "newline in release path")
		}
		if err := trustedEntry(h, p, d.IsDir()); err != nil {
			return err
		}
		e, ok, err := h.Lstat(p)
		if err != nil || !ok {
			return fmt.Errorf("cannot inspect installed release entry %s", p)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size += info.Size()
		if len(remaining) >= 10000 || size > maxReleaseBytes {
			return refuse(RefusedPath, "installed HQ release exceeds verification limits")
		}
		rel, err := filepath.Rel(filepath.Dir(s.ReleaseDir), p)
		if err != nil {
			return err
		}
		remaining[rel] = installedHQEntry{Entry: e, path: p}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		if err := checkDarwinACLs(paths); err != nil {
			return err
		}
	}
	for _, name := range []string{"hq/hq/main.mjs", "hq/governance/interim-release.json", "hq/helpers/darwin-owner.rb"} {
		if !remaining[name].Regular {
			return refuse(RefusedPath, "Darwin release lacks %s", name)
		}
	}
	archive, err := openPinnedFile(s.Archive, s.ArtifactSHA256)
	if err != nil {
		return err
	}
	defer archive.Close()
	if err := matchDarwinArchive(archive, remaining); err != nil {
		return err
	}
	meta, err := os.ReadFile(filepath.Join(s.ReleaseDir, "governance/interim-release.json"))
	if err != nil {
		return err
	}
	var record struct {
		Target string `json:"target_platform"`
	}
	if err = json.Unmarshal(meta, &record); err != nil || record.Target != "darwin" {
		return refuse(RefusedPath, "HQ interim release must target darwin")
	}
	node, err := openPinnedFile(s.Node, s.NodeSHA256)
	if err != nil {
		return err
	}
	defer node.Close()
	info, err := node.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0111 == 0 {
		return refuse(RefusedPath, "Node is not executable")
	}
	return checkDarwinNode(node)
}

func openPinnedFile(p, digest string) (*os.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxReleaseBytes+1))
	if err != nil || n > maxReleaseBytes || hex.EncodeToString(h.Sum(nil)) != digest {
		f.Close()
		return nil, refuse(RefusedPath, "%s does not match its approved SHA-256", p)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func matchDarwinArchive(r io.Reader, remaining map[string]installedHQEntry) error {
	ar := tar.NewReader(r)
	for {
		hdr, err := ar.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		entry, ok := remaining[name]
		if !ok || name != path.Clean(name) {
			return refuse(RefusedPath, "unexpected or repeated tar entry %q", name)
		}
		if hdr.Format != tar.FormatUSTAR || hdr.Mode != int64(entry.Mode) {
			return refuse(RefusedPath, "archive %q has format %s mode %04o; expected ustar and installed mode %04o", name, hdr.Format, hdr.Mode, entry.Mode)
		}
		delete(remaining, name)
		if hdr.Typeflag == tar.TypeDir && entry.Dir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || !entry.Regular {
			return refuse(RefusedPath, "unexpected tar entry type for %q", name)
		}
		want := sha256.New()
		if _, err := io.Copy(want, ar); err != nil {
			return err
		}
		f, err := openPinnedFile(entry.path, hex.EncodeToString(want.Sum(nil)))
		if err != nil {
			return err
		}
		f.Close()
	}
	if len(remaining) != 0 {
		return refuse(RefusedPath, "installed HQ tree contains entries absent from the approved archive")
	}
	return nil
}

// Darwin ACLs may grant writes despite safe POSIX modes. Read all protected
// ancestors and tree entries in bounded batches. Read-only deny entries such
// as the platform's standard "everyone deny delete" are safe.
func checkDarwinACLs(paths []string) error {
	for len(paths) > 0 {
		n := min(48, len(paths))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "/bin/ls", append([]string{"-lde"}, paths[:n]...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		out, err := cmd.Output()
		cancel()
		if err != nil {
			return fmt.Errorf("inspect Darwin ACLs: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, " allow ") {
				return refuse(RefusedPath, "release, runtime and service paths must have no allow ACL entries")
			}
		}
		paths = paths[n:]
	}
	return nil
}

// Pinning the Node executable cannot authorize private loadable libraries.
// Inspect every slice; use only the OS loader and sealed system libraries.
func checkDarwinNode(file *os.File) error {
	fat, err := macho.NewFatFile(file)
	if err == nil {
		for _, arch := range fat.Arches {
			if err := checkNodeSlice(arch.File); err != nil {
				return err
			}
		}
		return nil
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return fmt.Errorf("read Node Mach-O: %w", err)
	}
	m, err := macho.NewFile(file)
	if err != nil {
		return err
	}
	return checkNodeSlice(m)
}

func checkNodeSlice(m *macho.File) error {
	if m.Type != macho.TypeExec {
		return refuse(RefusedPath, "Node must be a Mach-O executable")
	}
	for _, load := range m.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return errors.New("malformed Mach-O load command")
		}
		command := m.ByteOrder.Uint32(raw)
		switch command {
		case 0x27: // LC_DYLD_ENVIRONMENT
			return refuse(RefusedPath, "Node supplies loader environment overrides")
		case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0xe: // strong, weak, re-export, lazy, upward dylibs or dylinker
			if len(raw) < 12 {
				return errors.New("missing Mach-O library name")
			}
			offset := m.ByteOrder.Uint32(raw[8:12])
			if uint64(offset) >= uint64(len(raw)) {
				return errors.New("invalid Mach-O library name")
			}
			name, _, found := bytes.Cut(raw[offset:], []byte{0})
			p := string(name)
			if !found || p != path.Clean(p) || !(strings.HasPrefix(p, "/usr/lib/") || strings.HasPrefix(p, "/System/Library/")) {
				return refuse(RefusedPath, "Node requires a non-system loader or library: %q", p)
			}
		}
	}
	return nil
}
