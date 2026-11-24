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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const maxReleaseBytes = 256 << 20

var publicHPinRepository = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$`)
var publicHPinTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var publicHPinCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)

type installedHQEntry struct {
	Entry
	path string // discovered from the installed tree before reading the archive
}

// macOS ships bsdtar. Check the approved archive directly against every file
// of its extraction. An installer never extracts or executes a file as root.
func verifyDarwinReleaseFiles(s HQService, h Host) error {
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

// Read the layout marker only after matching the complete extraction to its
// approved archive. Older Darwin releases have no marker and retain v1.
func verifyDarwinRelease(s HQService, h Host) (string, error) {
	if err := verifyDarwinReleaseFiles(s, h); err != nil {
		return "", err
	}
	meta, err := os.ReadFile(filepath.Join(s.ReleaseDir, "governance/interim-release.json"))
	if err != nil {
		return "", err
	}
	return darwinControlCapability(meta)
}

// The ordinary launchd job has no authenticated selected-H preloader. A
// private H candidate cannot start through that argv. Inspect its pin only
// after the entire extraction has matched the approved archive; Build also
// repeats this check when a saved plan is rebuilt before root apply.
func checkUnselectedHQBootstrap(s HQService) error {
	p := filepath.Join(s.ReleaseDir, "governance/soul-contracts.json")
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil // older public HQ releases did not include the H pin
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return refuse(RefusedPath, "HQ H pin must be a bounded regular file")
	}
	var pin map[string]json.RawMessage
	decoder := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	if err := decoder.Decode(&pin); err != nil {
		return refuse(RefusedPath, "invalid HQ H pin: %v", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return refuse(RefusedPath, "trailing data in HQ H pin")
	}
	if pin == nil {
		return refuse(RefusedPath, "HQ H pin must be a JSON object")
	}
	if value, present := pin["private_candidate"]; present && !bytes.Equal(bytes.TrimSpace(value), []byte("true")) {
		return refuse(RefusedPath, "invalid HQ H private_candidate marker")
	} else if present {
		return refuse(RefusedList, "private H candidate requires authenticated selection; ordinary HQ service argv cannot start it")
	}
	// A present pin with a missing or misspelled marker must not be mistaken
	// for an older release without a pin. Match the public pin shape that HQ
	// checks at startup, including unknown fields, before creating the role.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var public struct {
		SchemaVersion   int      `json:"schema_version"`
		Repository      string   `json:"repository"`
		Tag             string   `json:"tag"`
		Commit          string   `json:"commit"`
		Paths           []string `json:"paths"`
		DigestAlgorithm string   `json:"digest_algorithm"`
		Digest          string   `json:"digest"`
		Files           int      `json:"files"`
	}
	check := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	check.DisallowUnknownFields()
	if err := check.Decode(&public); err != nil {
		return refuse(RefusedPath, "invalid public HQ H pin: %v", err)
	}
	if public.SchemaVersion != 1 || !publicHPinRepository.MatchString(public.Repository) ||
		!publicHPinTag.MatchString(public.Tag) || !publicHPinCommit.MatchString(public.Commit) ||
		len(public.Paths) == 0 || !sort.StringsAreSorted(public.Paths) ||
		public.DigestAlgorithm != "sha256-manifest-v1" || !strings.HasPrefix(public.Digest, "sha256:") ||
		!digestHex.MatchString(strings.TrimPrefix(public.Digest, "sha256:")) || public.Files < 1 {
		return refuse(RefusedPath, "invalid public HQ H pin fields")
	}
	for i, p := range public.Paths {
		if p == "" || (i > 0 && p == public.Paths[i-1]) {
			return refuse(RefusedPath, "invalid public HQ H pin paths")
		}
	}
	return nil
}

func darwinControlCapability(meta []byte) (string, error) {
	var record struct {
		Target     string          `json:"target_platform"`
		Capability json.RawMessage `json:"owner_control_capability"`
	}
	if json.Unmarshal(meta, &record) != nil || record.Target != "darwin" {
		return "", refuse(RefusedPath, "HQ interim release must target darwin")
	}
	if record.Capability == nil {
		return launchControlV1, nil
	}
	var value string
	if json.Unmarshal(record.Capability, &value) != nil || value != launchControlV2 {
		return "", refuse(RefusedPath, "unsupported Darwin owner-control capability in the HQ release")
	}
	return value, nil
}

func openPinnedFile(p, digest string) (*os.File, error) {
	return openPinnedFileLimit(p, digest, maxReleaseBytes)
}

func openPinnedFileLimit(p, digest string, limit int64) (*os.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit || hex.EncodeToString(h.Sum(nil)) != digest {
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
	var slices []*macho.File
	fat, err := macho.NewFatFile(file)
	switch {
	case err == nil:
		slices, err = universalNodeSlices(fat)
		if err != nil {
			return err
		}
	case errors.Is(err, macho.ErrNotFat):
		thin, err := macho.NewFile(file)
		if err != nil {
			return err
		}
		slices = []*macho.File{thin}
	default:
		return fmt.Errorf("read Node Mach-O: %w", err)
	}

	hasARM64 := false
	for _, slice := range slices {
		if err := checkNodeSlice(slice); err != nil {
			return err
		}
		if slice.Cpu == macho.CpuArm64 {
			hasARM64 = true
		}
	}
	if !hasARM64 {
		return refuse(RefusedPath, "Node must include an arm64 executable slice for the Apple Silicon HQ service")
	}
	return nil
}

// Darwin selects a universal executable's slice by its directory entry.
// debug/macho parses the directory and the image headers independently.
func universalNodeSlices(fat *macho.FatFile) ([]*macho.File, error) {
	slices := make([]*macho.File, 0, len(fat.Arches))
	for _, arch := range fat.Arches {
		if arch.FatArchHeader.Cpu != arch.File.Cpu || arch.FatArchHeader.SubCpu != arch.File.SubCpu {
			return nil, refuse(RefusedPath, "Node architecture directory does not match its executable slice")
		}
		slices = append(slices, arch.File)
	}
	return slices, nil
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
