package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rebuild a complete, synthetic Darwin service plan from retained bytes. The
// host supplies account and ownership metadata; no file or account is installed.
func TestFirstHQPlanBindsOptionalVerifiedService(t *testing.T) {
	base := t.TempDir()
	h := emptyHost()
	const admin = "operator"
	const id = "plan-20261119T020000Z-abcd"
	h.accounts[admin] = Account{Name: admin, UID: 501}
	release := filepath.Join(base, "hq")
	for _, dir := range []string{release, filepath.Dir(launchPlist)} {
		for p := dir; ; p = filepath.Dir(p) {
			h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
			if p == "/" {
				break
			}
		}
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, entry := range []struct{ name, content string }{
		{"hq/", ""}, {"hq/governance/", ""}, {"hq/governance/interim-release.json", `{"target_platform":"darwin"}`},
		{"hq/helpers/", ""}, {"hq/helpers/darwin-owner.rb", "# fixture\n"},
		{"hq/hq/", ""}, {"hq/hq/main.mjs", "// fixture\n"},
	} {
		path := filepath.Join(base, entry.name)
		dir := strings.HasSuffix(entry.name, "/")
		header := &tar.Header{Name: entry.name, Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(entry.content)), Format: tar.FormatUSTAR}
		if dir {
			header.Mode = 0755
			header.Typeflag = tar.TypeDir
			if err := os.MkdirAll(path, 0755); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte(entry.content), 0644); err != nil {
			t.Fatal(err)
		}
		h.entries[path] = Entry{Dir: dir, Regular: !dir, Owner: "root", Group: "wheel", Mode: uint32(header.Mode)}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.content) > 0 {
			if _, err := tw.Write([]byte(entry.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	// A synthetic thin Mach-O header with no load commands. It is parsed only.
	node := make([]byte, 32)
	binary.LittleEndian.PutUint32(node[0:4], 0xfeedfacf)
	binary.LittleEndian.PutUint32(node[4:8], 0x0100000c)
	binary.LittleEndian.PutUint32(node[12:16], 2)
	s := &HQService{ReleaseDir: release, Node: filepath.Join(base, "node"), Archive: filepath.Join(base, "hq.tar"),
		ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(archive.Bytes())), NodeSHA256: fmt.Sprintf("%x", sha256.Sum256(node))}
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{s.Node, node, 0755}, {s.Archive, archive.Bytes(), 0644}} {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
		h.entries[file.path] = Entry{Regular: true, Owner: "root", Group: "wheel", Mode: uint32(file.mode)}
	}
	p, err := Build(Input{HQAccount: DarwinHQAccount, HQService: s, Platform: PlatformDarwin, Invoker: admin}, h)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Saved{Plan: p, HQService: s, PlanID: id, PlanDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	h.files[filepath.Join(base, "Library", "Application Support", "managed-machine", "members", "plans", id+".json")] = string(raw)
	canonical, got, err := FirstHQPlan(base, admin, id, h)
	if err != nil || got != digest || !strings.Contains(canonical, launchLabel) || !strings.Contains(canonical, s.ArtifactSHA256) {
		t.Fatalf("first-HQ service plan: %s, %v", got, err)
	}
	t.Run("Intel-only Node with the correct digest", func(t *testing.T) {
		intel := append([]byte(nil), node...)
		binary.LittleEndian.PutUint32(intel[4:8], uint32(macho.CpuAmd64))
		candidate := *s
		candidate.Node = filepath.Join(base, "node-intel")
		if err := os.WriteFile(candidate.Node, intel, 0755); err != nil {
			t.Fatal(err)
		}
		h.entries[candidate.Node] = h.entries[s.Node]
		candidate.NodeSHA256 = fmt.Sprintf("%x", sha256.Sum256(intel))
		_, err := Build(Input{HQAccount: DarwinHQAccount, HQService: &candidate, Platform: PlatformDarwin, Invoker: admin}, h)
		if err == nil || !strings.Contains(err.Error(), "arm64 executable slice") {
			t.Fatalf("expected a native runtime diagnostic before plan approval, got %v", err)
		}
	})
	t.Run("service rollback leaves a new digest outside first-HQ scope", func(t *testing.T) {
		// The initial apply created the role, then removed its service plist.
		name := DarwinHQAccount
		home := HQHome(PlatformDarwin, name)
		h.accounts[name] = Account{Name: name, UID: 320, GID: 320, Group: name, Home: home, Shell: DarwinNoLoginShell, DarwinRole: darwinHQRoleName}
		h.entries[home] = Entry{Dir: true, Mode: 0700, Owner: name, Group: name}
		defer delete(h.accounts, name)
		defer delete(h.entries, home)
		current, err := Build(Input{HQAccount: name, Platform: PlatformDarwin, Invoker: admin, HQService: s}, h)
		if err != nil {
			t.Fatal(err)
		}
		if current.Changes() != 1 || len(current.Steps) != 2 || current.Steps[0].Action != ActionNone || current.Steps[1].Action != ActionCreate {
			t.Fatalf("remaining plan: %+v", current.Steps)
		}
		newDigest, err := current.Digest()
		if err != nil || newDigest == digest {
			t.Fatalf("remaining plan digest: %s, %v", newDigest, err)
		}
		const newID = "plan-20261119T040000Z-abcd"
		raw, err := json.Marshal(Saved{Plan: current, HQService: s, PlanID: newID, PlanDigest: newDigest})
		if err != nil {
			t.Fatal(err)
		}
		h.files[filepath.Join(base, "Library", "Application Support", "managed-machine", "members", "plans", newID+".json")] = string(raw)
		for _, attempt := range []string{id, newID} {
			if _, _, err := FirstHQPlan(base, admin, attempt, h); err == nil || !strings.Contains(err.Error(), "role to be absent") {
				t.Fatalf("accepted non-fresh plan %s: %v", attempt, err)
			}
		}
	})
	if err := os.WriteFile(s.Node, []byte("changed"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := FirstHQPlan(base, admin, id, h); err == nil {
		t.Fatal("accepted the saved plan after the retained runtime changed")
	}
}
