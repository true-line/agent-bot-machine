package members

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the production archive and host rebuild without provisioning a role.
func TestDarwinHQRecoveryBindsSoleServiceStep(t *testing.T) {
	for _, version := range []string{launchControlV1, launchControlV2} {
		t.Run(version, func(t *testing.T) { testDarwinHQRecoveryPlan(t, version) })
	}
}

func testDarwinHQRecoveryPlan(t *testing.T, version string) {
	base := t.TempDir()
	h := emptyHost()
	const admin = "operator"
	const id = "plan-20261119T020000Z-abcd"
	h.accounts[admin] = Account{Name: admin, UID: 501}
	const uid = 331
	h.accounts[DarwinHQAccount] = Account{Name: DarwinHQAccount, UID: uid, GID: uid, Group: DarwinHQAccount, PrimaryUsers: []string{DarwinHQAccount}, Groups: []string{DarwinHQAccount}, DarwinRole: darwinHQRoleName, Home: HQHome(PlatformDarwin, DarwinHQAccount), Shell: DarwinNoLoginShell}
	h.entries[HQHome(PlatformDarwin, DarwinHQAccount)] = Entry{Dir: true, Owner: DarwinHQAccount, Group: DarwinHQAccount, Mode: 0700}
	s := makeTestHQRelease(t, h, base, version, filepath.Join(base, "node"), "// fixture\n")
	p, err := Build(Input{HQAccount: DarwinHQAccount, HQService: s, Platform: PlatformDarwin, Invoker: admin}, h)
	if err != nil {
		t.Fatal(err)
	}
	var rec launchRecord
	if err := json.Unmarshal([]byte(p.Steps[1].Content), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Plist, "<string>"+socketForCapability(version)+"</string>") {
		t.Fatalf("wrong plist %s", rec.Plist)
	}
	if version == launchControlV1 {
		if strings.Contains(p.Steps[1].Content, "runtime_directory") || p.Steps[1].Detail != "install the approved LaunchDaemon and verify status as its owner" {
			t.Fatal("legacy canonical service record changed")
		}
	} else if rec.RuntimeDir == nil || rec.RuntimeDir.Action != ActionCreate || !strings.Contains(p.Steps[1].Detail, "create "+launchRuntimeDir+" as root:wheel 0755") {
		t.Fatal("new directory effect missing from the canonical approval")
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	saved := Saved{Plan: p, HQService: s, PlanID: id, PlanDigest: digest}
	down := func(HQService, string) (bool, string, error) { return false, "", nil }
	if err := checkDarwinHQRecovery(saved, admin, uid, h, down); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinHQRecovery(saved, admin, uid, h, func(HQService, string) (bool, string, error) { return true, "42", nil }); err == nil {
		t.Fatal("running service accepted for recovery")
	}
	if err := checkDarwinHQRecovery(saved, admin, uid+1, h, down); err == nil {
		t.Fatal("role UID no longer matches the pairing")
	}
	for _, change := range []func(*Saved){
		func(v *Saved) { v.Plan.Steps[0].Action = ActionCreate },
		func(v *Saved) { v.Plan.Steps = append(v.Plan.Steps, Step{Kind: KindAccount, Action: ActionCreate}) },
		func(v *Saved) { v.Plan.Members = []string{"harness"} },
		func(v *Saved) { v.Plan.Members = nil },
		func(v *Saved) { v.Plan.Steps[1].Content += "changed" },
		func(v *Saved) { v.HQService = nil },
	} {
		v := saved
		v.Plan.Steps = append([]Step(nil), p.Steps...)
		change(&v)
		if err := checkDarwinHQRecovery(v, admin, uid, h, down); err == nil {
			t.Fatal("accepted a changed or ineligible plan")
		}
	}
	// A matching release under a different layout cannot reuse the paired
	// approval or take over an on-disk job from another layout.
	alternate := launchRuntimeSocket
	if version == launchControlV2 {
		alternate = launchSocket
	}
	h.entries[launchPlist] = Entry{Regular: true, Owner: "root", Group: "wheel", Mode: 0644}
	h.files[launchPlist] = strings.Replace(rec.Plist, socketForCapability(version), alternate, 1)
	if err := checkDarwinHQRecovery(saved, admin, uid, h, down); err == nil {
		t.Fatal("accepted mismatched existing LaunchDaemon")
	}
	delete(h.entries, launchPlist)
	delete(h.files, launchPlist)
	if err := os.WriteFile(s.Node, []byte("changed"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkDarwinHQRecovery(saved, admin, uid, h, down); err == nil {
		t.Fatal("changed retained runtime was accepted")
	}
}

func makeTestHQRelease(t *testing.T, h *fakeHost, base, version, nodePath, main string) *HQService {
	t.Helper()
	release := filepath.Join(base, "hq")
	for _, dir := range []string{release, filepath.Dir(launchPlist)} {
		for p := dir; ; p = filepath.Dir(p) {
			h.entries[p] = Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
			if p == "/" {
				break
			}
		}
	}
	h.entries[filepath.Dir(launchRuntimeDir)] = Entry{Dir: true, Owner: "root", Group: "admin", Mode: 0755}
	meta := `{"target_platform":"darwin"}`
	if version == launchControlV2 {
		meta = `{"target_platform":"darwin","owner_control_capability":"darwin-owner-control/v2"}`
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, entry := range []struct{ name, content string }{
		{"hq/", ""}, {"hq/governance/", ""}, {"hq/governance/interim-release.json", meta},
		{"hq/helpers/", ""}, {"hq/helpers/darwin-owner.rb", "# fixture\n"},
		{"hq/hq/", ""}, {"hq/hq/main.mjs", main},
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
	s := &HQService{ReleaseDir: release, Node: nodePath, Archive: filepath.Join(base, "hq.tar"),
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

	return s
}
