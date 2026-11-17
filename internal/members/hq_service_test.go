//go:build linux

package members

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHQServiceBindsInstalledBytesAndOwnerToApproval(t *testing.T) {
	// Actual files and GNU-tar bytes, with root ownership supplied through the
	// injected host so this regression needs no privileged filesystem changes.
	base := t.TempDir()
	release := filepath.Join(base, "v1", "hq")
	h := bare()
	for p := release; ; p = filepath.Dir(p) {
		h.entries[p] = Entry{Dir: true, Owner: "root", Mode: 0755}
		if p == "/" {
			break
		}
	}
	write := func(p, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		h.entries[filepath.Dir(p)] = Entry{Dir: true, Owner: "root", Mode: 0755}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		h.entries[p] = Entry{Regular: true, Owner: "root", Mode: uint32(mode)}
	}
	entry := filepath.Join(release, "hq/main.mjs")
	write(entry, "fixture", 0644)
	write(filepath.Join(release, "governance/interim-release.json"), "{}", 0644)
	node := filepath.Join(base, "node")
	write(node, "fixture-node", 0755)
	raw, err := exec.Command("/usr/bin/tar", "--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner", "--mode=u+rwX,go+rX,go-w", "--format=ustar", "-cf", "-", "-C", filepath.Dir(release), "hq").Output()
	if err != nil {
		t.Fatal(err)
	}
	s := HQService{ReleaseDir: release, Node: node, NodeSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("fixture-node"))), ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	in := request
	in.Invoker = "operator"
	in.HQService = &s
	h.accounts["operator"] = Account{UID: 1001}
	p, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	if last := p.Steps[len(p.Steps)-1]; last.Target != hqSocketName || last.Owner != "operator" || !strings.Contains(last.Content, s.ArtifactSHA256) {
		t.Fatalf("activation step %v", last)
	}
	digest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	h.accounts["operator"] = Account{UID: 1002}
	changed, err := Build(in, h)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := changed.Digest()
	if err != nil || changedDigest == digest {
		t.Fatal("owner UID change must change the approval")
	}
	e := h.entries[entry]
	e.Owner = DefaultHQAccount
	h.entries[entry] = e
	if _, err := Build(in, h); err == nil {
		t.Fatal("accepted a release writable by HQ")
	}
	e.Owner = "root"
	h.entries[entry] = e
	write(entry, "replacement", 0644)
	if _, err := Build(in, h); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("replacement: %v", err)
	}
}

func TestHQServiceRejectsInvalidRecord(t *testing.T) {
	for _, bad := range []string{"null", "{}", `{"unknown":"value"}`, `{}{}`} {
		if _, err := decodeHQService([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestHQOwnerStatusRequiresAuthenticatedPublicEndpoint(t *testing.T) {
	good := `{"hq":{"account":"agent-bot-hq","sockets":{"ownerControl":{"account":"operator","uid":1002,"path":"/run/agent-bot-hq/control.sock","peer_check":"SO_PEERCRED"}}}}`
	if !confirmsHQOwner([]byte(good), "operator", "1002") {
		t.Fatal("valid owner status refused")
	}
	for _, bad := range []string{strings.Replace(good, "1002", "1003", 1), strings.Replace(good, "SO_PEERCRED", "", 1), strings.Replace(good, "/run/agent-bot-hq/control.sock", "/tmp/control.sock", 1)} {
		if confirmsHQOwner([]byte(bad), "operator", "1002") {
			t.Fatal("incorrect owner status accepted")
		}
	}
}
