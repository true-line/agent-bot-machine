//go:build darwin || linux

package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveGateObjectV3RejectsAliasesAndChangedBytes(t *testing.T) {
	root := t.TempDir()
	data := []byte(`{"gate":"T03"}`)
	sha := digest(data)
	name := strings.TrimPrefix(sha, "sha256:")
	uri := gateObjectPrefixV3 + "gate-manifest/" + name
	parent := filepath.Join(root, "objects", "sha256", name[:2])
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(parent, name)
	if err := os.WriteFile(object, data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveGateObjectV3(root, uri, sha, 1024); err != nil || string(got) != string(data) {
		t.Fatalf("exact object: %q, %v", got, err)
	}
	for _, bad := range []struct{ uri, sha string }{
		{uri + "/../" + name, sha},
		{gateObjectPrefixV3 + "blob/" + name + "?x=1", sha},
		{"file://" + object, sha},
		{uri, "sha256:" + strings.Repeat("0", 64)},
		{uri, strings.ToUpper(sha)},
	} {
		if _, err := ResolveGateObjectV3(root, bad.uri, bad.sha, 1024); err == nil {
			t.Fatalf("accepted bad reference %q %q", bad.uri, bad.sha)
		}
	}
	if _, err := ResolveGateObjectV3(root, uri, sha, int64(len(data)-1)); err == nil {
		t.Fatal("accepted undersized limit")
	}
	if _, err := ResolveGateObjectV3(root, uri, sha, maxGateManifestBytesV3+1); err == nil {
		t.Fatal("accepted gate manifest bound above class limit")
	}
	alias := filepath.Join(root, "alias")
	if err := os.Link(object, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGateObjectV3(root, uri, sha, 1024); err == nil {
		t.Fatal("accepted hard link")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alias, object); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGateObjectV3(root, uri, sha, 1024); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte(`{"gate":"T02"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGateObjectV3(root, uri, sha, 1024); err == nil {
		t.Fatal("accepted changed bytes")
	}
}

func TestResolveGateObjectV3RejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	data := []byte("evidence")
	sha := digest(data)
	name := strings.TrimPrefix(sha, "sha256:")
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "sha256", name[:2]), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sha256", name[:2], name), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "objects")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveGateObjectV3(root, gateObjectPrefixV3+"blob/"+name, sha, 1024); err == nil {
		t.Fatal("accepted symlinked directory")
	}
}
