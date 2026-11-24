//go:build darwin

package members

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aT03SiblingCredentialObservationRejectsMissingAndMismatchedFiles(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	state := filepath.Join(home, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "credential")
	if _, _, err := observeStage2aT03Credential(home, path, uid, gid); err == nil {
		t.Fatal("missing credential was accepted")
	}
	if err := os.WriteFile(path, []byte("fixture-only"), 0600); err != nil {
		t.Fatal(err)
	}
	meta, digest, err := observeStage2aT03Credential(home, path, uid, gid)
	if err != nil || meta.Path != path || meta.Mode != "0600" || !stage2aPrefixedDigest.MatchString(digest) {
		t.Fatalf("private sibling credential refused: %v", err)
	}
	if _, _, err := observeStage2aT03Credential(home, path, uid+1, gid); err == nil {
		t.Fatal("mismatched owner was accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeStage2aT03Credential(home, path, uid, gid); err == nil {
		t.Fatal("public credential was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(state, "other")
	if err := os.WriteFile(other, []byte("fixture-only"), 0600); err != nil {
		t.Fatal(err)
	}
	_, otherDigest, err := observeStage2aT03Credential(home, other, uid, gid)
	if err != nil || otherDigest == digest {
		t.Fatal("different path matched the credential metadata digest")
	}
	if err := os.Symlink(path, filepath.Join(state, "link")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeStage2aT03Credential(home, filepath.Join(state, "link"), uid, gid); err == nil {
		t.Fatal("symlink credential was accepted")
	}
}
