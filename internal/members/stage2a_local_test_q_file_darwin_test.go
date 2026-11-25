//go:build darwin

package members

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStage2aLocalTestQFixedFileProvenance(t *testing.T) {
	physical, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || !strings.HasPrefix(physical, "/private/") {
		t.Fatalf("test needs a physical Darwin temp directory: %q, %v", physical, err)
	}
	file := filepath.Join(physical, "q-approval.json")
	want := []byte(`{"schema":"fixed-q-test"}`)
	if err := os.WriteFile(file, want, 0400); err != nil {
		t.Fatal(err)
	}
	read := func(path string, uid, gid uint32) ([]byte, error) {
		return stage2aReadProtectedFileForUID(path, 8192, uid, gid, 0400)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if got, err := read(file, uid, gid); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("exact protected file refused: %v", err)
	}
	if _, err := read(file, uid+1, gid); err == nil {
		t.Fatal("wrong file or parent owner accepted")
	}
	if _, err := read(file, uid, gid+1); err == nil {
		t.Fatal("wrong file group accepted")
	}
	alias := filepath.Join(physical, "q-alias.json")
	if err := os.Symlink(file, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := read(alias, uid, gid); err == nil {
		t.Fatal("symlinked Q approval accepted")
	}
	if strings.HasPrefix(file, "/private/var/") {
		logicalAlias := strings.TrimPrefix(file, "/private")
		if _, err := read(logicalAlias, uid, gid); err == nil {
			t.Fatal("/var symlink alias accepted in place of physical path")
		}
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := read(file, uid, gid); err == nil {
		t.Fatal("wrong mode accepted")
	}
}
