//go:build darwin

package members

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aQualificationDriverProvesBoundPath(t *testing.T) {
	// Darwin's Unix socket path is short; t.TempDir can exceed that limit.
	dir := shortStage2aDriverTestDir(t)
	boundPath := filepath.Join(dir, "bound.sock")
	bound, err := net.ListenUnix("unix", &net.UnixAddr{Name: boundPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	if err := proveStage2aQualificationDriverListener(bound, boundPath); err != nil {
		t.Fatalf("bound listener refused its own pathname: %v", err)
	}
	foreignPath := filepath.Join(dir, "foreign.sock")
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Name: foreignPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	if err := proveStage2aQualificationDriverListener(bound, foreignPath); err == nil {
		t.Fatal("listener accepted a pathname bound to another socket")
	}
}

func TestStage2aQualificationDriverNoFollowMode(t *testing.T) {
	dir := shortStage2aDriverTestDir(t)
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	name := "driver.sock"
	path := filepath.Join(dir, name)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := unix.Fchmodat(int(parent.Fd()), name, 0600, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatalf("socket must be mode 0600: mode=%v", info.Mode())
	}
	// A substituted symlink must never change the target's permissions.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	// Darwin may successfully change the link's own mode. The target must
	// retain its mode either way.
	_ = unix.Fchmodat(int(parent.Fd()), name, 0600, unix.AT_SYMLINK_NOFOLLOW)
	info, err = os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("symlink target mode changed: mode=%v", info.Mode())
	}
}

func TestStage2aQualificationDriverClosePreservesOccupant(t *testing.T) {
	dir := shortStage2aDriverTestDir(t)
	path := filepath.Join(dir, "driver.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	l := &stage2aQualificationDriverListener{listener: listener, path: path}
	l.close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("closed one-use endpoint was removed: mode=%v", info.Mode())
	}
	if rebound, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"}); err == nil {
		rebound.Close()
		t.Fatal("closed endpoint was silently reused")
	}
}

func shortStage2aDriverTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "qdl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
