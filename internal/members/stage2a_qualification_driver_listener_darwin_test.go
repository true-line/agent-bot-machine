//go:build darwin

package members

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aQualificationDriverProvesBoundPath(t *testing.T) {
	// Darwin's Unix socket path is short; t.TempDir can exceed that limit.
	dir, err := os.MkdirTemp("/private/tmp", "qdl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
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
