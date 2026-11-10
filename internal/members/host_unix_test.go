//go:build !windows

package members

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestOSHostReadsTheRunningHost(t *testing.T) {
	h := OSHost{}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	a, ok, err := h.Account(me.Username)
	if err != nil || !ok {
		t.Fatalf("Account(%s) = %v, %v", me.Username, ok, err)
	}
	if a.Name != me.Username || a.Home != me.HomeDir || a.Group == "" {
		t.Errorf("account = %+v", a)
	}
	if _, ok, err := h.Account("abm-no-such-account"); ok || err != nil {
		t.Errorf("an unknown account: %v, %v", ok, err)
	}

	dir := t.TempDir()
	sub := filepath.Join(dir, "abm-a")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	e, ok, err := h.Lstat(sub)
	if err != nil || !ok || !e.Dir || e.Mode != 0o2750 || e.Owner != me.Username {
		t.Errorf("Lstat = %+v, %v, %v", e, ok, err)
	}
	file := filepath.Join(dir, "f")
	os.WriteFile(file, []byte("x\n"), 0o644)
	link := filepath.Join(dir, "l")
	os.Symlink(file, link)
	// A link is reported as itself, never followed.
	if e, _, _ := h.Lstat(link); e.Regular || e.Dir {
		t.Errorf("a link read as %+v", e)
	}
	if s, ok, err := h.ReadFile(file); s != "x\n" || !ok || err != nil {
		t.Errorf("ReadFile = %q, %v, %v", s, ok, err)
	}
	if _, ok, err := h.Lstat(filepath.Join(dir, "none")); ok || err != nil {
		t.Errorf("a missing path: %v, %v", ok, err)
	}
	names, err := h.List(dir)
	if err != nil || len(names) != 3 {
		t.Errorf("List = %v, %v", names, err)
	}
	if names, err := h.List(filepath.Join(dir, "none")); names != nil || err != nil {
		t.Errorf("a missing directory: %v, %v", names, err)
	}
}
