//go:build darwin

package members

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aInstallSealAsNonrootAdmin(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("A seal requires nonroot effective UID")
	}
	source, approved := stage2aObservedFixture(t)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(parent, &st); err != nil {
		t.Fatal(err)
	}
	a := stage2aAdminSnapshots{
		uid: st.Uid, runnerReadGID: st.Gid, namespace: parent,
		namespaceDev: st.Dev, namespaceInode: st.Ino, namespaceBirth: st.Btim,
		verifyInstalledGroup: func() error { return nil },
	}
	const name = "snap_aaaaaaaaaaaaaaaaaaaaaaaa"
	prepared, err := prepareStage2aInstallSnapshotAt(source, parent, name,
		st.Uid, st.Gid, st.Uid, st.Gid, approved, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stage2aCleanPrivateStage(prepared.WrapperPath)
		stage2aCleanPrivateStage(filepath.Join(parent, name))
	})
	if _, err := os.Stat(filepath.Join(parent, name)); !os.IsNotExist(err) {
		t.Fatalf("root preparation published a final name: %v", err)
	}
	identity, digest, err := stage2aSealPreparedSnapshotAt(a, prepared, name, approved, false)
	if err != nil || identity.Mode != "0555" || digest != prepared.Digest {
		t.Fatalf("A seal failed: %v, %+v, %q", err, identity, digest)
	}
	if _, _, err := stage2aSealPreparedSnapshotAt(a, prepared, name, approved, false); err == nil {
		t.Fatal("spent preparation accepted twice")
	}

	const second = "snap_bbbbbbbbbbbbbbbbbbbbbbbb"
	changed, err := prepareStage2aInstallSnapshotAt(source, parent, second,
		st.Uid, st.Gid, st.Uid, st.Gid, approved, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage2aCleanPrivateStage(changed.WrapperPath) })
	file := filepath.Join(changed.Stage.RootPath, "Contents/opt/quickstart-check.mjs")
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.WriteAt([]byte("X"), 0)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || os.Chmod(file, 0555) != nil {
		t.Fatalf("fixture mutation failed: %v, %v", writeErr, closeErr)
	}
	if _, _, err := stage2aSealPreparedSnapshotAt(a, changed, second, approved, false); err == nil {
		t.Fatal("changed prepared bytes were published")
	}
	if _, err := os.Stat(filepath.Join(parent, second)); !os.IsNotExist(err) {
		t.Fatalf("changed bytes occupied final name: %v", err)
	}
}
