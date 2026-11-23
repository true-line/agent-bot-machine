//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
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

// A disposable root guest may set all three IDs to exercise the actual
// kernel credential handoff. This tests the seal seam, not owner proof or T03.
func TestStage2aRootToAdminSealHandoff(t *testing.T) {
	if os.Getenv("STAGE2A_SEAL_TEST_CHILD") == "1" {
		if !stage2aInstallSealNoIP() {
			t.Fatal("A child has direct IP access")
		}
		var handoff struct {
			Namespace string                    `json:"namespace"`
			Name      string                    `json:"name"`
			Prepared  stage2aPreparedSnapshot   `json:"prepared"`
			Approved  []Stage2aDefinitionRecord `json:"approved"`
			AdminUID  uint32                    `json:"admin_uid"`
			AdminGID  uint32                    `json:"admin_gid"`
			RunnerGID uint32                    `json:"runner_gid"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&handoff); err != nil {
			t.Fatal(err)
		}
		groups, groupsErr := os.Getgroups()
		if handoff.AdminUID < 400 || handoff.RunnerGID == 0 ||
			uint32(os.Getuid()) != handoff.AdminUID || uint32(os.Geteuid()) != handoff.AdminUID ||
			uint32(os.Getgid()) != handoff.AdminGID || uint32(os.Getegid()) != handoff.AdminGID ||
			groupsErr != nil || len(groups) != 1 || groups[0] != int(handoff.AdminGID) {
			t.Fatalf("A child kernel credentials differ: got uid=%d euid=%d gid=%d egid=%d groups=%v groups_err=%v; want uid=%d gid=%d and only its primary group",
				os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, groupsErr,
				handoff.AdminUID, handoff.AdminGID)
		}
		var st unix.Stat_t
		if err := unix.Stat(handoff.Namespace, &st); err != nil {
			t.Fatal(err)
		}
		a := stage2aAdminSnapshots{
			uid: handoff.AdminUID, runnerReadGID: handoff.RunnerGID, namespace: handoff.Namespace,
			namespaceDev: st.Dev, namespaceInode: st.Ino, namespaceBirth: st.Btim,
			verifyInstalledGroup: func() error { return nil },
		}
		if _, _, err := stage2aSealPreparedSnapshotAt(a, handoff.Prepared, handoff.Name,
			handoff.Approved, false); err != nil {
			t.Fatal(err)
		}
		return
	}
	uidText := os.Getenv("STAGE2A_SEAL_TEST_A_UID")
	adminGIDText := os.Getenv("STAGE2A_SEAL_TEST_A_GID")
	runnerGIDText := os.Getenv("STAGE2A_SEAL_TEST_R_GID")
	if os.Getuid() != 0 || uidText == "" || adminGIDText == "" || runnerGIDText == "" {
		t.Skip("requires an explicit disposable root guest and separate A/R IDs")
	}
	uid64, uidErr := strconv.ParseUint(uidText, 10, 32)
	adminGID64, adminGIDErr := strconv.ParseUint(adminGIDText, 10, 32)
	runnerGID64, runnerGIDErr := strconv.ParseUint(runnerGIDText, 10, 32)
	if uidErr != nil || adminGIDErr != nil || runnerGIDErr != nil ||
		uid64 < 400 || adminGID64 == 0 || runnerGID64 == 0 || adminGID64 == runnerGID64 {
		t.Fatal("invalid explicit separate A/R IDs")
	}
	uid, adminGID, runnerGID := uint32(uid64), uint32(adminGID64), uint32(runnerGID64)
	base, err := os.MkdirTemp("/private/var/db", "agent-bot-stage2a-a-seal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
		_ = os.RemoveAll(base)
	})
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	namespace := filepath.Join(base, "namespace")
	if err := os.Mkdir(namespace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(namespace, int(uid), int(runnerGID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(namespace, 0750); err != nil {
		t.Fatal(err)
	}
	source, approved := stage2aObservedFixture(t)
	const name = "snap_cccccccccccccccccccccccc"
	prepared, err := prepareStage2aInstallSnapshotAt(source, namespace, name,
		0, 0, uid, runnerGID, approved, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(namespace, name)); !os.IsNotExist(err) {
		t.Fatalf("root published before A handoff: %v", err)
	}
	me, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	from, err := os.Open(me)
	if err != nil {
		t.Fatal(err)
	}
	defer from.Close()
	childPath := filepath.Join(base, "seal-test")
	to, err := os.OpenFile(childPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(to, from)
	closeErr := to.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy test child: %v, %v", copyErr, closeErr)
	}
	handoff, err := json.Marshal(struct {
		Namespace string                    `json:"namespace"`
		Name      string                    `json:"name"`
		Prepared  stage2aPreparedSnapshot   `json:"prepared"`
		Approved  []Stage2aDefinitionRecord `json:"approved"`
		AdminUID  uint32                    `json:"admin_uid"`
		AdminGID  uint32                    `json:"admin_gid"`
		RunnerGID uint32                    `json:"runner_gid"`
	}{namespace, name, prepared, approved, uid, adminGID, runnerGID})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile,
		childPath, "-test.run=^TestStage2aRootToAdminSealHandoff$", "-test.v")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "STAGE2A_SEAL_TEST_CHILD=1"}
	cmd.Stdin = bytes.NewReader(handoff)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: adminGID, Groups: []uint32{}}}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("A child refused root handoff: %v: %s", err, output)
	}
	identity, digest, err := observeStage2aSourceAt(filepath.Join(namespace, name), uid, runnerGID, approved, false)
	if err != nil || identity.Mode != "0555" || digest != prepared.Digest ||
		identity.Inode != prepared.Stage.Inode {
		t.Fatalf("A-sealed root-to-A node changed: %v, %+v, %q", err, identity, digest)
	}
	t.Logf("root-to-A seal passed: A uid=%d gid=%d, R gid=%d, inode=%s, digest=%s; no T credit",
		uid, adminGID, runnerGID, identity.Inode, digest)
}
