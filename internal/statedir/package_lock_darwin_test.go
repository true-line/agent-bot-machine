package statedir

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func macLockHome(t *testing.T, homeMode, libraryMode os.FileMode) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("use the distinct owner/root process test as root")
	}
	home := t.TempDir()
	if err := os.Chmod(home, homeMode); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(home, "Library")
	if err := os.Mkdir(library, libraryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(library, libraryMode); err != nil {
		t.Fatal(err)
	}
	return home
}

func requireMacLock(t *testing.T, home string, uid int) *macPackageLock {
	t.Helper()
	lock, err := LockMacPackage(home, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return lock.(*macPackageLock)
}

func requireBusyMacLock(t *testing.T, home string, uid int) {
	t.Helper()
	lock, err := LockMacPackage(home, uid)
	if err == nil {
		_ = lock.Close()
		t.Fatal("another lifecycle operation acquired the lock")
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("expected kernel contention, got %v", err)
	}
}

func requireNoMacLockArtifacts(t *testing.T, home string) {
	t.Helper()
	files, err := os.ReadDir(filepath.Join(home, "Library"))
	if err != nil || len(files) != 0 {
		t.Fatalf("expected no lock artifacts, got %d entries (%v)", len(files), err)
	}
}

func TestMacPackageLockSharedHome(t *testing.T) {
	home := macLockHome(t, 0750, 0755)
	uid := os.Geteuid()
	lock := requireMacLock(t, home, uid)
	path := filepath.Join(home, "Library", macLockName)
	info, err := os.Stat(path)
	if err != nil || info.Mode() != 0600 {
		t.Fatalf("private lock file: %v (%v)", info, err)
	}
	requireBusyMacLock(t, home, uid)
	legacy, err := os.Open(filepath.Join(home, "Library"))
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err := acquireMacFlock(int(legacy.Fd())); err != nil {
		t.Fatalf("shared layout unexpectedly depended on the Library lock: %v", err)
	}
	// The named lock must remain authoritative even with the readable
	// directory lock acquired independently by the same fixture user.
	requireBusyMacLock(t, home, uid)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoMacLockArtifacts(t, home)
	reopened := requireMacLock(t, home, uid)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoMacLockArtifacts(t, home)
}

func TestMacPackageLockLegacyPrivateLayouts(t *testing.T) {
	for _, modes := range [][2]os.FileMode{{0700, 0755}, {0750, 0700}} {
		t.Run(fmt.Sprintf("%04o-%04o", modes[0], modes[1]), func(t *testing.T) {
			home := macLockHome(t, modes[0], modes[1])
			fd, err := unix.Open(filepath.Join(home, "Library"), macDirectoryFlags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := acquireMacFlock(fd); err != nil {
				t.Fatal(err)
			}
			requireBusyMacLock(t, home, os.Geteuid())
			requireNoMacLockArtifacts(t, home)
			if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
				t.Fatal(err)
			}
			lock := requireMacLock(t, home, os.Geteuid())
			if err := acquireMacFlock(fd); !errors.Is(err, unix.EWOULDBLOCK) {
				t.Fatalf("a legacy contender did not see the modern lock: %v", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
			requireNoMacLockArtifacts(t, home)
		})
	}
}

func TestMacPackageLockDetectsReplacedNameAndStaleDescriptors(t *testing.T) {
	home := macLockHome(t, 0750, 0755)
	lock := requireMacLock(t, home, os.Geteuid())
	fd, err := unix.Openat(lock.library, macLockName, macLockFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	newLock := requireMacLock(t, home, os.Geteuid())
	if err := acquireMacFlock(fd); err != nil {
		t.Fatal(err)
	}
	if newLock.matchesFile(macLockName, fd) {
		t.Fatal("an old descriptor aliases the newly named lock")
	}
	path := filepath.Join(home, "Library", macLockName)
	renamed := path + ".fixture-replaced"
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unrelated fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := newLock.Close(); err == nil {
		t.Fatal("cleanup accepted a replaced lock")
	}
	if payload, err := os.ReadFile(path); err != nil || string(payload) != "unrelated fixture" {
		t.Fatal("cleanup did not preserve the replacement")
	}
}

func TestMacPackageLockRefusesWritableParentsBeforeCreatingFiles(t *testing.T) {
	for _, modes := range [][2]os.FileMode{{0770, 0755}, {0750, 0775}} {
		home := macLockHome(t, modes[0], modes[1])
		lock, err := LockMacPackage(home, os.Geteuid())
		if err == nil {
			_ = lock.Close()
			t.Fatal("accepted a parent writable by other accounts")
		}
		requireNoMacLockArtifacts(t, home)
	}
}

func TestMacPackageLockRefusesExtendedWritePermissions(t *testing.T) {
	home := macLockHome(t, 0750, 0755)
	library := filepath.Join(home, "Library")
	if err := exec.Command("/bin/chmod", "+a", "everyone allow add_file", library).Run(); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("/bin/chmod", "-N", library).Run()
	if lock, err := LockMacPackage(home, os.Geteuid()); err == nil {
		_ = lock.Close()
		t.Fatal("accepted a Library directory with an extended write grant")
	}
	requireNoMacLockArtifacts(t, home)
}

func TestMacPackageLockRecoversAfterProcessExit(t *testing.T) {
	home := macLockHome(t, 0750, 0755)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMacPackageLockFixtureChild$")
	cmd.Env = append(os.Environ(), "MACHINE_LOCK_TEST_HOME="+home, "MACHINE_LOCK_TEST_UID="+strconv.Itoa(os.Geteuid()))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("fixture child did not report its lock: %q (%v)", line, err)
	}
	requireBusyMacLock(t, home, os.Geteuid())
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	lock := requireMacLock(t, home, os.Geteuid())
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoMacLockArtifacts(t, home)
}

func TestMacPackageLockRootAndOwnerShareTheSameFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("run this fixture as root in a disposable macOS test environment")
	}
	const uid, gid = 60001, 60001
	dir, err := os.MkdirTemp("/private/tmp", "machine-lock-root-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	home := filepath.Join(dir, "home")
	library := filepath.Join(home, "Library")
	if err := os.MkdirAll(library, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{home, library} {
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(home, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(library, 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, "lock-test")
	if err := os.WriteFile(executable, binary, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0755); err != nil {
		t.Fatal(err)
	}
	asOwner := func(busy bool) *exec.Cmd {
		cmd := exec.Command(executable, "-test.run=^TestMacPackageLockFixtureChild$")
		cmd.Env = []string{"MACHINE_LOCK_TEST_HOME=" + home, "MACHINE_LOCK_TEST_UID=" + strconv.Itoa(uid)}
		if busy {
			cmd.Env = append(cmd.Env, "MACHINE_LOCK_TEST_EXPECT_BUSY=1")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
		return cmd
	}

	rootLock := requireMacLock(t, home, uid)
	if output, err := asOwner(true).CombinedOutput(); err != nil {
		t.Fatalf("the owner did not see the root-held lock: %v (%s)", err, output)
	}
	if err := rootLock.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate interruption before root could hand off a preparation.
	stale := filepath.Join(library, macPreparePrefix+"0123456789abcdef01234567")
	if err := os.WriteFile(stale, nil, 0600); err != nil {
		t.Fatal(err)
	}
	child := asOwner(false)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = child.Process.Kill(); _ = child.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("administrator fixture did not acquire its lock: %q (%v)", line, err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the owner did not clear the abandoned root preparation: %v", err)
	}
	requireBusyMacLock(t, home, uid)
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	requireNoMacLockArtifacts(t, home)
}

func TestMacPackageLockFixtureChild(t *testing.T) {
	home := os.Getenv("MACHINE_LOCK_TEST_HOME")
	if home == "" {
		t.Skip("child fixture only")
	}
	uid, err := strconv.Atoi(os.Getenv("MACHINE_LOCK_TEST_UID"))
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("MACHINE_LOCK_TEST_EXPECT_BUSY") == "1" {
		requireBusyMacLock(t, home, uid)
		return
	}
	requireMacLock(t, home, uid)
	fmt.Println("locked")
	_, _ = os.Stdin.Read(make([]byte, 1))
}
