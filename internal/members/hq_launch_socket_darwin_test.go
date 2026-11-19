package members

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRollbackOfObservedLaunchSocket(t *testing.T) {
	release, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		t.Fatal(err)
	}
	version, _, _ := strings.Cut(release, ".")
	major, err := strconv.Atoi(version)
	if err != nil {
		t.Fatal(err)
	}
	// Darwin 24 (macOS 15) rejects AT_NODELETEBUSY before vnode lookup.
	hasGuardedUnlink := major >= 25
	for _, scenario := range []string{
		"closed", "absent", "live listener", "bound socket", "live pid", "invalid pid",
		"replacement socket", "regular file", "symlink", "mode changed", "wrong owner",
		"writable parent", "replaced parent", "unobserved",
	} {
		t.Run(scenario, func(t *testing.T) {
			temp, err := os.MkdirTemp("/private/tmp", "hq-rb.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(temp) })
			dir := filepath.Join(temp, "dir")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			parent, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			path := filepath.Join(dir, filepath.Base(launchSocket))
			bind := func() int {
				t.Helper()
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
					unix.Close(fd)
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0666); err != nil {
					unix.Close(fd)
					t.Fatal(err)
				}
				return fd
			}
			fd := bind()
			uid := uint32(os.Geteuid())
			observed, err := waitForLaunchSocket(path, uid, 0)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "live listener" || scenario == "bound socket" {
				defer unix.Close(fd)
			} else if err = unix.Close(fd); err != nil {
				t.Fatal(err)
			}

			pid := ""
			switch scenario {
			case "absent":
				err = os.Remove(path)
			case "live listener":
				err = unix.Listen(fd, 1)
			case "live pid":
				pid = strconv.Itoa(os.Getpid())
			case "invalid pid":
				pid = "-1"
			case "replacement socket", "regular file", "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "replacement socket":
					err = unix.Close(bind())
				case "regular file":
					err = os.WriteFile(path, []byte("retained"), 0644)
				case "symlink":
					err = os.Symlink(path+".original", path)
				}
			case "mode changed":
				err = os.Chmod(path, 0600)
			case "wrong owner":
				uid++
			case "writable parent":
				err = os.Chmod(dir, 0777)
			case "replaced parent":
				if err = os.Rename(dir, dir+".old"); err == nil {
					err = os.Mkdir(dir, 0700)
				}
				if err == nil {
					err = unix.Close(bind())
				}
			case "unobserved":
				observed = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			originalEntry, _ := os.Lstat(path)
			err = unlinkStoppedSocket(parent, observed, uid, pid)
			after, statErr := os.Lstat(path)
			if !hasGuardedUnlink && (scenario == "closed" || scenario == "bound socket") {
				if !errors.Is(err, unix.EINVAL) || statErr != nil || !os.SameFile(originalEntry, after) {
					t.Fatalf("unsupported guarded unlink = %v, preserved endpoint = %v", err, statErr)
				}
				return
			}
			if scenario == "closed" || scenario == "absent" {
				if err != nil || !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("rollback = %v, remaining socket = %v", err, statErr)
				}
				return
			}
			if err == nil || statErr != nil || !os.SameFile(originalEntry, after) {
				t.Fatalf("rollback = %v, preserved endpoint = %v", err, statErr)
			}
			if scenario == "bound socket" && !errors.Is(err, unix.EBUSY) {
				t.Fatalf("kernel did not veto removing a bound socket: %v", err)
			}
			if scenario == "replaced parent" {
				if old, err := os.Lstat(filepath.Join(dir+".old", filepath.Base(launchSocket))); err != nil || !os.SameFile(observed, old) {
					t.Fatal("rollback changed the original directory entry", err)
				}
			}
		})
	}
}
