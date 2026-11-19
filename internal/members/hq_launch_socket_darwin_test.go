package members

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
			err = unlinkStoppedSocket(parent, filepath.Base(path), observed, uid, pid)
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

func TestInterruptedUpgradeBootoutPreservesSocketProvenance(t *testing.T) {
	for _, scenario := range []string{"captured", "replaced", "no capture", "already removed", "journal unavailable",
		"stays absent", "original reappears", "replacement after absence"} {
		t.Run(scenario, func(t *testing.T) {
			dir, err := os.MkdirTemp("/private/tmp", "mm-stop.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			parent, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			path := filepath.Join(dir, "owner.sock")
			bind := func() func() {
				t.Helper()
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				closeSocket := func() {
					if fd >= 0 {
						unix.Close(fd)
						fd = -1
					}
				}
				t.Cleanup(closeSocket)
				if err = unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
					t.Fatal(err)
				}
				if err = os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
				return closeSocket
			}
			uid := uint32(os.Geteuid())
			var published os.FileInfo
			var releaseSocket func()
			if scenario != "no capture" {
				releaseSocket = bind()
				published, err = waitForLaunchSocket(path, uid, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			missingAtStop := scenario == "stays absent" || scenario == "original reappears" || scenario == "replacement after absence"
			if missingAtStop {
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
			}
			process := exec.Command("/usr/bin/true")
			if err := process.Run(); err != nil {
				t.Fatal(err)
			}
			pid := strconv.Itoa(process.ProcessState.Pid())
			evidence, err := observedStopEvidence(parent, filepath.Base(path), published, pid, uid)
			if err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(dir, "journal")
			if scenario == "journal unavailable" {
				record = filepath.Join(dir, "absent", "journal")
			}
			j := upgradeJournal{Phase: "starting-next"}
			interrupted := errors.New("interrupted immediately after bootout")
			err = j.recordBootout(record, "stopping-next", evidence, func() error {
				if scenario == "journal unavailable" {
					t.Fatal("bootout preceded durable evidence")
				}
				var before upgradeJournal
				b, e := os.ReadFile(record)
				if e != nil || json.Unmarshal(b, &before) != nil || before.Phase != "stopping-next" ||
					before.Stopping == nil || *before.Stopping != *evidence || before.Stopping.Parent.Inode == 0 || before.Stopping.PID != pid {
					t.Fatal("job, directory and leaf observation were not journaled first")
				}
				if (before.Stopping.Socket.Inode == 0) != (missingAtStop || scenario == "no capture") {
					t.Fatal("wrong recorded leaf state")
				}
				return interrupted
			})
			if scenario == "journal unavailable" {
				if err == nil || errors.Is(err, interrupted) {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			switch scenario {
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				bind()
			case "no capture", "replacement after absence":
				bind()
			case "original reappears":
				if err := os.Rename(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "already removed":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			// Re-open the durable journal as a new apply would. Only the captured
			// endpoint gets as far as the separate kernel-guarded removal boundary.
			b, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			var restored upgradeJournal
			if err = json.Unmarshal(b, &restored); err != nil {
				t.Fatal(err)
			}
			unowned := scenario == "replaced" || scenario == "no capture" || scenario == "original reappears" || scenario == "replacement after absence"
			if unowned {
				replacement, e := waitForLaunchSocket(path, uid, 0)
				if e != nil {
					t.Fatal(e)
				}
				changed, e := observedStopEvidence(parent, filepath.Base(path), replacement, pid, uid)
				if e != nil {
					t.Fatal(e)
				}
				if e = restored.recordBootout(record, "stopping-next", changed, func() error {
					t.Fatal("second stop adopted a new endpoint")
					return nil
				}); e == nil {
					t.Fatal("replaced recorded evidence")
				}
			}
			if scenario == "stays absent" {
				changedPID := *evidence
				changedPID.PID = "1"
				if e := restored.recordBootout(record, "stopping-next", &changedPID, func() error {
					t.Fatal("changed process accepted with absent leaf")
					return nil
				}); e == nil {
					t.Fatal("absent leaf lost its job identity")
				}
			}
			called := false
			err = clearRecordedEndpoint(path, restored.Stopping, func(d *os.File, f os.FileInfo, p string) error {
				called = true
				if published == nil || !os.SameFile(published, f) || d.Name() != dir || p != pid {
					t.Fatal("unverified removal")
				}
				kernel, err := unix.Sysctl("kern.osrelease")
				if err != nil {
					t.Fatal(err)
				}
				if !supportsGuardedUpgrade(kernel) {
					// Older Darwin retains the recorded node for operator recovery.
					if err = unlinkStoppedSocket(d, filepath.Base(path), f, uid, p); !errors.Is(err, unix.EINVAL) {
						t.Fatal(err)
					}
					return nil
				}
				busy := false
				err = retryBusyHQEndpoint(func() error {
					e := unlinkStoppedSocket(d, filepath.Base(path), f, uid, p)
					if errors.Is(e, unix.EBUSY) {
						busy = true
						releaseSocket()
					}
					return e
				})
				if !busy {
					t.Fatal("kernel did not protect open socket")
				}
				if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("original endpoint not removed after release")
				}
				return err
			})
			if (err != nil) != unowned || called != (scenario == "captured") {
				t.Fatalf("called=%v, error=%v", called, err)
			}
			if unowned {
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("unowned entry was removed")
				}
			}
			if unowned && scenario != "original reappears" {
				if _, err := observedStopEvidence(parent, filepath.Base(path), published, pid, uid); err == nil {
					t.Fatal("accepted changed endpoint before bootout")
				}
			}
		})
	}
}

// Pre-existing journals have no stopping record until a stop was captured.
func TestUpgradeJournalWithoutStopEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.sock")
	remove := func(*os.File, os.FileInfo, string) error { t.Fatal("unexpected removal"); return nil }
	if err := clearRecordedEndpoint(path, nil, remove); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := clearRecordedEndpoint(path, nil, remove); err == nil {
		t.Fatal("unrecorded leaf accepted")
	}
}

func TestUpgradeRetriesOnlyBusyEndpoint(t *testing.T) {
	other := errors.New("changed inode or pairing")
	tries := 0
	err := retryBusyHQEndpoint(func() error {
		tries++
		if tries == 1 {
			return unix.EBUSY
		}
		return other
	})
	if !errors.Is(err, other) || tries != 2 {
		t.Fatalf("tries=%d, err=%v", tries, err)
	}
	start := time.Now()
	err = retryBusyHQEndpoint(func() error { return unix.EBUSY })
	if !errors.Is(err, unix.EBUSY) || time.Since(start) > 3*time.Second {
		t.Fatal("busy endpoint did not terminate", err)
	}
}
