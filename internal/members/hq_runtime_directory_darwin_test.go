package members

import (
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

func TestDarwinRuntimeDirectoryPlan(t *testing.T) {
	secure := Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0755}
	for _, tc := range []struct {
		name    string
		path    string
		entry   Entry
		want    string
		denyACL bool
	}{
		{name: "create", want: ActionCreate},
		{name: "reuse", path: launchRuntimeDir, entry: secure, want: ActionNone},
		{name: "writable ancestor", path: filepath.Dir(launchRuntimeDir), entry: Entry{Dir: true, Owner: "root", Mode: 0775}},
		{name: "foreign product directory", path: launchRuntimeDir, entry: Entry{Dir: true, Owner: "operator", Group: "wheel", Mode: 0755}},
		{name: "group inherited", path: launchRuntimeDir, entry: Entry{Dir: true, Owner: "root", Group: "admin", Mode: 0755}},
		{name: "wrong mode", path: launchRuntimeDir, entry: Entry{Dir: true, Owner: "root", Group: "wheel", Mode: 0700}},
		{name: "linked leaf", path: launchRuntimeDir, entry: Entry{Owner: "root", Group: "wheel", Mode: 0755}},
		{name: "allow ACL", denyACL: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := emptyHost()
			for _, p := range pathAncestry(filepath.Dir(launchRuntimeDir)) {
				h.entries[p] = secure
			}
			if tc.path != "" {
				h.entries[tc.path] = tc.entry
			}
			result, err := planLaunchDirectory(h, func(paths []string) error {
				if !slices.Contains(paths, "/Library/Application Support") || !slices.Contains(paths, "/Library") || !slices.Contains(paths, "/") || (tc.want == ActionNone && !slices.Contains(paths, launchRuntimeDir)) {
					t.Fatal("unchecked ancestry", paths)
				}
				if tc.denyACL {
					return errors.New("fixture ACL")
				}
				return nil
			})
			if tc.want == "" {
				if err == nil {
					t.Fatal("accepted", result)
				}
				return
			}
			if err != nil || *result != (launchDirectory{Path: launchRuntimeDir, Action: tc.want, Owner: "root", Group: "wheel", Mode: "0755"}) {
				t.Fatal(result, err)
			}
		})
	}
}

func TestDarwinRuntimeDirectoryCreationAndRollback(t *testing.T) {
	for _, scenario := range []string{"created", "preexisting", "nonempty", "replacement", "already removed"} {
		t.Run(scenario, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "test owned runtime")
			if scenario == "preexisting" {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
				dir, err := createLaunchDirectory(p, os.Getuid(), os.Getgid())
				if dir != nil || !errors.Is(err, os.ErrExist) {
					t.Fatal("adopted preexisting directory", err)
				}
				original, err := os.Stat(p)
				if err != nil || original.Mode().Perm() != 0700 {
					t.Fatal("pre-existing directory changed", err)
				}
				return
			}
			dir, err := createLaunchDirectory(p, os.Getuid(), os.Getgid())
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			st, err := dir.Stat()
			if err != nil || st.Mode().Perm() != 0755 {
				t.Fatal(st, err)
			}
			switch scenario {
			case "nonempty":
				err = os.WriteFile(filepath.Join(p, "retain"), []byte("test"), 0600)
			case "replacement":
				if err := os.Rename(p, p+".old"); err != nil {
					t.Fatal(err)
				}
				err = os.Mkdir(p, 0755)
			case "already removed":
				err = os.Remove(p)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = removeLaunchDirectory(dir, p)
			_, after := os.Lstat(p)
			if scenario == "nonempty" || scenario == "replacement" {
				if err == nil || after != nil {
					t.Fatal("removed unowned or occupied directory", err, after)
				}
			} else if err != nil || !errors.Is(after, os.ErrNotExist) {
				t.Fatal(err, after)
			}
		})
	}
}

func TestDarwinBrokerDirectoryPublishesExactGroupModeOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fixture")
	dir, err := createProtectedDirectory(p, os.Getuid(), os.Getgid(), os.ModeSetgid|0750)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	st, err := dir.Stat()
	if err != nil || st.Mode().Perm() != 0750 || st.Mode()&os.ModeSetgid == 0 {
		t.Fatal(st, err)
	}
	if err = os.WriteFile(filepath.Join(p, "retain"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = createProtectedDirectory(p, os.Getuid(), os.Getgid(), 0755); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing directory changed", err)
	}
	current, err := os.Lstat(p)
	if err != nil || !os.SameFile(st, current) {
		t.Fatal("lost original directory", err)
	}
}

// Check the kernel's inherited group on two successive Unix listeners. The
// process UID is unchanged; only the directory groups differ.
func TestDarwinBrokerDirectorySocketRestart(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, gid int) {
		dir := filepath.Join(t.TempDir(), "broker")
		pin, err := createProtectedDirectory(dir, os.Getuid(), gid, fileMode(02750))
		if err != nil {
			t.Fatal(err)
		}
		defer pin.Close()
		// A relative leaf avoids Darwin's 103-byte Unix socket path limit
		// under long per-user test roots.
		t.Chdir(dir)
		host := OSHost{}
		expected, exists, err := host.Lstat(".")
		group, groupErr := user.LookupGroupId(strconv.Itoa(gid))
		if err != nil || !exists || groupErr != nil || expected.Group != group.Name || expected.Mode != 02750 {
			t.Fatal("staged directory metadata", err, groupErr)
		}
		for _, cycle := range []string{"start", "restart"} {
			t.Run(cycle, func(t *testing.T) {
				step, err := brokerDirectoryStep(host, dir, expected.Owner, group.Name, 02750)
				if err != nil || step.Action != ActionNone {
					t.Fatal("reviewed directory was not reusable", err)
				}
				const path = "broker.sock"
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := listener.Close(); err != nil {
						t.Error(err)
					}
				})
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
				got, exists, err := host.Lstat(path)
				if err != nil || !exists || got.Owner != expected.Owner || got.Group != group.Name || got.Mode != 0660 {
					t.Fatal("socket did not inherit the reviewed ownership and access", err)
				}
			})
			if _, err := os.Lstat("broker.sock"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stopped listener left an endpoint", err)
			}
		}
	}
	t.Run("primary", func(t *testing.T) { check(t, os.Getgid()) })
	t.Run("supplementary", func(t *testing.T) {
		for _, gid := range groups {
			if gid != os.Getgid() && gid > 0 {
				if _, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
					check(t, gid)
					return
				}
			}
		}
		t.Skip("no other named group for the current process")
	})
}
