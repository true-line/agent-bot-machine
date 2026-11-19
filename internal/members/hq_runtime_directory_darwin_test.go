package members

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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
