//go:build darwin

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/qwts/managed-machine/internal/statedir"
)

func TestMembersPlansExtendedACL(t *testing.T) {
	home := t.TempDir()
	state, err := statedir.Path("darwin", func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "members", "plans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	name := approvePlanID + ".json"
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	setACL := func(p, ace string) {
		t.Helper()
		if err := exec.Command("/bin/chmod", "+a", ace, p).Run(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := exec.Command("/bin/chmod", "-N", p).Run(); err != nil {
				t.Error(err)
			}
		})
	}
	// Home directories commonly deny deletion through an ACL. Listing still works.
	setACL(home, "everyone deny delete")
	opened, err := openMembersPlans(home)
	if err != nil {
		t.Fatal("refused default deny-only home ACL")
	}
	defer opened.Close()
	f, err := openSavedPlan(opened, name)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Run("file allow", func(t *testing.T) {
		// POSIX bits stay private while the ACL grants access.
		if err := exec.Command("/bin/chmod", "+a", "everyone allow read", file).Run(); err != nil {
			t.Fatal(err)
		}
		defer exec.Command("/bin/chmod", "-N", file).Run()
		if _, err := openSavedPlan(opened, name); err == nil {
			t.Fatal("fetched a plan with an extended allow entry")
		}
		raw, err := readMembersPlans(home, "list", "")
		if err != nil || string(raw) != `{"plan_ids":[]}` {
			t.Fatal("listed an ACL-exposed plan")
		}
	})
	setACL(filepath.Dir(state), "everyone allow add_file")
	if _, err := openMembersPlans(home); err == nil {
		t.Fatal("accepted individually writable ancestor through ACL")
	}
}

var testMacPackageLock = statedir.LockMacPackage
