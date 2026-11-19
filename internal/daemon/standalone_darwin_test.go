package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMachineAndDeclarationSerializeFirstUse(t *testing.T) {
	library, home := t.TempDir(), t.TempDir()
	ns := filepath.Join(library, standaloneNamespace)
	if err := os.MkdirAll(ns, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"declaration-pending-v1", "declaration-v1"} {
		path := filepath.Join(ns, name)
		if err := os.WriteFile(path, []byte("public fixture"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := prepareMachineLifecycleAt(library, home); err == nil {
			t.Fatal("Machine began with a pending or active declaration")
		}
		if _, err := os.Stat(stateDir(home)); !os.IsNotExist(err) {
			t.Fatal("refused operation created state")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareMachineLifecycleAt(library, home); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(stateDir(home))
	if err != nil || !st.IsDir() {
		t.Fatal("first Machine startup must be visible to subsequent issuance")
	}
	if err := os.WriteFile(filepath.Join(ns, "machine-retired-v1"), []byte("retired"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := prepareMachineLifecycleAt(library, home); err != nil {
		t.Fatal(err)
	}
}

func TestAdministratorStandaloneDeclaration(t *testing.T) {
	cmd := exec.Command("/usr/bin/ruby", "--disable-gems", "../../tests/fixtures/standalone-hq-signing.rb")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("public fixture: %v: %s", err, out)
	}
}
