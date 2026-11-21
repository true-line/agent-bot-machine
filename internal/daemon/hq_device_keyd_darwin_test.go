package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/output"
	"golang.org/x/sys/unix"
)

func TestHQDeviceDarwinCodeRequirement(t *testing.T) {
	dir, err := os.Open("/bin")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	ref, err := deviceDirectoryReference(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = verifyDeviceCode(ctx, ref, "echo", "anchor apple"); err != nil {
		t.Fatal("Apple signature requirement was not evaluated", err)
	}
	if verifyDeviceCode(ctx, ref, "echo", deviceKeydRequirement) == nil {
		t.Fatal("system executable accepted as keyd")
	}
}

func TestHQDeviceDarwinParentReferenceSurvivesMove(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "bin")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	ref, err := deviceDirectoryReference(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, filepath.Join(base, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(ref, "fixture"))
	if err != nil || string(raw) != "original" {
		t.Fatal("directory reference followed replacement")
	}
}

func TestDeviceKeydDirectoryPermissionDiagnostic(t *testing.T) {
	const administrator uint32 = 501
	for _, tc := range []struct {
		name, path, want string
		uid, gid, mode   uint32
		ancestor         bool
	}{
		{"root ancestor", "/opt", "", 0, 0, 0755, true},
		{"prefix admin group", "/opt/homebrew", "", administrator, 80, 0775, true},
		{"cellar admin group", "/opt/homebrew/Cellar", "", administrator, 80, 0775, true},
		{"cellar wheel group", "/opt/homebrew/Cellar", "mode 0775 allows group 0 to write", administrator, 0, 0775, true},
		{"cellar wheel read", "/opt/homebrew/Cellar", "", administrator, 0, 0755, true},
		{"foreign owner", "/opt/homebrew/Cellar", "owned by UID 502", 502, 80, 0755, true},
		{"world write", "/opt/homebrew/Cellar", "mode 0777 allows other users to write", administrator, 80, 0777, true},
		{"outside exception", "/usr/local/Cellar", "mode 0775 allows group 80 to write", administrator, 80, 0775, true},
		{"final directory", "/opt/homebrew/Cellar", "mode 0775 allows group 80 to write", administrator, 80, 0775, false},
		{"package bin", "/opt/homebrew/Cellar/managed-machine/1/bin", "mode 0775 allows group 80 to write", administrator, 80, 0775, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := deviceKeydDirectoryIssue(tc.path, unix.Stat_t{Uid: tc.uid, Gid: tc.gid, Mode: uint16(tc.mode)}, int(administrator), tc.ancestor)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.path) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected issue %v", err)
			}
		})
	}
}

func TestDaemonStatusOnlyShowsKeydPathIssueInAdministratorHumanOutput(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "machine-keyd-status-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	executable := filepath.Join(dir, "managed-machine")
	for _, name := range []string{executable, filepath.Join(dir, "agent-bot-keyd")} {
		if err := os.WriteFile(name, nil, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(channelEnv, filepath.Join(t.TempDir(), "channel"))
	home := t.TempDir()
	deps := owner(home)
	caller := Caller{UID: 501, Username: "admin", RegisteredHome: home, Home: home, PrefixOwner: "admin", DarwinAdmin: true}
	inspections := 0
	deps.Executable = func() (string, error) { inspections++; return executable, nil }
	deps.Caller = func() (Caller, error) { return caller, nil }

	runStatus := func(mode string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		app := &cli.App{Name: "managed-machine", Commands: []cli.Command{Command(deps)}, Stdout: &stdout, Stderr: &stderr}
		if code := app.Run([]string{"daemon", "status", mode}); code != 0 || stderr.Len() != 0 {
			t.Fatalf("status changed exit or stderr: %d %s", code, stderr.String())
		}
		return stdout.String()
	}
	for _, mode := range []output.Mode{output.Compact, output.JSON} {
		result := run(deps, cli.Context{Mode: mode}, []string{"status"})
		if result.Human != "" || result.Diagnostic != nil || inspections != 0 {
			t.Fatalf("structured status performed the custody diagnostic: %+v", result)
		}
	}
	structured := runStatus("--json")
	human := runStatus("--human")
	if !strings.Contains(human, "Bundled keyd custody path refused") || !strings.Contains(human, "/private/tmp") ||
		!strings.Contains(human, "allows other users to write") || inspections != 1 {
		t.Fatalf("missing actionable administrator output: %s", human)
	}
	administrator := caller
	for _, other := range []Caller{
		{UID: 501, Username: "admin", Home: home, RegisteredHome: home, PrefixOwner: "different", DarwinAdmin: true},
		{UID: 501, Username: "admin", Home: home, RegisteredHome: home, PrefixOwner: "admin"},
		{UID: 0, Username: "root", Home: home, RegisteredHome: home, PrefixOwner: "root", DarwinAdmin: true},
		{UID: 501, Username: "admin", Home: dir, RegisteredHome: home, PrefixOwner: "admin", DarwinAdmin: true},
	} {
		caller = other
		if got := runStatus("--human"); strings.Contains(got, "custody path") || inspections != 1 {
			t.Fatalf("unqualified caller ran the local path check: %s", got)
		}
		if got := runStatus("--json"); got != structured {
			t.Fatalf("JSON status changed: %s", got)
		}
	}
	caller = administrator
	if err := os.Remove(filepath.Join(dir, "agent-bot-keyd")); err != nil {
		t.Fatal(err)
	}
	if got := runStatus("--human"); strings.Contains(got, "custody path") {
		t.Fatalf("manual installation received a bundled-keyd warning: %s", got)
	}
}
