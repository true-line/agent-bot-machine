package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
)

func TestDarwinStopAndUninstallCheckBothDomains(t *testing.T) {
	const unloaded = "exit 0"
	const absent = "echo 'Boot-out failed: 3: No such process' >&2; exit 3"
	const noDomain = "echo 'Could not find domain for user gui' >&2; exit 112"
	const noService = "echo 'Could not find specified service' >&2; exit 113"
	const ioFailure = "echo 'Boot-out failed: 5: Input/output error' >&2; exit 5"
	const missingFile = "echo 'No such file or directory' >&2; exit 2"
	const refused = "echo 'Operation not permitted' >&2; exit 1"

	for _, tc := range []struct {
		name, verb, gui, user string
		keyd                  bool
		failedDomains         []string
	}{
		{"stop-gui-refused-user-absent", "stop", refused, absent, false, []string{"gui"}},
		{"uninstall-gui-absent-keyd-user-refused", "uninstall", absent, refused, true, []string{"user"}},
		{"uninstall-user-unloaded-gui-refused", "uninstall", refused, unloaded, false, []string{"gui"}},
		{"uninstall-both-refused", "uninstall", refused, refused, false, []string{"gui", "user"}},
		{"uninstall-domain-unavailable-user-absent", "uninstall", noDomain, noService, true, nil},
		{"uninstall-domain-unavailable-user-denied", "uninstall", noDomain, refused, false, []string{"user"}},
		{"stop-gui-io-error", "stop", ioFailure, absent, false, []string{"gui"}},
		{"uninstall-user-file-error", "uninstall", absent, missingFile, true, []string{"user"}},
		{"stop-both-absent", "stop", absent, absent, false, nil},
		{"uninstall-gui-unloaded-user-absent", "uninstall", unloaded, absent, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			machine, _ := unitPath("darwin", root)
			keyd, _ := keydUnitPath("darwin", root)
			if err := os.MkdirAll(filepath.Dir(machine), 0700); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{machine, keyd} {
				if err := os.WriteFile(path, []byte("<key>Label</key><string>fixture.unrelated</string>"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target := machine
			if tc.keyd {
				target = keyd
			}
			script := fmt.Sprintf(`#!/bin/sh
[ "$#" = 2 ] && [ "$1" = bootout ] || exit 64
case "$2" in
    gui/%d/dev.qwts.agent-machine|user/%[1]d/dev.qwts.agent-machine|gui/%[1]d/dev.qwts.agent-bot.keyd|user/%[1]d/dev.qwts.agent-bot.keyd) ;;
    *) exit 64 ;;
esac
[ "${2##*/}.plist" = "%[2]s" ] || exit 0
case "$2" in
    gui/*) %[3]s ;;
    user/*) %[4]s ;;
    *) exit 64 ;;
esac
`, os.Getuid(), filepath.Base(target), tc.gui, tc.user)
			if err := os.WriteFile(filepath.Join(root, "launchctl"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root)
			deps := owner(root)
			var attempted []string
			deps.Deactivate = func(path string) error {
				attempted = append(attempted, path)
				return DeactivateUserService("darwin", path)
			}
			result := run(deps, cli.Context{}, []string{tc.verb})
			if len(attempted) != 2 || attempted[0] != machine || attempted[1] != keyd {
				t.Fatalf("expected to stop both Machine and keyd, attempted %v", attempted)
			}
			if len(tc.failedDomains) > 0 {
				if result.Diagnostic == nil || result.Diagnostic.ID != diag.DaemonServiceFailed {
					t.Fatalf("expected unload failure, got %+v", result)
				}
				for _, domain := range tc.failedDomains {
					if !strings.Contains(result.Diagnostic.Message, domain+"/") {
						t.Fatalf("missing %s failure in %s", domain, result.Diagnostic.Message)
					}
				}
			} else if result.Diagnostic != nil {
				t.Fatal(result.Diagnostic.Message)
			}
			for _, path := range []string{machine, keyd} {
				data, err := os.ReadFile(path)
				if tc.verb == "uninstall" && len(tc.failedDomains) == 0 {
					if !os.IsNotExist(err) {
						t.Fatalf("expected %s to be removed, got %v", filepath.Base(path), err)
					}
				} else if err != nil || string(data) != "<key>Label</key><string>fixture.unrelated</string>" {
					t.Fatalf("failed to retain %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

func TestDarwinUninstallWithoutPlistsUsesOnlyMachineServiceTargets(t *testing.T) {
	root := t.TempDir()
	stub := filepath.Join(root, "launchctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\nexit 3\n"
	if err := os.WriteFile(stub, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	deps := owner(root)
	deps.Deactivate = func(path string) error { return DeactivateUserService("darwin", path) }
	if result := run(deps, cli.Context{}, []string{"uninstall"}); result.Diagnostic != nil {
		t.Fatal(result.Diagnostic.Message)
	}
	if err := deps.Deactivate(filepath.Join(root, "fixture.unrelated.plist")); err == nil {
		t.Fatal("accepted an unknown unit")
	}
	got, err := os.ReadFile(stub + ".calls")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("bootout gui/%[1]d/dev.qwts.agent-machine\nbootout user/%[1]d/dev.qwts.agent-machine\nbootout gui/%[1]d/dev.qwts.agent-bot.keyd\nbootout user/%[1]d/dev.qwts.agent-bot.keyd\n", os.Getuid())
	if string(got) != want {
		t.Fatalf("unexpected unload targets: %s", got)
	}
}

func TestDarwinStopReportsBothServiceErrors(t *testing.T) {
	deps := owner(t.TempDir())
	deps.Deactivate = func(path string) error { return fmt.Errorf("unload failed for %s", filepath.Base(path)) }
	res := run(deps, cli.Context{}, []string{"stop"})
	if res.Diagnostic == nil || res.Diagnostic.ID != diag.DaemonServiceFailed {
		t.Fatalf("expected a service failure, got %+v", res.Diagnostic)
	}
	for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
		if !strings.Contains(res.Diagnostic.Message, "unload failed for "+label+".plist") {
			t.Fatalf("missing error for %s in %q", label, res.Diagnostic.Message)
		}
	}
}
