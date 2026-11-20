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

func TestDarwinServiceRemovalCoordinatesWithInstall(t *testing.T) {
	for _, verb := range []string{"stop", "uninstall"} {
		t.Run(verb, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(channelEnv, filepath.Join(home, "channel"))
			if err := os.Mkdir(filepath.Join(home, "Library"), 0700); err != nil {
				t.Fatal(err)
			}
			deps := owner(home)
			for _, name := range []string{"managed-machine", "agent-bot-keyd"} {
				if err := os.WriteFile(filepath.Join(home, name), []byte("fixture"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			deps.Executable = func() (string, error) { return filepath.Join(home, "managed-machine"), nil }
			deps.Caller = func() (Caller, error) {
				return Caller{Username: "admin", UID: os.Getuid(), Home: home, RegisteredHome: home}, nil
			}
			deps.LockLifecycle = testMacPackageLock
			stops := 0
			deps.Deactivate = func(string) error { stops++; return nil }
			overlapped := false
			deps.Activate = func(path string) error {
				if filepath.Base(path) != darwinServiceLabel+".plist" {
					return nil
				}
				overlapped = true
				// Both plists exist, and the ongoing install still owns its lifecycle lock.
				result := run(deps, cli.Context{}, []string{verb})
				if result.Diagnostic == nil || !strings.Contains(result.Diagnostic.Message, "lifecycle is busy") || stops != 0 {
					t.Errorf("overlapping %s: diagnostic %v, stopped %d jobs", verb, result.Diagnostic, stops)
				}
				return nil
			}
			if result := run(deps, cli.Context{}, []string{"install"}); result.Diagnostic != nil {
				t.Fatal(result.Diagnostic.Message)
			}
			if !overlapped {
				t.Fatal("did not reach Machine activation")
			}
			for _, label := range []string{darwinServiceLabel, darwinKeydServiceLabel} {
				if _, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", label+".plist")); err != nil {
					t.Error(err)
				}
			}
			if result := run(deps, cli.Context{}, []string{verb}); result.Diagnostic != nil || stops != 2 {
				t.Fatalf("retry %s: diagnostic %v, stopped %d jobs", verb, result.Diagnostic, stops)
			}
		})
	}
}

func TestDarwinServiceLifecycleRetainsSeparateHelperAndChangedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv(channelEnv, filepath.Join(home, "channel"))
	deps := owner(home)
	caller := Caller{Username: "admin", Home: home, RegisteredHome: home, UID: os.Getuid()}
	deps.Caller = func() (Caller, error) { return caller, nil }
	current := filepath.Join(home, "new", "managed-machine")
	deps.Executable = func() (string, error) { return current, nil }
	old := filepath.Join(home, "previous", "managed-machine")
	state := filepath.Join(home, ".local", "state", "agent-bot")
	file, err := Install("darwin", home, old, "")
	if err != nil {
		t.Fatal(err)
	}
	keydPath, _ := keydUnitPath("darwin", home)
	priorKeyd := filepath.Join(filepath.Dir(old), "agent-bot-keyd")
	keydBody := keydAgent(state, priorKeyd)
	if err := os.WriteFile(keydPath, []byte(keydBody), 0600); err != nil {
		t.Fatal(err)
	}
	deps.ReadUserJob = func(_ int, domain, label string) ([]byte, bool, error) {
		if domain != "gui" || label != darwinKeydServiceLabel {
			return nil, false, nil
		}
		return []byte("\tpath = " + keydPath + "\n\tprogram = " + priorKeyd + "\n\targuments = {\n\t\t" + priorKeyd + "\n\t\tserve\n\t\t--state-dir\n\t\t" + state + "\n\t}\n"), true, nil
	}
	if _, err := inspectServiceLifecycle(caller, home, current, "stop", deps.ReadUserJob); err != nil {
		t.Fatalf("previous manual installation: %v", err)
	}
	// A newly supplied independent plist must survive an uninstall in progress.
	deps.Deactivate = func(path string) error {
		if path == keydPath {
			temp := keydPath + ".replacement"
			if err := os.WriteFile(temp, []byte("independent replacement"), 0600); err != nil {
				return err
			}
			return os.Rename(temp, keydPath)
		}
		return nil
	}
	result := run(deps, cli.Context{}, []string{"uninstall"})
	if result.Diagnostic == nil {
		t.Fatal("reported successful uninstall of replaced registration")
	}
	if body, err := os.ReadFile(keydPath); err != nil || string(body) != "independent replacement" {
		t.Fatal("independent replacement removed")
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatal("unchanged Machine unit was not removed")
	}

	// With no sibling executable, Machine-only startup leaves independent keyd alone.
	var actions []string
	deps.Activate = func(path string) error { actions = append(actions, path); return nil }
	for _, verb := range []string{"install", "start"} {
		result := run(deps, cli.Context{}, []string{verb})
		if result.Diagnostic != nil {
			t.Fatal(result.Diagnostic.Message)
		}
	}
	if len(actions) != 2 || actions[0] != file || actions[1] != file {
		t.Fatal("Machine-only startup acted on independent keyd")
	}
}

func TestDarwinManualRemovalLeavesRegisteredIdentityKeyd(t *testing.T) {
	for _, verb := range []string{"stop", "uninstall"} {
		t.Run(verb, func(t *testing.T) {
			home := t.TempDir()
			deps := owner(home)
			caller := Caller{Username: "admin", UID: os.Getuid(), Home: home + "/", RegisteredHome: home}
			deps.Caller = func() (Caller, error) { return caller, nil }
			deps.Root = func() (string, error) { return caller.Home, nil }
			exe := filepath.Join(home, "manual", "managed-machine")
			deps.Executable = func() (string, error) { return exe, nil }
			machine, err := Install("darwin", home, exe, "")
			if err != nil {
				t.Fatal(err)
			}
			keyd, _ := keydUnitPath("darwin", home)
			state := filepath.Join(home, ".local", "state", "agent-bot")
			program := filepath.Join(home, "identity", "agent-bot-keyd")
			identityUnit := strings.ReplaceAll(keydAgent(state, program), "\t", "  ")
			if err := os.WriteFile(keyd, []byte(identityUnit), 0600); err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(state, "keyd", "keyd.json")
			if err := os.MkdirAll(filepath.Dir(record), 0700); err != nil {
				t.Fatal(err)
			}
			deps.ReadUserJob = func(_ int, domain, label string) ([]byte, bool, error) {
				if domain == "gui" && label == darwinKeydServiceLabel {
					return []byte("\tpath = " + keyd + "\n\tprogram = " + program + "\n\targuments = {\n\t\t" + program + "\n\t\tserve\n\t\t--state-dir\n\t\t" + state + "\n\t}\n"), true, nil
				}
				return nil, false, nil
			}
			var stopped []string
			deps.Deactivate = func(p string) error { stopped = append(stopped, p); return nil }
			if result := run(deps, cli.Context{}, []string{verb}); result.Diagnostic == nil || len(stopped) != 0 {
				t.Fatal("missing independent ownership record was accepted")
			}
			bytes := []byte(fmt.Sprintf("{\"bin\":%q,\"label\":%q}\n", program, darwinKeydServiceLabel))
			if err := os.WriteFile(record, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if result := run(deps, cli.Context{}, []string{verb}); result.Diagnostic != nil {
				t.Fatal(result.Diagnostic.Message)
			}
			if len(stopped) != 1 || stopped[0] != machine {
				t.Fatal("wrong service stopped")
			}
			if got, err := os.ReadFile(keyd); err != nil || string(got) != identityUnit {
				t.Fatal("changed independent plist")
			}
			if got, err := os.ReadFile(record); err != nil || string(got) != string(bytes) {
				t.Fatal("changed independent record")
			}
			if _, err := os.Stat(machine); verb == "stop" && err != nil || verb == "uninstall" && !os.IsNotExist(err) {
				t.Fatal("wrong Machine plist outcome", err)
			}
			caller.RegisteredHome = "/var/empty"
			caller.Home = "/private/var/empty"
			if caller.Refuse() == "" {
				t.Fatal("caller accepted a differently spelled registered home")
			}
		})
	}
}

func TestDarwinServiceLifecycleAcceptsOldHomebrewKeg(t *testing.T) {
	home := t.TempDir()
	caller := Caller{Home: home, RegisteredHome: home, UID: os.Getuid()}
	dir := "/opt/homebrew/Cellar/managed-machine/0.12.4/bin"
	machine := filepath.Join(dir, "managed-machine")
	bin := filepath.Join(dir, "agent-bot-keyd")
	state := filepath.Join(home, ".local", "state", "agent-bot")
	if _, err := Install("darwin", home, machine, ""); err != nil {
		t.Fatal(err)
	}
	file, _ := keydUnitPath("darwin", home)
	if err := os.WriteFile(file, []byte(keydAgent(state, bin)), 0600); err != nil {
		t.Fatal(err)
	}
	readJob := func(_ int, domain, label string) ([]byte, bool, error) {
		if domain != "user" || label != darwinKeydServiceLabel {
			return nil, false, nil
		}
		return []byte("\tpath = " + file + "\n\tprogram = " + bin + "\n\targuments = {\n\t\t" + bin + "\n\t\tserve\n\t\t--state-dir\n\t\t" + state + "\n\t}\n"), true, nil
	}
	if _, err := inspectServiceLifecycle(caller, home, "/opt/homebrew/opt/managed-machine/bin/managed-machine", "stop", readJob); err != nil {
		t.Fatal(err)
	}
}

// A missing shared plist is not evidence that keyd belongs to Machine.
func TestDarwinSharedKeydLifecycle(t *testing.T) {
	for _, verb := range []string{"install", "start", "stop", "uninstall"} {
		for _, record := range []string{"absent", "Machine", "Identity", "loaded-only", "wrong-program", "nested-only"} {
			t.Run(verb+"/"+record, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv(channelEnv, filepath.Join(home, "channel"))
				exe := filepath.Join(home, "bin", "managed-machine")
				keyd := filepath.Join(filepath.Dir(exe), "agent-bot-keyd")
				if err := os.Mkdir(filepath.Dir(exe), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyd, []byte("fixture"), 0700); err != nil {
					t.Fatal(err)
				}
				file, _ := keydUnitPath("darwin", home)
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(home, ".local", "state", "agent-bot")
				body := keydAgent(state, keyd)
				if record == "Identity" {
					body = strings.ReplaceAll(body, "\t", "  ")
				}
				if record != "absent" && record != "loaded-only" {
					if err := os.WriteFile(file, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
				deps := owner(home)
				deps.Caller = func() (Caller, error) {
					return Caller{Username: "admin", UID: os.Getuid(), Home: home, RegisteredHome: home}, nil
				}
				deps.Executable = func() (string, error) { return exe, nil }
				deps.ReadUserJob = func(_ int, domain, label string) ([]byte, bool, error) {
					if record == "absent" || label != darwinKeydServiceLabel || domain != "user" {
						return nil, false, nil
					}
					program := keyd
					if record == "wrong-program" {
						program = filepath.Join(home, "other", "agent-bot-keyd")
					}
					indent := "\t"
					if record == "nested-only" {
						indent = "\t\t"
					}
					out := indent + "path = " + file + "\n" + indent + "program = " + program + "\n\targuments = {\n\t\t" + program + "\n\t\tserve\n\t\t--state-dir\n\t\t" + state + "\n\t}\n"
					return []byte(out), true, nil
				}
				managerCalls := 0
				deps.Activate = func(string) error { managerCalls++; return nil }
				deps.Deactivate = deps.Activate
				result := run(deps, cli.Context{}, []string{verb})
				if record == "absent" || record == "Machine" {
					if result.Diagnostic != nil || managerCalls == 0 {
						t.Fatalf("valid %s refused: %v", record, result.Diagnostic)
					}
					return
				}
				if result.Diagnostic == nil || managerCalls != 0 {
					t.Fatalf("unproved %s was acted on: %v (%d calls)", record, result.Diagnostic, managerCalls)
				}
				got, err := os.ReadFile(file)
				if record == "loaded-only" {
					if !os.IsNotExist(err) {
						t.Fatal("overwrote absent plist")
					}
				} else if err != nil || string(got) != body {
					t.Fatal("changed original plist")
				}
			})
		}
	}
}

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
			deps.Deactivate = func(path string) error { return DeactivateUserService("darwin", path) }
			result := run(deps, cli.Context{}, []string{tc.verb})
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
