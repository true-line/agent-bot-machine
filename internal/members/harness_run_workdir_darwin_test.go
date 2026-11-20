package members

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHarnessWorkdirByDescriptor(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	request := harnessRunInput{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", MemberID: "agent.one"}
	open := func() (*os.File, error) { return harnessWorkdir(home, os.Geteuid(), request) }
	d, err := open()
	if err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(home, ".agent-bot-hq", "souls", request.SoulID, request.MemberID)
	st, err := d.Stat()
	d.Close()
	actual, e := os.Lstat(expected)
	if err != nil || e != nil || !os.SameFile(st, actual) || st.Mode().Perm() != 0700 {
		t.Fatal("wrong working directory")
	}
	d, err = open()
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := os.Remove(expected); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(home, expected); err != nil {
		t.Fatal(err)
	}
	if d, err = open(); err == nil {
		d.Close()
		t.Fatal("followed a member workdir symlink")
	}
}

func TestHarnessNativeStateDefaultsArePrivateAndStable(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	policy := exampleHarness()
	grant := installedHarness{Digest: strings.Repeat("d", 64), Policy: policy}
	req := harnessRunInput{PlanDigest: grant.Digest, AdapterID: "adapter-one", LaunchID: "ln_01c4eabcfedcba00000000ff",
		SoulID: "agent_01234567-0123-4567-0123-456789abcdef", Role: "agent", MemberToken: strings.Repeat("b", 48)}
	keys := []string{"HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"}
	run := func(member, expected string) map[string]string {
		t.Helper()
		req.MemberID = member
		cmd, _, err := harnessAdapterCommand(grant, req, 321)
		if err != nil {
			t.Fatal(err)
		}
		work, err := prepareHarnessWorkdir(cmd, home, os.Geteuid(), req)
		if err != nil {
			t.Fatal(err)
		}
		defer work.Close()
		wanted := filepath.Join(home, ".agent-bot-hq", "souls", req.SoulID, member)
		if work.Name() != wanted {
			t.Fatalf("ACP working directory changed: %q", work.Name())
		}
		env := map[string]string{}
		for _, v := range cmd.Env {
			k, p, ok := strings.Cut(v, "=")
			if !ok {
				t.Fatal("malformed environment")
			}
			if _, dup := env[k]; dup {
				t.Fatalf("duplicate variable %s", k)
			}
			env[k] = p
		}
		if env["PATH"] != "/usr/bin:/bin" {
			t.Fatal("unexpected executable search path")
		}
		for _, k := range keys {
			p := env[k]
			if p == "" || !strings.HasPrefix(p, wanted+string(os.PathSeparator)) {
				t.Fatalf("wrong location for %s", k)
			}
			st, err := os.Lstat(p)
			if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
				t.Fatalf("invalid %s directory: %v", k, err)
			}
		}
		// Observe the actual child defaults through an inert system utility.
		probe := exec.Command("/bin/sh", "-c", `set -eu
for dir in "$HOME" "$XDG_CACHE_HOME" "$TMPDIR"; do
  if [ "$1" = fresh ]; then test ! -e "$dir/marker"; printf %s "$2" > "$dir/marker"
  else test "$(cat "$dir/marker")" = "$2"; fi
done`, "fixture", expected, member)
		probe.Env, probe.Dir = cmd.Env, work.Name()
		if err := probe.Run(); err != nil {
			t.Fatalf("member %s: %v", member, err)
		}
		return env
	}
	first := run("Writer", "fresh")
	for _, name := range []string{"reader", "editor"} {
		second := run(name, "fresh")
		for _, k := range keys {
			a, e := os.Stat(first[k])
			if e != nil {
				t.Fatal(e)
			}
			b, e := os.Stat(second[k])
			if e != nil {
				t.Fatal(e)
			}
			if os.SameFile(a, b) {
				t.Fatalf("members share %s", k)
			}
		}
	}
	reopened := run("Writer", "reopen")
	for _, k := range keys {
		if first[k] != reopened[k] {
			t.Fatal("failed to reopen same member", k)
		}
	}
	cache := first["XDG_CACHE_HOME"]
	if err := os.Chmod(cache, 0755); err != nil {
		t.Fatal(err)
	}
	req.MemberID = "Writer"
	if d, e := prepareHarnessWorkdir(&exec.Cmd{}, home, os.Geteuid(), req); e == nil {
		d.Close()
		t.Fatal("reused a nonprivate state directory")
	}
	if err := os.Rename(cache, cache+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(home, cache); err != nil {
		t.Fatal(err)
	}
	if d, e := prepareHarnessWorkdir(&exec.Cmd{}, home, os.Geteuid(), req); e == nil {
		d.Close()
		t.Fatal("followed a redirected cache")
	}
}

func TestHarnessWorkdirRefusesCaseAliasedMember(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	req := harnessRunInput{SoulID: "agent_01234567-0123-4567-0123-456789abcdef", MemberID: "Writer"}
	first, err := harnessWorkdir(home, os.Geteuid(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	original, err := first.Stat()
	if err != nil {
		t.Fatal(err)
	}
	aliasPath := filepath.Join(filepath.Dir(first.Name()), "writer")
	alias, statErr := os.Lstat(aliasPath)
	req.MemberID = "writer"
	other, err := harnessWorkdir(home, os.Geteuid(), req)
	switch {
	case statErr == nil && os.SameFile(original, alias):
		if other != nil || err == nil {
			t.Fatal("accepted a second member spelling for the first directory")
		}
	case os.IsNotExist(statErr):
		if err != nil {
			t.Fatal("case-sensitive filesystem should support both spellings", err)
		}
		defer other.Close()
		distinct, e := other.Stat()
		if e != nil || os.SameFile(original, distinct) {
			t.Fatal("expected distinct member workspaces", e)
		}
	default:
		t.Fatal("unexpected fixture state", statErr)
	}
	req.MemberID = "Writer"
	reopened, err := harnessWorkdir(home, os.Geteuid(), req)
	if err != nil {
		t.Fatal("original spelling unusable", err)
	}
	defer reopened.Close()
	again, err := reopened.Stat()
	if err != nil || !os.SameFile(original, again) {
		t.Fatal("original member workspace changed", err)
	}
}
