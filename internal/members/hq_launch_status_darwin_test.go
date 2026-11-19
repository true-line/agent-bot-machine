package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerStatusFailureOnlyEmitsPublicClassifications(t *testing.T) {
	job := []byte("system/internal = {\n\tstate = running\n\targuments = {\n\t\tPRIVATE_ARGUMENT\n\t}\n\tlast exit code = 23\n\tstate = PRIVATE_STATE\n\tlast exit code = PRIVATE_EXIT\n}")
	for _, tc := range []struct{ stderr, want string }{
		{"connect ENOENT " + launchSocket, "owner-control socket missing"},
		{"connect EACCES " + launchSocket, "owner-control socket access denied"},
		{"connect ECONNREFUSED " + launchSocket, "owner-control connection refused"},
		{`{"ok":false,"transport_error":"connection closed","detail":"PRIVATE_DETAIL"}`, "owner-control connection closed"},
		{`{"code":"host.internal","correlation_id":"PRIVATE_IDENTIFIER"}`, "HQ returned a status refusal"},
		{"sudo: a password is required", "sudo requires authentication"},
		{"expected an owner control socket owned by uid 0 at mode 666", "owner-control socket has unexpected type, owner or mode"},
		{"ENOENT: no such file or directory, lstat '" + launchSocket + "'", "owner-control socket missing"},
		{"EACCES: permission denied, lstat '" + launchSocket + "'", "owner-control socket access denied"},
		{"owner control requires a root-managed directory at /private/var", "owner-control socket parent is not root-managed"},
		{"connect ENOENT /PRIVATE_PATH", ""},
		{"EACCES: permission denied, lstat '/PRIVATE_PATH'", ""},
		{"owner control requires a root-managed directory at /PRIVATE_PATH", ""},
		{"unknown PRIVATE_RAW_DIAGNOSTIC", ""},
	} {
		// Use a real exit status so the original child failure is preserved.
		_, err := exec.Command("/bin/sh", "-c", `printf '%s' "$1" >&2; exit 1`, "test", tc.stderr).Output()
		got := withLaunchState(ownerStatusFailure(err), job, "")
		if tc.want == "" && ownerStatusStderr([]byte(tc.stderr)) != "" {
			t.Fatalf("misclassified unrelated stderr: %q", tc.stderr)
		}
		if !strings.Contains(got.Error(), "exit status 1") || !strings.Contains(got.Error(), tc.want) ||
			!strings.Contains(got.Error(), "launchd state running, launchd last exit code 23") || strings.Contains(got.Error(), "PRIVATE") {
			t.Fatalf("status failure: %v", got)
		}
	}
	if got := ownerStatusFailure(errors.New("PRIVATE_SETUP_ERROR")); strings.Contains(got.Error(), "PRIVATE") {
		t.Fatalf("leaked setup error: %v", got)
	}
}

func TestHQStatusProbeStartsInPublicWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	out, err := hqProgramOutput("/bin/pwd")
	if err != nil || strings.TrimSpace(string(out)) != "/" {
		t.Fatalf("working directory %q: %v", out, err)
	}
}

func TestWaitForLaunchSocket(t *testing.T) {
	// Darwin bounds sockaddr_un paths; use a short disposable directory.
	dir, err := os.MkdirTemp("/tmp", "hqwait.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "control")
	uid := uint32(os.Geteuid())
	done := make(chan error, 1)
	go func() {
		_, err := waitForLaunchSocket(path, uid, time.Second)
		done <- err
	}()
	time.Sleep(80 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("returned before socket appeared: %v", err)
	default:
	}
	staged := filepath.Join(dir, "staged")
	listener, err := net.Listen("unix", staged)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(staged, 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, path); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := waitForLaunchSocket(path, uid, 0); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := waitForLaunchSocket(filepath.Join(dir, "missing"), uid, 75*time.Millisecond); err == nil || !strings.Contains(err.Error(), "before the deadline") {
		t.Fatalf("missing socket: %v", err)
	}
	if got := withLaunchState(errors.New("socket absent"), []byte("\tstate = waiting\n\truns = 0\n\tlast exit code = (never exited)\n\tprivate = HIDDEN"), ""); got.Error() != "socket absent (launchd state waiting, launchd runs 0, launchd has never exited)" {
		t.Fatalf("readiness failure should report only bounded launchd state: %v", got)
	}
	if elapsed := time.Since(start); elapsed < 75*time.Millisecond || elapsed > time.Second {
		t.Fatalf("deadline not respected: %s", elapsed)
	}
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{file, link, filepath.Join(file, "inaccessible")} {
		start = time.Now()
		if _, err := waitForLaunchSocket(candidate, uid, time.Second); err == nil || strings.Contains(err.Error(), "before the deadline") {
			t.Fatalf("unexpected result for invalid endpoint: %v", err)
		}
		if time.Since(start) >= time.Second {
			t.Fatal("retried an invalid socket or non-ENOENT error")
		}
	}
}

func TestWaitForLaunchSocketRefusesForeignOrPrivateNode(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "hqmode.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "control")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	uid := uint32(os.Geteuid())
	for _, tc := range []struct {
		mode    os.FileMode
		wantUID uint32
	}{{0600, uid}, {0666, uid + 1}} {
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := waitForLaunchSocket(path, tc.wantUID, time.Second); err == nil || !strings.Contains(err.Error(), "unexpected type, owner or mode") {
			t.Fatalf("accepted wrong socket metadata: %v", err)
		}
	}
}

func TestLaunchExitDiagnosticsRequireReleaseAndApprovedJob(t *testing.T) {
	const base = "darwin-owner-control/v1"
	const advertised = `{"capability":"darwin-owner-control/v1","launch_diagnostics":"darwin-hq-launch-exits/v1"}`
	const owner = "fixture-owner"
	service := HQService{ReleaseDir: "/fixture/hq", Node: "/fixture/node"}
	// The source path, executable, argv and public state all belong to this one print.
	head := "system/" + launchLabel + " = {\n\tpath = " + launchPlist + "\n\tprogram = /usr/bin/ruby\n\targuments = {\n"
	for _, arg := range []string{"/usr/bin/ruby", "--disable-gems", "/fixture/hq/helpers/darwin-owner.rb", "launch",
		"/fixture/node", "/fixture/hq/hq/main.mjs", "run", "--home", launchState, "--owner-account", owner} {
		head += "\t\t" + arg + "\n"
	}
	head += "\t}\n\tstate = spawn scheduled\n\truns = 1\n"

	report := func(t *testing.T, capability, job string, started bool) string {
		t.Helper()
		var cap launchRoleCapability
		if err := json.Unmarshal([]byte(capability), &cap); err != nil {
			t.Fatal(err)
		}
		raw := []byte(job)
		return withLaunchState(errors.New("status failed"), raw, cap.exitDiagnostics(raw, service, owner, started)).Error()
	}
	for i, label := range []string{
		"native launcher rejected the role or arguments", "native launchd socket check-in failed",
		"launchd returned an unexpected descriptor count", "native launcher could not validate the inherited Unix stream descriptor",
		"native launcher could not verify the protected public socket metadata", "native launcher could not verify the launchd-bound address",
		"native launcher could not execute the approved Node runtime", "Node owner-control activation failed after exec",
	} {
		code := 80 + i
		job := head + fmt.Sprintf("\tlast exit code = %d\n}", code)
		want := fmt.Sprintf("status failed (launchd state spawn scheduled, launchd runs 1, launchd last exit code %d, %s)", code, label)
		if got := report(t, advertised, job, true); got != want {
			t.Errorf("exit %d: %q", code, got)
		}
	}
	job := head + "\tlast exit code = 84\n}"
	v2 := strings.NewReplacer(base, launchControlV2, launchExitsV1, launchExitsV2).Replace(advertised)
	native159 := strings.Replace(job, "code = 84", "code = 88", 1)
	if d := report(t, v2, native159, true); !strings.Contains(d, "native launchd socket check-in returned 159") {
		t.Fatal(d)
	}
	for _, transport := range []string{launchControlV1, launchControlV2} {
		for _, diagnostics := range []string{launchExitsV1, launchExitsV2} {
			advertisement := strings.NewReplacer(base, transport, launchExitsV1, diagnostics).Replace(advertised)
			if d := report(t, advertisement, job, true); !strings.Contains(d, hqLaunchExitReasons[84]) {
				t.Errorf("%s %s lost known exit 84: %s", transport, diagnostics, d)
			}
			d := report(t, advertisement, native159, true)
			if strings.Contains(d, "native launchd socket check-in returned 159") != (diagnostics == launchExitsV2) {
				t.Errorf("%s %s wrongly classified exit 88: %s", transport, diagnostics, d)
			}
		}
	}
	for _, tc := range []struct {
		name, capability, job string
		started               bool
	}{
		{"old release", `{"capability":"` + base + `"}`, job, true},
		{"future contract", strings.Replace(advertised, "exits/v1", "exits/v3", 1), job, true},
		{"future field type", `{"capability":"` + base + `","launch_diagnostics":{}}`, job, true},
		{"unknown capability", strings.Replace(advertised, base, "unknown/v1", 1), job, true},
		{"previously loaded job", advertised, job, false},
		{"different job", advertised, strings.Replace(job, "system/"+launchLabel, "system/other", 1), true},
		{"different source", advertised, strings.Replace(job, launchPlist, "/private/other.plist", 1), true},
		{"different program", advertised, strings.Replace(job, "program = /usr/bin/ruby", "program = /fixture/other", 1), true},
		{"different owner argument", advertised, strings.Replace(job, owner, "other", 1), true},
		{"different runtime argument", advertised, strings.Replace(job, "/fixture/node", "/fixture/other", 1), true},
		{"active process", advertised, strings.Replace(job, "\truns =", "\tpid = 23\n\truns =", 1), true},
		{"running", advertised, strings.Replace(job, "spawn scheduled", "running", 1), true},
		{"no launches", advertised, strings.Replace(job, "runs = 1", "runs = 0", 1), true},
		{"unknown exit", advertised, strings.Replace(job, "code = 84", "code = 88", 1), true},
		{"generic error", advertised, strings.Replace(job, "code = 84", "code = 1", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := withLaunchState(errors.New("status failed"), []byte(tc.job), "").Error()
			if got := report(t, tc.capability, tc.job, tc.started); got != want || !strings.Contains(got, "launchd last exit code") {
				t.Errorf("expected numeric launchctl evidence only: %q", got)
			}
		})
	}
}
