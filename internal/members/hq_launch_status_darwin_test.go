package members

import (
	"errors"
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
		got := withLaunchState(ownerStatusFailure(err), job)
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
	go func() { done <- waitForLaunchSocket(path, uid, time.Second) }()
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
	if err := waitForLaunchSocket(path, uid, 0); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := waitForLaunchSocket(filepath.Join(dir, "missing"), uid, 75*time.Millisecond); err == nil || !strings.Contains(err.Error(), "before the deadline") {
		t.Fatalf("missing socket: %v", err)
	}
	if got := withLaunchState(errors.New("socket absent"), []byte("\tstate = waiting\n\truns = 0\n\tlast exit code = (never exited)\n\tprivate = HIDDEN")); got.Error() != "socket absent (launchd state waiting, launchd runs 0, launchd has never exited)" {
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
		if err := waitForLaunchSocket(candidate, uid, time.Second); err == nil || strings.Contains(err.Error(), "before the deadline") {
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
		if err := waitForLaunchSocket(path, tc.wantUID, time.Second); err == nil || !strings.Contains(err.Error(), "unexpected type, owner or mode") {
			t.Fatalf("accepted wrong socket metadata: %v", err)
		}
	}
}
