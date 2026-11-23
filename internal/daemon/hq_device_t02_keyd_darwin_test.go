package daemon

import (
	"bufio"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the same live process sampler used between Start and Wait in the
// qualified provider. The fixture contains no key or network behavior.
func TestStage2aT02KeydObservationBindsLiveChild(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("qualified keyd runs in a nonroot admin account")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable for native process fixture")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "keyd-fixture.c")
	path := filepath.Join(dir, "agent-bot-keyd")
	if err := os.WriteFile(source, []byte("#include <stdio.h>\n#include <unistd.h>\nint main(void) { puts(\"ready\"); fflush(stdout); sleep(10); return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command(compiler, source, "-o", path)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile native fixture: %v: %s", err, output)
	}
	cmd := exec.Command(path, "hq-device")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if ready, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("fixture startup: %q %v", ready, err)
	}
	machinePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	delegation := deviceDelegation{Option: "enrollment-proof", Nonce: strings.Repeat("a", 22),
		Epoch: strings.Repeat("b", 64), UID: 309,
		HQ:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Machine: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32)))}
	witness, err := observeStage2aT02KeydCommand(cmd.Process.Pid, dir, machinePath, delegation)
	if err != nil {
		t.Fatal(err)
	}
	if witness.RequestNonce != delegation.Nonce || witness.HQEpoch != delegation.Epoch ||
		witness.HQUid != delegation.UID || witness.MachinePID != os.Getpid() ||
		witness.KeydProcess.PID != cmd.Process.Pid || witness.KeydProcess.ParentPID != os.Getpid() ||
		witness.KeydExecutableSHA256 == "" || witness.MachineExecutableSHA256 == "" {
		t.Fatalf("unbound process witness: %+v", witness)
	}
	if _, err := observeStage2aT02KeydCommand(cmd.Process.Pid, dir, machinePath,
		deviceDelegation{Option: "identity", Nonce: delegation.Nonce, Epoch: delegation.Epoch, UID: delegation.UID}); err == nil {
		t.Fatal("accepted non-enrollment purpose")
	}
	if _, err := observeStage2aT02KeydCommand(cmd.Process.Pid, dir, machinePath,
		deviceDelegation{Option: delegation.Option, Nonce: delegation.Nonce, Epoch: delegation.Epoch, UID: 0}); err == nil {
		t.Fatal("accepted unbound HQ UID")
	}
}
