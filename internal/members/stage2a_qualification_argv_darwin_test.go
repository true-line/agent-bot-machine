package members

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStage2aQualificationKernelChecksPinnedExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observeStage2aQualificationProcess(os.Getpid(), executable, os.Args, true)
	if err != nil || observed.Kernel.PID != os.Getpid() {
		t.Fatalf("cannot authenticate pinned image: %v", err)
	}
	if _, err := observeStage2aQualificationProcess(os.Getpid(), "/bin/false", os.Args, true); err == nil {
		t.Fatal("wrong executable accepted")
	}
}

func TestStage2aQualificationReadyBindsExactArgv(t *testing.T) {
	peer := stage2aQualificationPeerV1{
		executable:        "/private/bin/node",
		argv:              []string{"/private/bin/node", "/private/suite.mjs", "--connect", "/private/q.sock"},
		reviewedArgvProof: true,
	}
	ready := stage2aQualificationReadyV1{ExecPath: peer.executable, Argv: append([]string(nil), peer.argv...)}
	if !validStage2aQualificationReadyArgv(12, ready, peer) {
		t.Fatal("exact pinned argv refused")
	}
	ready.Argv[3] = "/private/replay.sock"
	if validStage2aQualificationReadyArgv(12, ready, peer) || validStage2aQualificationReadyArgv(10, stage2aQualificationReadyV1{}, peer) {
		t.Fatal("changed or missing argv accepted")
	}
}
