//go:build darwin

package members

import (
	"encoding/binary"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestSoulProcessArgumentsObservedWithoutEnvironment(t *testing.T) {
	process, err := observeSoulProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if process.Kernel.PID != os.Getpid() || process.Kernel.EffectiveUID != uint32(os.Geteuid()) {
		t.Fatalf("current process kernel identity differs: %+v", process.Kernel)
	}
	observed := process.Arguments
	if observed.ExecPath == "" || !reflect.DeepEqual(observed.Argv, os.Args) {
		t.Fatalf("current process arguments differ: path=%q argv=%q want=%q", observed.ExecPath, observed.Argv, os.Args)
	}
	child := exec.Command("/bin/sleep", "5")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	process, err = observeSoulProcess(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if process.Kernel.ParentPID != os.Getpid() {
		t.Fatalf("child process parent differs: %+v", process.Kernel)
	}
	observed = process.Arguments
	if observed.ExecPath != "/bin/sleep" || !reflect.DeepEqual(observed.Argv, []string{"/bin/sleep", "5"}) {
		t.Fatalf("child process arguments differ: %+v", observed)
	}
}

func TestSoulProcessArgumentsRejectsMalformedArea(t *testing.T) {
	valid := make([]byte, 4)
	binary.NativeEndian.PutUint32(valid, 2)
	valid = append(valid, []byte("/bin/sleep\x00\x00\x00\x00\x00\x00/bin/sleep\x005\x00SECRET=value\x00")...)
	got, err := parseSoulProcessArguments(valid)
	if err != nil || got.ExecPath != "/bin/sleep" || !reflect.DeepEqual(got.Argv, []string{"/bin/sleep", "5"}) {
		t.Fatalf("valid area refused: %+v: %v", got, err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"short":      func([]byte) []byte { return []byte{1, 2, 3} },
		"zero argc":  func(v []byte) []byte { binary.NativeEndian.PutUint32(v, 0); return v },
		"large argc": func(v []byte) []byte { binary.NativeEndian.PutUint32(v, 129); return v },
		"relative":   func(v []byte) []byte { v[4] = 'b'; return v },
		"no path":    func(v []byte) []byte { return v[:5] },
		"missing padding": func(v []byte) []byte {
			return append(v[:15], v[16:]...)
		},
		"nonzero padding": func(v []byte) []byte { v[15] = 'x'; return v },
		"empty argv zero": func(v []byte) []byte {
			return append(v[:20], append([]byte{0}, v[20:]...)...)
		},
		"empty argv one before environment": func(v []byte) []byte { v[31] = 0; return v },
		"missing arg": func(v []byte) []byte {
			binary.NativeEndian.PutUint32(v, 3)
			return v[:len(v)-len("SECRET=value\x00")]
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyOfValid := append([]byte(nil), valid...)
			if _, err := parseSoulProcessArguments(mutate(copyOfValid)); err == nil {
				t.Fatal("malformed process arguments accepted")
			}
		})
	}
}

func TestSoulProcessArgumentsRefusesLiveEmptyArgv(t *testing.T) {
	for _, example := range []struct {
		name string
		path string
		args []string
	}{
		{name: "empty argv zero", path: "/bin/sleep", args: []string{"", "5"}},
		{name: "empty argv one", path: "/usr/bin/yes", args: []string{"/usr/bin/yes", ""}},
	} {
		t.Run(example.name, func(t *testing.T) {
			child := exec.Command(example.path)
			child.Args = example.args
			child.Env = []string{"ABM_SECRET_TEST=not-for-output"}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = child.Process.Kill()
				_ = child.Wait()
			}()
			if _, err := observeSoulKernelProcess(child.Process.Pid); err != nil {
				t.Fatalf("child was not live before argv check: %v", err)
			}
			if _, err := observeSoulProcessArguments(child.Process.Pid); err == nil {
				t.Fatal("empty argv was accepted")
			}
		})
	}
}

func TestSoulKernelProcessSnapshotBindsPIDStartAndCredentials(t *testing.T) {
	first, err := observeSoulKernelProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	next, err := observeSoulKernelProcess(os.Getpid())
	if err != nil || !sameSoulKernelProcess(first, next) {
		t.Fatalf("live process identity changed: %+v %+v: %v", first, next, err)
	}
	if first.RealUID != uint32(os.Getuid()) || first.EffectiveUID != uint32(os.Geteuid()) ||
		first.RealGID != uint32(os.Getgid()) || first.PrimaryGroupGID != uint32(os.Getegid()) ||
		first.ParentPID <= 0 || first.ProcessGroupID <= 0 || first.StartSeconds <= 0 {
		t.Fatalf("kernel process credentials differ from current process: %+v", first)
	}
	for name, change := range map[string]func(*soulKernelProcessSnapshot){
		"reused PID":             func(s *soulKernelProcessSnapshot) { s.StartMicros++ },
		"new parent":             func(s *soulKernelProcessSnapshot) { s.ParentPID++ },
		"new group":              func(s *soulKernelProcessSnapshot) { s.ProcessGroupID++ },
		"new real UID":           func(s *soulKernelProcessSnapshot) { s.RealUID++ },
		"new effective UID":      func(s *soulKernelProcessSnapshot) { s.EffectiveUID++ },
		"new primary GID":        func(s *soulKernelProcessSnapshot) { s.PrimaryGroupGID++ },
		"new supplemental group": func(s *soulKernelProcessSnapshot) { s.Groups[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := first
			changed.Groups = append([]uint32(nil), first.Groups...)
			change(&changed)
			if sameSoulKernelProcess(first, changed) {
				t.Fatal("changed process identity accepted")
			}
		})
	}
}

func TestSoulKernelProcessSnapshotRejectsExitedChild(t *testing.T) {
	child := exec.Command("/bin/sleep", "5")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	first, err := observeSoulKernelProcess(child.Process.Pid)
	if err != nil || first.ParentPID != os.Getpid() {
		t.Fatalf("child was not independently observed: %+v: %v", first, err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed child unexpectedly exited cleanly")
	}
	if next, err := observeSoulKernelProcess(child.Process.Pid); err == nil && sameSoulKernelProcess(first, next) {
		t.Fatalf("reaped child remained a live process: %+v", next)
	}
}
