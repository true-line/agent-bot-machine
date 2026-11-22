//go:build darwin

package members

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestObserveSoulAdmissionPeer(t *testing.T) {
	if path := os.Getenv("MACHINE_SOUL_ADMISSION_TEST_CHILD"); path != "" {
		conn, err := net.Dial("unix", path)
		if err != nil {
			os.Exit(2)
		}
		defer conn.Close()
		var release [1]byte
		if _, err := conn.Read(release[:]); err != nil {
			os.Exit(2)
		}
		return
	}
	if _, err := ObserveSoulAdmissionPeer(nil); err == nil {
		t.Fatal("missing admission connection accepted")
	}
	dir, err := os.MkdirTemp("/private/tmp", "sap-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "admission.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestObserveSoulAdmissionPeer$")
	cmd.Env = append(os.Environ(), "MACHINE_SOUL_ADMISSION_TEST_CHILD="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := ObserveSoulAdmissionPeer(conn)
	if err != nil || peer.PID != cmd.Process.Pid || peer.UID != os.Getuid() {
		t.Fatalf("admission kernel peer: %+v, want PID %d UID %s: %v", peer,
			cmd.Process.Pid, strconv.Itoa(os.Getuid()), err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveSoulAdmissionPeer(conn); err == nil {
		t.Fatal("closed admission connection accepted")
	}
}
