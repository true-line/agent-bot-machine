package members

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestHarnessSupervisorOwnGroupAndEOF(t *testing.T) {
	control, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	defer writer.Close()
	records, sink, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer records.Close()
	defer sink.Close()
	stdout, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	// Only this test supplies a command; the production path constructs the
	// exact sandbox invocation from the locked, reviewed grant.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := exec.Command("/bin/sh", "-c", `trap '' TERM; /bin/sleep 20 & echo fixture-ready >&2; wait`)
	other := exec.Command("/bin/sleep", "20")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { other.Process.Kill(); other.Wait() }()
	done := make(chan int, 1)
	go func() {
		done <- superviseHarness(ctx, target, bufio.NewReader(control), control, stdout, &harnessReporter{output: sink}, 100*time.Millisecond)
		sink.Close()
	}()
	records.SetReadDeadline(time.Now().Add(6 * time.Second))
	dec := json.NewDecoder(records)
	var event struct{ Kind, Text string }
	if err := dec.Decode(&event); err != nil || event.Kind != "started" {
		t.Fatalf("missing supervisor start: %v", err)
	}
	if err := dec.Decode(&event); err != nil || event.Kind != "stderr" {
		t.Fatalf("missing adapter readiness: %v", err)
	}
	writer.Close()
	if status := <-done; status != harnessClosed {
		t.Fatalf("group closure unconfirmed (%d)", status)
	}
	if err := dec.Decode(&event); err != nil || event.Kind != "closed" {
		t.Fatalf("missing closure confirmation: %v", err)
	}
	if err := dec.Decode(&event); err != io.EOF {
		t.Fatal("unexpected trailing event")
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("unrelated process was disturbed", err)
	}
}

type rejectedACPReader struct{ read chan struct{} }

func (r rejectedACPReader) Read([]byte) (int, error) {
	select {
	case r.read <- struct{}{}:
	default:
	}
	return 0, io.EOF
}

func TestHarnessSupervisorDoesNotReadACPAfterChildStartRefusal(t *testing.T) {
	control, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	output, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdout, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	acp := rejectedACPReader{read: make(chan struct{}, 1)}
	status := superviseHarnessStarted(ctx, exec.Command("/bin/sleep", "20"), acp,
		control, stdout, &harnessReporter{output: output}, 100*time.Millisecond,
		func(int) error { return errors.New("child acceptance refused") })
	if status != harnessUncontained {
		t.Fatalf("refused child returned %d", status)
	}
	select {
	case <-acp.read:
		t.Fatal("ACP input read after child acceptance refused")
	case <-time.After(50 * time.Millisecond):
	}
}
