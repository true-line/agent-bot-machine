//go:build darwin

package members

import (
	"os"
	"testing"
	"time"
)

func TestCooperativeFD3WriterCannotBlockCutoff(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(make([]byte, 1<<20))
		done <- writeErr
	}()
	start := time.Now()
	if err := finishSoulCooperativePipeWrite(writer, done, 20*time.Millisecond); err == nil {
		t.Fatal("blocked FD3 writer was accepted")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("blocked FD3 writer delayed dispatcher cutoff")
	}
	reader.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked FD3 writer did not exit after pipe closure")
	}
}
