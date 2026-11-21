package members

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// launchd can publish a Unix stream socket under a different name from the
// address on its descriptor. Check the kernel's response at the published
// vnode while a separate process retains the last descriptor.
func TestHQDatagramProbeOfPublishedStream(t *testing.T) {
	for _, state := range []string{"bound", "listening"} {
		t.Run(state, func(t *testing.T) {
			dir, err := os.MkdirTemp("/private/tmp", "hq-sock.")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			bound, published := filepath.Join(dir, "bound.sock"), filepath.Join(dir, "published.sock")

			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			unix.CloseOnExec(fd)
			stream := os.NewFile(uintptr(fd), "stream")
			defer stream.Close()
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: bound}); err != nil {
				t.Fatal(err)
			}
			if state == "listening" {
				if err := unix.Listen(fd, 1); err != nil {
					t.Fatal(err)
				}
			}
			probe := func(path string, want error) {
				t.Helper()
				d, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(d)
				if got := unix.Connect(d, &unix.SockaddrUnix{Name: path}); !errors.Is(got, want) {
					t.Fatalf("datagram connect at %s = %v, want %v", filepath.Base(path), got, want)
				}
			}
			probe(bound, unix.EPROTOTYPE)
			if err := os.Rename(bound, published); err != nil {
				t.Fatal(err)
			}
			identity, err := os.Lstat(published)
			if err != nil {
				t.Fatal(err)
			}
			probe(published, unix.EPROTOTYPE)

			// cat waits on stdin and retains the inherited socket until EOF.
			holder := exec.Command("/bin/cat")
			holder.ExtraFiles = []*os.File{stream}
			in, err := holder.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := holder.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if holder.ProcessState == nil {
					in.Close()
					holder.Wait()
				}
			}()
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			probe(published, unix.EPROTOTYPE)
			if err := in.Close(); err != nil {
				t.Fatal(err)
			}
			if err := holder.Wait(); err != nil {
				t.Fatal(err)
			}
			probe(published, unix.ECONNREFUSED)
			after, err := os.Lstat(published)
			if err != nil || !os.SameFile(identity, after) {
				t.Fatal("expected the same published socket after the last descriptor closed", err)
			}
			if err := os.Remove(published); err != nil {
				t.Fatal(err)
			}
			probe(published, unix.ENOENT)
		})
	}
}
