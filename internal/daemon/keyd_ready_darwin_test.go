package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const readyReply = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"agent-bot-keyd","version":"0.2.2"}}}`

func TestKeydInitializePeerAndReply(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "mmki.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "fixture.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, tc := range []struct {
		name, reply string
		uid         int
		want        error
	}{
		{"healthy", readyReply, os.Getuid(), nil},
		{"another-uid", readyReply, os.Getuid() + 1, errKeydPeer},
		{"wrong-helper", strings.Replace(readyReply, "agent-bot-keyd", "other", 1), os.Getuid(), errKeydReply},
		{"wrong-id", strings.Replace(readyReply, `"id":1`, `"id":2`, 1), os.Getuid(), errKeydReply},
		{"wrong-protocol", strings.Replace(readyReply, keydProtocol, "unknown", 1), os.Getuid(), errKeydReply},
		{"error", `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"fixture"}}`, os.Getuid(), errKeydReply},
		{"oversize", strings.Repeat("x", 8193), os.Getuid(), errKeydReply},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("unix", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			s, err := listener.Accept()
			if err != nil {
				c.Close()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			deadline := time.Now().Add(time.Second)
			go func() {
				defer s.Close()
				s.SetDeadline(deadline)
				line, err := bufio.NewReader(s).ReadString('\n')
				if tc.want == errKeydPeer {
					if line != "" || !errors.Is(err, io.EOF) {
						done <- errors.New("sent request to unverified peer")
						return
					}
				} else {
					if err != nil || line != keydInitialize {
						done <- errors.New("unexpected initialize request")
						return
					}
					fmt.Fprintln(s, tc.reply)
				}
				done <- nil
			}()
			err = initializeKeyd(c, tc.uid, deadline)
			c.Close()
			if r := <-done; r != nil {
				t.Fatal(r)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBundledKeydDeadlineAndDelayedBind(t *testing.T) {
	home, err := os.MkdirTemp("/private/tmp", "mmkl.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	// Directory-inherited read-only permissions do not grant foreign writers.
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow readattr,readsecurity,directory_inherit", home).CombinedOutput(); err != nil {
		t.Fatalf("set test home ACL: %v %s", err, out)
	}
	dir := filepath.Join(home, ".local", "state", "agent-bot", "keyd")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caller := Caller{UID: os.Getuid(), Username: "fixture", PrefixOwner: "fixture", Home: home, RegisteredHome: home, DarwinAdmin: true}
	start := time.Now()
	if err := waitBundledKeyd(caller, 70*time.Millisecond); !errors.Is(err, errKeydEndpoint) {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatal("unbounded readiness wait")
	}
	path := filepath.Join(dir, "keyd.sock")
	done := make(chan error, 1)
	go func() {
		time.Sleep(80 * time.Millisecond)
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			done <- err
			return
		}
		defer l.Close()
		if err = os.Chmod(path, 0600); err != nil {
			done <- err
			return
		}
		l.SetDeadline(time.Now().Add(2 * time.Second))
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != keydInitialize {
			done <- errors.New("unexpected initialize request")
			return
		}
		_, err = fmt.Fprintln(c, readyReply)
		done <- err
	}()
	err = waitBundledKeyd(caller, time.Second)
	if responderErr := <-done; responderErr != nil {
		t.Fatal(responderErr)
	}
	if err != nil {
		t.Fatal(err)
	}
}
