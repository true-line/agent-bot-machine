//go:build darwin

package members

import (
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHarnessGroupPermissionRequiresVerifiedClosure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		denied unix.Signal
		closed bool
	}{
		{"TERM racing with confirmed exit", unix.SIGTERM, true},
		{"TERM with live or unknown group", unix.SIGTERM, false},
		{"KILL racing with confirmed exit", unix.SIGKILL, true},
		{"KILL with live or unknown group", unix.SIGKILL, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const leader = 4711
			var sent []unix.Signal
			checks := 0
			signal := func(target int, sig unix.Signal) error {
				if target != -leader {
					t.Fatal("unexpected process group")
				}
				sent = append(sent, sig)
				if sig == tc.denied {
					return unix.EPERM
				}
				return nil
			}
			await := func(pid int, deadline time.Time) bool {
				if pid != leader || deadline.Before(time.Now()) {
					t.Fatal("expected bounded check of the original group")
				}
				checks++
				return sent[len(sent)-1] == tc.denied && tc.closed
			}
			got := stopHarnessGroup(leader, time.Second, signal, await)
			want := []unix.Signal{unix.SIGTERM}
			if tc.denied == unix.SIGKILL {
				want = append(want, unix.SIGKILL)
			}
			if got != tc.closed || checks != len(want) || !slices.Equal(sent, want) {
				t.Fatalf("closure=%t checks=%d signals=%v", got, checks, sent)
			}
		})
	}
}
