//go:build darwin

package members

import (
	"errors"
	"testing"
)

func TestStage2aProviderWaitsForAssignedLiveRunner(t *testing.T) {
	dead := errors.New("runner no longer matches its kernel role")
	for _, tc := range []struct {
		name       string
		live       Stage2aLiveReply
		runnerPID  int
		checkError error
		want       bool
		wantCheck  bool
	}{
		{name: "B finalized before R starts", live: Stage2aLiveReply{Phase: "finalized"}},
		{name: "prebind with R", live: Stage2aLiveReply{Phase: "prebind", RunnerPID: 4321}, runnerPID: 4321},
		{name: "different R", live: Stage2aLiveReply{Phase: "finalized", RunnerPID: 4321}, runnerPID: 4322},
		{name: "R exited", live: Stage2aLiveReply{Phase: "finalized", RunnerPID: 4321}, runnerPID: 4321, checkError: dead, wantCheck: true},
		{name: "assigned R live", live: Stage2aLiveReply{Phase: "finalized", RunnerPID: 4321}, runnerPID: 4321, want: true, wantCheck: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked := false
			got := stage2aProviderRunnerLive(tc.live, tc.runnerPID, func(pid int) error {
				checked = true
				if pid != tc.live.RunnerPID {
					t.Fatalf("checked the wrong runner PID: %d", pid)
				}
				return tc.checkError
			})
			if got != tc.want || checked != tc.wantCheck {
				t.Fatalf("runner live = %t, kernel check called = %t; want %t, %t", got, checked, tc.want, tc.wantCheck)
			}
		})
	}
}
