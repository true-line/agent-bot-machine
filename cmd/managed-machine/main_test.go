package main

import "testing"

func TestStage2aFixedLauncherRoutesChildRole(t *testing.T) {
	for _, role := range []string{"soul-run", "soul-bridge", "soul-child", "cooperative-soul-child"} {
		got, ok := stage2aRoleCommand("darwin", []string{"managed-machine", role})
		if !ok || got != role {
			t.Fatalf("fixed role %q was not dispatched: %q, %t", role, got, ok)
		}
	}
	for _, args := range [][]string{{"managed-machine", "harness-run"}, {"managed-machine", "soul-child", "extra"}, {"managed-machine", "soul-other"}} {
		if role, ok := stage2aRoleCommand("darwin", args); ok {
			t.Fatalf("unreviewed launcher command %q dispatched as %q", args, role)
		}
	}
	if role, ok := stage2aRoleCommand("linux", []string{"managed-machine", "soul-child"}); ok {
		t.Fatalf("non-Darwin child command dispatched as %q", role)
	}
}
