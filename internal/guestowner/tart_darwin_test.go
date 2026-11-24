//go:build darwin

package guestowner

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/qwts/managed-machine/internal/daemon"
)

func TestCheckedTartFileRejectsAdministratorOwnedOrUnpinnedPath(t *testing.T) {
	path := t.TempDir() + "/tartctl"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkedTartFile(path, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("administrator-owned executable path accepted")
	}
	if err := checkedTartFile(protectedTartRoot+"/tartctl", "bad-digest"); err == nil {
		t.Fatal("unreviewed executable digest accepted")
	}
}

func TestObserveTartGuestRejectsMalformedExecutableDigestBeforeRunning(t *testing.T) {
	caller := daemon.Caller{UID: os.Getuid(), RegisteredHome: t.TempDir()}
	_, err := ObserveTartGuest(context.Background(), caller, "stage2a-rehearsal",
		"02:00:00:00:00:01", "25G83", "not-a-digest", hex.EncodeToString(make([]byte, 32)))
	if err == nil {
		t.Fatal("malformed Tart wrapper digest accepted")
	}
}
