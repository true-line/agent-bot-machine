//go:build darwin

package guestowner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/qwts/managed-machine/internal/daemon"
)

func TestCheckedTartFileRequiresOwnedRegularPinnedBytes(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "TartQualification")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tartctl")
	content := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	if err := checkedTartFile(path, home, os.Getuid(), digest); err != nil {
		t.Fatalf("owned pinned executable refused: %v", err)
	}
	if err := checkedTartFile(path, home, os.Getuid(), hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("substituted executable digest accepted")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkedTartFile(path, home, os.Getuid(), digest); err == nil {
		t.Fatal("writable Tart directory accepted")
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
