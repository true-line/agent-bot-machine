//go:build darwin

package members

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSoulStartClaimSpendsExactStartOnce(t *testing.T) {
	now := time.Date(2026, 11, 21, 14, 0, 0, 0, time.UTC)
	canonical := []byte(`{"installed":"reviewed R and B grant"}`)
	planID := "plan-20261121T140000Z-abcd"
	digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
	runner, bridge := runnerFixture()[0], bridgeFixture()[0]
	live := SoulRunRequest{PlanDigest: digest, InstallationID: runner.InstallationID,
		StartID: "st_0123456789abcdef01234567", HQEpoch: strings.Repeat("d", 64)}
	launchID, runtimeID := "ln_0123456789abcdef01234567", "runtime-1"
	assignment, err := PrepareSoulStartAssignment(runner, bridge, 309, 501, planID, digest,
		live.StartID, launchID, runtimeID, live.HQEpoch, now, now.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := prepareSoulStartClaim(assignment, planID, canonical, runner, bridge,
		309, 501, live, launchID, runtimeID, now)
	if err != nil {
		t.Fatal(err)
	}
	assignmentBytes, err := json.Marshal(assignment)
	if err != nil || claim.AssignmentSHA256 != fmt.Sprintf("%x", sha256.Sum256(assignmentBytes)) {
		t.Fatal("claim did not bind the exact assignment bytes", err)
	}
	path := filepath.Join(t.TempDir(), soulStartClaimName(live.InstallationID, live.StartID))
	if err := claimSoulStartOnceFile(path, claim); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		t.Fatalf("claim mode: %v, %v", st, err)
	}
	if err := claimSoulStartOnceFile(path, claim); err == nil {
		t.Fatal("replayed start claimed again")
	}
	reboundLaunch := "ln_0123456789abcdef01234568"
	reboundAssignment, err := PrepareSoulStartAssignment(runner, bridge, 309, 501, planID, digest,
		live.StartID, reboundLaunch, runtimeID, live.HQEpoch, now, now.Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	reboundClaim, err := prepareSoulStartClaim(reboundAssignment, planID, canonical, runner, bridge,
		309, 501, live, reboundLaunch, runtimeID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimSoulStartOnceFile(path, reboundClaim); err == nil {
		t.Fatal("same start was rebound to a different launch")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("replay changed the spent claim", err)
	}
	var saved soulStartClaim
	if json.Unmarshal(bytes.TrimSpace(after), &saved) != nil || saved != claim || saved.State != "started" {
		t.Fatal("claim was not durable and exact")
	}
	if err := claimSoulStartOnceFile(filepath.Join(t.TempDir(), "chosen.json"), claim); err == nil {
		t.Fatal("caller-chosen claim name accepted")
	}
	if err := claimSoulStartOnceFile(path, soulStartClaim{State: "failed"}); err == nil {
		t.Fatal("invalid claim replaced a spent start")
	}
	changed := assignment
	changed.BridgeUID++
	if _, err := prepareSoulStartClaim(changed, planID, canonical, runner, bridge,
		309, 501, live, launchID, runtimeID, now); err == nil {
		t.Fatal("changed bridge UID prepared a claim")
	}
	if _, err := prepareSoulStartClaim(assignment, planID, canonical, runner, bridge,
		309, 501, live, launchID, runtimeID, now.Add(20*time.Second)); err == nil {
		t.Fatal("expired assignment prepared a claim")
	}
}

func TestSoulStartClaimNameBindsInstallationAndStart(t *testing.T) {
	first := soulStartClaimName("inst_0000000000000001", "st_0123456789abcdef01234567")
	for _, next := range []string{
		soulStartClaimName("inst_0000000000000002", "st_0123456789abcdef01234567"),
		soulStartClaimName("inst_0000000000000001", "st_0123456789abcdef01234568"),
	} {
		if first == next || len(next) != 69 || !strings.HasSuffix(next, ".json") {
			t.Fatal("claim names did not isolate the installation/start tuple")
		}
	}
}
