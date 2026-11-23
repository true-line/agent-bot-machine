//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCooperativeRecoveryRetainsJournalUntilCompletionCleanup(t *testing.T) {
	root := t.TempDir()
	paths := soulCooperativeLaunchPaths{requestDir: filepath.Join(root, "requests"),
		stagingDir:    filepath.Join(root, "staging"),
		completionDir: filepath.Join(root, "completions")}
	for _, path := range []string{paths.requestDir, paths.stagingDir, paths.completionDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	claims := filepath.Join(root, "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(claims)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	pending := ".cooperative-pending-test.json"
	completion := filepath.Join(paths.completionDir, "completion.json")
	if err := os.WriteFile(filepath.Join(claims, pending), []byte("journal"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(completion, []byte("completion"), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("completion removal interrupted")
	remove := func(path string) error {
		if path == completion {
			return failure
		}
		return os.Remove(path)
	}
	if err := completeCooperativeRecoveryCleanup(dir, paths, "", nil, completion, pending, remove); !errors.Is(err, failure) || soulCooperativeLeafAbsent(filepath.Join(claims, pending)) {
		t.Fatal("failed completion cleanup discarded the signed pending journal")
	}
	if err := completeCooperativeRecoveryCleanup(dir, paths, "", nil, completion, pending, os.Remove); err != nil || !soulCooperativeLeafAbsent(filepath.Join(claims, pending)) ||
		!soulCooperativeLeafAbsent(completion) {
		t.Fatalf("recovery cleanup retry did not finish: %v", err)
	}
}

func TestCooperativeRecoveryReusesExactCutoffAfterCommitCrash(t *testing.T) {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", ed25519.SeedSize)))
	pub := private.Public().(ed25519.PublicKey)
	q := Stage2aStopRequest{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID: "installation-1", StartID: "st_1234567890abcdef12345678",
		LaunchID: "ln_1234567890abcdef12345678", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)}
	h := "sha256:" + strings.Repeat("d", 64)
	payload := soulCooperativeRecoveryPayloadV3{Contract: "machine/v3",
		Kind: "soul-cooperative-recovery-cutoff", SchemaVersion: 3,
		ReservationSHA256: q.ReservationSHA256, HDescriptorDigest: h,
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch,
		RunnerUID: 351, ClaimSpent: true, AttachedClaim: true,
		RunnerUIDIdle: true, HQEndpointsAbsent: true,
		RecoveredAt: time.Now().UTC().Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(payload, 3, soulCooperativeRecoveryPurposeV3,
		pub, func(preimage []byte) ([]byte, error) { return ed25519.Sign(private, preimage), nil })
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	store := stage2aAdminClaimStore{path: path, uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	name := ".cooperative-recovery-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if err := commitStage2aReservation(dir, name, envelope); err != nil {
		t.Fatal(err)
	}
	// Model a restart immediately after the signed cutoff is committed: the
	// next caller must reuse those bytes instead of attempting another commit.
	reused, got, err := readSoulCooperativeRecoveryCutoff(dir, store, name, pub, q, h, 351)
	if err != nil || !bytes.Equal(reused, envelope) || got != payload {
		t.Fatalf("committed recovery cutoff was not reusable: %v", err)
	}
	other := q
	other.StartID = "st_ffffffffffffffffffffffff"
	if _, _, err := readSoulCooperativeRecoveryCutoff(dir, store, name, pub, other, h, 351); err == nil {
		t.Fatal("cutoff from a different start was reused")
	}
}

func TestCooperativeRecoveryRequiresExactSignedTerminal(t *testing.T) {
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", ed25519.SeedSize)))
	pub := private.Public().(ed25519.PublicKey)
	q := Stage2aStopRequest{ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		InstallationID: "installation-1", StartID: "st_1234567890abcdef12345678",
		LaunchID: "ln_1234567890abcdef12345678", PlanID: "plan-20261122T120000Z-abcd",
		PlanDigest: strings.Repeat("b", 64), HQEpoch: strings.Repeat("c", 64)}
	h := "sha256:" + strings.Repeat("d", 64)
	dirPath := t.TempDir()
	dir, err := os.Open(dirPath)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	store := stage2aAdminClaimStore{path: dirPath, uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
	stop := soulCooperativeStopPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-stop",
		SchemaVersion: 3, ReservationSHA256: q.ReservationSHA256, HDescriptorDigest: h,
		InstallationID: q.InstallationID, StartID: q.StartID, LaunchID: q.LaunchID,
		PlanID: q.PlanID, PlanDigest: q.PlanDigest, HQEpoch: q.HQEpoch, RunnerUIDIdle: true}
	envelope, err := signStage2aEnvelope(stop, 3, soulCooperativeStopPurposeV3, pub,
		func(preimage []byte) ([]byte, error) { return ed25519.Sign(private, preimage), nil })
	if err != nil {
		t.Fatal(err)
	}
	name := ".cooperative-stop-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if err := os.WriteFile(dirPath+"/"+name, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	if kind, err := soulCooperativeExistingTerminal(dir, store, pub, q, h); err != nil || kind != "stop" {
		t.Fatalf("exact A terminal refused: kind=%q err=%v", kind, err)
	}
	altered := q
	altered.ReservationSHA256 = "sha256:" + strings.Repeat("e", 64)
	if _, err := soulCooperativeExistingTerminal(dir, store, pub, altered, h); err == nil {
		t.Fatal("terminal from a different reservation accepted")
	}
	if _, err := soulCooperativeExistingTerminal(dir, store, pub, q,
		"sha256:"+strings.Repeat("f", 64)); err == nil {
		t.Fatal("terminal from a different H descriptor accepted")
	}
}
