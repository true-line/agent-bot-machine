//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCooperativeCancelRequiresSignedExactSelector(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "requests")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 02750); err != nil {
		t.Fatal(err)
	}
	paths := soulCooperativeLaunchPaths{requestDir: dir, cancel: filepath.Join(dir, "cancel.json")}
	now := time.Now().UTC()
	want := soulCooperativeCancelPayloadV3{Contract: "machine/v3", Kind: "soul-cooperative-cancel",
		SchemaVersion: 3, ReservationSHA256: "sha256:" + strings.Repeat("a", 64),
		AttachSHA256: "sha256:" + strings.Repeat("b", 64), InstallationID: "inst_0123456789abcdef01234567",
		StartID: "st_0123456789abcdef01234567", LaunchID: "ln_0123456789abcdef01234567",
		RunnerPID: 901, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(want, 3, soulCooperativeCancelPurposeV3,
		pub, func(p []byte) ([]byte, error) { return ed25519.Sign(priv, p), nil })
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := verifySoulCooperativeCancelEnvelope(envelope, pub, want, now); err != nil || digest == "" {
		t.Fatalf("signed cancel refused: digest=%q err=%v", digest, err)
	}
	wrong := want
	wrong.RunnerPID++
	if _, err := verifySoulCooperativeCancelEnvelope(envelope, pub, wrong, now); err == nil {
		t.Fatal("wrong live child accepted a cancel selector")
	}
	if _, err := verifySoulCooperativeCancelEnvelope(envelope, pub, want, now.Add(21*time.Second)); err == nil {
		t.Fatal("expired cancel selector accepted")
	}
	if _, err := verifySoulCooperativeCancelEnvelopeAt(envelope, pub, want,
		now.Add(21*time.Second), true); err != nil {
		t.Fatalf("exact expired A selector cannot be renewed: %v", err)
	}
	if _, err := verifySoulCooperativeCancelEnvelopeAt(envelope, pub, wrong,
		now.Add(21*time.Second), true); err == nil {
		t.Fatal("renewal accepted expired selector for a different child")
	}
	preAttach := want
	preAttach.AttachSHA256 = soulCooperativeNoAttachDigest
	preAttach.RunnerPID = 0
	preAttachEnvelope, err := signStage2aEnvelope(preAttach, 3, soulCooperativeCancelPurposeV3,
		pub, func(p []byte) ([]byte, error) { return ed25519.Sign(priv, p), nil })
	if err != nil {
		t.Fatal(err)
	}
	preAttachLive := want
	preAttachLive.AttachSHA256 = ""
	if _, err := verifySoulCooperativeCancelEnvelope(preAttachEnvelope, pub, preAttachLive, now); err != nil {
		t.Fatalf("preattach cancel failed to bind reservation/start: %v", err)
	}
	preAttachLive.StartID = "st_ffffffffffffffffffffffff"
	if _, err := verifySoulCooperativeCancelEnvelope(preAttachEnvelope, pub, preAttachLive, now); err == nil {
		t.Fatal("preattach cancel accepted a different start")
	}
	if err := os.WriteFile(paths.cancel, envelope, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.cancel, 0440); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var parent unix.Stat_t
	_ = unix.Fstat(fd, &parent)
	if parent.Mode == unix.S_IFDIR|02750 {
		if found, digest, err := readSoulCooperativeCancel(fd, paths, pub, want, now); err != nil || !found || digest == "" {
			t.Fatalf("custodied signed cancel refused: found=%t digest=%q err=%v", found, digest, err)
		}
	} else if found, _, err := readSoulCooperativeCancel(fd, paths, pub, want, now); err == nil || found {
		t.Fatal("cancel reader accepted a directory without reviewed setgid mode")
	}
	if err := os.Chmod(paths.cancel, 0660); err != nil {
		t.Fatal(err)
	}
	if found, _, err := readSoulCooperativeCancel(fd, paths, pub, want, now); err == nil || found {
		t.Fatal("writable cancel selector accepted")
	}
}
