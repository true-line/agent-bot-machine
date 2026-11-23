//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeCancelPurposeV3 = "agent-bot/soul-cooperative-cancel/v3"
const soulCooperativeNoAttachDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type soulCooperativeCancelPayloadV3 struct {
	Contract          string `json:"contract"`
	Kind              string `json:"kind"`
	SchemaVersion     int    `json:"schema_version"`
	ReservationSHA256 string `json:"reservation_sha256"`
	AttachSHA256      string `json:"attach_sha256"`
	InstallationID    string `json:"installation_id"`
	StartID           string `json:"start_id"`
	LaunchID          string `json:"launch_id"`
	RunnerPID         int    `json:"runner_pid"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
}

// R may read the one-use selector, but cannot write the A-owned request dir.
// A failed or altered selector makes the dispatcher terminate its child.
func readSoulCooperativeCancel(dirFD int, paths soulCooperativeLaunchPaths,
	key ed25519.PublicKey, live soulCooperativeCancelPayloadV3,
	now time.Time) (bool, string, error) {
	return readSoulCooperativeCancelWithExpiry(dirFD, paths, key, live, now, false)
}

func readSoulCooperativeCancelWithExpiry(dirFD int, paths soulCooperativeLaunchPaths,
	key ed25519.PublicKey, live soulCooperativeCancelPayloadV3,
	now time.Time, allowExpired bool) (bool, string, error) {
	fd, err := unix.Openat(dirFD, filepath.Base(paths.cancel), stage2aFileOpenFlags, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, "", nil
	}
	if err != nil {
		return false, "", errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), paths.cancel)
	defer f.Close()
	var parent, before, after unix.Stat_t
	if unix.Fstat(dirFD, &parent) != nil || unix.Fstat(fd, &before) != nil ||
		parent.Mode != unix.S_IFDIR|02750 || before.Mode != unix.S_IFREG|0440 ||
		before.Uid != parent.Uid || before.Gid != parent.Gid || before.Nlink != 1 ||
		before.Size < 1 || before.Size > 8192 ||
		checkDarwinACLs([]string{paths.cancel}) != nil {
		return false, "", errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return false, "", errSoulCooperativeAuthority
	}
	digest, err := verifySoulCooperativeCancelEnvelopeAt(raw, key, live, now, allowExpired)
	if err != nil {
		return false, "", err
	}
	return true, digest, nil
}

func verifySoulCooperativeCancelEnvelope(raw []byte, key ed25519.PublicKey,
	live soulCooperativeCancelPayloadV3, now time.Time) (string, error) {
	return verifySoulCooperativeCancelEnvelopeAt(raw, key, live, now, false)
}

func verifySoulCooperativeCancelEnvelopeAt(raw []byte, key ed25519.PublicKey,
	live soulCooperativeCancelPayloadV3, now time.Time, allowExpired bool) (string, error) {
	payloadRaw, digest, err := verifySoulCooperativePurposeV3(raw, key, soulCooperativeCancelPurposeV3)
	if err != nil || len(payloadRaw) > 4096 {
		return "", errSoulCooperativeAuthority
	}
	var got soulCooperativeCancelPayloadV3
	dec := json.NewDecoder(bytes.NewReader(payloadRaw))
	dec.DisallowUnknownFields()
	if dec.Decode(&got) != nil || dec.Decode(new(any)) != io.EOF ||
		got.Contract != "machine/v3" || got.Kind != "soul-cooperative-cancel" ||
		got.SchemaVersion != 3 || got.ReservationSHA256 != live.ReservationSHA256 ||
		(live.AttachSHA256 != "" && got.AttachSHA256 != live.AttachSHA256) ||
		!stage2aPrefixedDigest.MatchString(got.AttachSHA256) || got.InstallationID != live.InstallationID ||
		got.StartID != live.StartID || got.LaunchID != live.LaunchID ||
		(live.RunnerPID >= 0 && got.RunnerPID != live.RunnerPID &&
			!(got.RunnerPID == 0 && got.AttachSHA256 == soulCooperativeNoAttachDigest)) {
		return "", errSoulCooperativeAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, got.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	if e1 != nil || e2 != nil || expires.Sub(issued) != 20*time.Second ||
		issued.After(now.Add(2*time.Second)) || (!allowExpired && !now.Before(expires)) {
		return "", errSoulCooperativeAuthority
	}
	return digest, nil
}

func publishSoulCooperativeCancel(paths soulCooperativeLaunchPaths,
	live *soulCooperativeLiveV3, key ed25519.PublicKey,
	sign func([]byte) ([]byte, error)) (string, error) {
	if live == nil || (live.attached && !stage2aPrefixedDigest.MatchString(live.attachSHA256)) ||
		len(key) != ed25519.PublicKeySize || sign == nil {
		return "", errSoulCooperativeAuthority
	}
	dir, err := openStage2aAdminDirectory(paths.requestDir, uint32(os.Getuid()))
	if err != nil {
		return "", errSoulCooperativeAuthority
	}
	defer dir.Close()
	var active unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), filepath.Base(paths.activeRequest), &active,
		unix.AT_SYMLINK_NOFOLLOW) != nil || active.Mode != unix.S_IFREG|0440 ||
		active.Uid != uint32(os.Getuid()) || active.Gid != uint32(live.installed.Policy.Runner.GID) ||
		active.Nlink != 1 {
		return "", errSoulCooperativeAuthority
	}
	attachSHA, runnerPID := live.attachSHA256, live.runnerPID
	if !live.attached {
		attachSHA, runnerPID = soulCooperativeNoAttachDigest, 0
	}
	want := soulCooperativeCancelPayloadV3{ReservationSHA256: live.digest,
		AttachSHA256: attachSHA, InstallationID: live.request.InstallationID,
		StartID: live.request.StartID, LaunchID: live.request.LaunchID,
		RunnerPID: runnerPID}
	// Recovery may not have the in-memory attach receipt. The old A-signed
	// cancel can still be validated against the exact reservation and start;
	// renewal then uses the no-attach cutoff that R accepts in either state.
	if !live.attached {
		want.AttachSHA256 = ""
		want.RunnerPID = -1
	}
	// A can renew an expired selector for the same exact spent claim. R cannot
	// replace this A-owned leaf, and malformed or mismatched old bytes refuse.
	if exists, digest, e := readSoulCooperativeCancelWithExpiry(int(dir.Fd()), paths, key,
		want, time.Now().UTC(), true); e != nil {
		return "", e
	} else if exists {
		if valid, _, e := readSoulCooperativeCancel(int(dir.Fd()), paths, key,
			want, time.Now().UTC()); e == nil && valid {
			return digest, nil
		}
	}
	now := time.Now().UTC()
	payload := soulCooperativeCancelPayloadV3{ReservationSHA256: live.digest,
		AttachSHA256: attachSHA, InstallationID: live.request.InstallationID,
		StartID: live.request.StartID, LaunchID: live.request.LaunchID,
		RunnerPID: runnerPID}
	payload.Contract, payload.Kind, payload.SchemaVersion = "machine/v3", "soul-cooperative-cancel", 3
	payload.IssuedAt = now.Format(time.RFC3339Nano)
	payload.ExpiresAt = now.Add(20 * time.Second).Format(time.RFC3339Nano)
	envelope, err := signStage2aEnvelope(payload, 3, soulCooperativeCancelPurposeV3, key, sign)
	if err != nil || len(envelope) > 8192 {
		return "", errSoulCooperativeAuthority
	}
	f, err := os.CreateTemp(paths.requestDir, ".cancel-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0440); err == nil {
		_, err = f.Write(envelope)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err := unix.Rename(f.Name(), paths.cancel); err != nil {
		return "", err
	}
	if err := dir.Sync(); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(envelope)), nil
}
