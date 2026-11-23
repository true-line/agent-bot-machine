//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

// publishSoulCooperativeStartV3 is the last A-only action before launchd may
// wake R. The caller holds the current H pair/installation authority. A spends
// the start before publishing the complete signed request; a lost reply stays
// spent and the installation remains active for explicit containment cleanup.
func publishSoulCooperativeStartV3(a soulCooperativeVerifiedStartV3,
	q SoulCooperativeReserveRequest, challenge []byte, issued time.Time,
	key ed25519.PublicKey, sign func([]byte) ([]byte, error)) (Stage2aReserveReply, error) {
	var reply Stage2aReserveReply
	p := a.installed.Policy
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	if err != nil || os.Getuid() != p.MachineUID || os.Geteuid() != p.MachineUID ||
		len(challenge) != 32 || fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != q.AdmissionChallengeSHA256 ||
		!bytes.Equal(key, decoded) || p.LaunchInputs == nil || len(key) != ed25519.PublicKeySize {
		return reply, errSoulCooperativeAuthority
	}
	paths, err := cooperativeLaunchPaths(q.InstallationID)
	if err != nil || a.installed.RequestDirectory.Path != paths.requestDir ||
		p.Runner.InstallationID != q.InstallationID {
		return reply, errSoulCooperativeAuthority
	}
	requestDir, err := stage2aInstalledDirectoryIdentity(paths.requestDir, p.MachineUID, p.Runner.GID, 02750)
	if err != nil || requestDir != a.installed.RequestDirectory {
		return reply, errSoulCooperativeAuthority
	}
	for _, leaf := range []string{paths.stagedRequest, paths.request, paths.activeRequest, paths.cancel} {
		if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
			return reply, errSoulCooperativeAuthority
		}
	}
	if _, err := os.Lstat(filepath.Join(paths.completionDir, "completion.json")); !errors.Is(err, os.ErrNotExist) {
		return reply, errSoulCooperativeAuthority
	}
	envelope, digest, err := signSoulCooperativeReservationV3(a, q, issued, key, sign)
	if err != nil {
		return reply, err
	}
	encodedEnvelope := base64.RawURLEncoding.EncodeToString(envelope)
	// A must not spend a start that its 64 KiB paired daemon transport cannot
	// return to HQ. Check the actual reply bytes before the one-use claim.
	reply = Stage2aReserveReply{EnvelopeBase64URL: encodedEnvelope, SHA256: digest}
	response, err := json.Marshal(reply)
	if err != nil || len(response) > 60<<10 {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	handoff := soulCooperativeDispatchRequest{Schema: soulCooperativeDispatchSchema,
		ReservationEnvelopeBase64URL: encodedEnvelope,
		ReservationSHA256:            digest, MachinePinPath: SoulAuthorityPin,
		LaunchInputRecords: *p.LaunchInputs, StateRoot: p.StateRoot,
		AdmissionChallengeBase64URL: base64.RawURLEncoding.EncodeToString(challenge)}
	raw, err := json.Marshal(handoff)
	if err != nil {
		return reply, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 64<<10 ||
		stage2aStrictJSONBounded(canonical, 64<<10, stage2aV3MaxJSONNodes) != nil {
		return reply, errSoulCooperativeAuthority
	}
	stagingIdentity, err := stage2aInstalledDirectoryIdentity(paths.stagingDir,
		p.MachineUID, p.Runner.GID, 02700)
	entries, listErr := os.ReadDir(paths.stagingDir)
	if err != nil || stagingIdentity != a.installed.StagingDirectory || listErr != nil || len(entries) != 0 {
		return reply, errSoulCooperativeAuthority
	}
	store := a.installed.claimStore()
	claimsDir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer claimsDir.Close()
	pending := cooperativePendingName(q.InstallationID, q.StartID)
	if requireUnspentStage2aReservation(claimsDir, pending) != nil ||
		commitStage2aReservation(claimsDir, pending, canonical) != nil {
		return reply, errSoulCooperativeAuthority
	}
	f, err := os.CreateTemp(paths.stagingDir, ".request-*")
	if err != nil {
		return reply, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0440); err == nil {
		_, err = f.Write(canonical)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return reply, err
	}
	if err := unix.RenamexNp(f.Name(), paths.stagedRequest, unix.RENAME_EXCL); err != nil {
		return reply, err
	}
	if err := syncUpgradeDir(paths.stagingDir); err != nil {
		return reply, err
	}
	// The A-only claim journal and complete staged handoff are durable before
	// spending. The watched request directory stays untouched until then.
	if err := spendSoulCooperativeStart(store, q); err != nil {
		return reply, err
	}
	if err := unix.RenamexNp(paths.stagedRequest, paths.request, unix.RENAME_EXCL); err != nil {
		return reply, err
	}
	if err := syncUpgradeDir(paths.requestDir); err != nil {
		return reply, err
	}
	return reply, nil
}
