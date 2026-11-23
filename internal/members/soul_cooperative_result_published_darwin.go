//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// A lost paired reply may retrieve only envelopes already published by A.
// An incomplete or expired publication never yields B launch authority.
func cooperativeReserveResultFromPublished(installed soulCooperativeInstalledV3,
	journal []byte, request soulCooperativeDispatchRequest,
	reservation soulCooperativeReservationPayloadV3, key ed25519.PublicKey,
	reply Stage2aReserveReply) (Stage2aReserveReply, error) {
	paths, err := cooperativeLaunchPaths(installed.Policy.Runner.InstallationID)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	if _, err := os.Lstat(paths.outcome); errors.Is(err, os.ErrNotExist) {
		return reply, nil
	} else if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	if !time.Now().Before(expires) {
		return reply, nil
	}
	dir, err := unix.Open(paths.requestDir, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	defer unix.Close(dir)
	name := filepath.Base(paths.request)
	if soulCooperativeLeafAbsent(paths.request) {
		name = filepath.Base(paths.activeRequest)
	}
	fd, err := unix.Openat(dir, name, stage2aFileOpenFlags, 0)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0640 ||
		before.Uid != uint32(installed.Policy.MachineUID) ||
		before.Gid != uint32(installed.Policy.Runner.GID) || before.Nlink != 1 ||
		before.Size != int64(len(journal)) || checkDarwinACLs([]string{filepath.Join(paths.requestDir, name)}) != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || !bytes.Equal(raw, journal) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	fd3Raw, err := cooperativeFD3AfterPublishedOutcome(paths, dir, fd, journal,
		request, reservation, key, before)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	var fd3 soulCooperativeFD3V3
	if stage2aDecodeExact(fd3Raw, &fd3) != nil || fd3.Schema != soulCooperativeFD3SchemaV3 ||
		fd3.ReservationSHA256 != reply.SHA256 {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	// The signed outcome binds B's envelope hash. Re-read the A-only sidecar
	// through its checked directory and verify it against that exact digest.
	sideFD, err := unix.Openat(dir, filepath.Base(paths.outcome), stage2aFileOpenFlags, 0)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	side := os.NewFile(uintptr(sideFD), paths.outcome)
	defer side.Close()
	var sideStat unix.Stat_t
	if unix.Fstat(sideFD, &sideStat) != nil || sideStat.Mode != unix.S_IFREG|0440 ||
		sideStat.Uid != before.Uid || sideStat.Gid != before.Gid || sideStat.Nlink != 1 ||
		sideStat.Size < 1 || sideStat.Size > 32<<10 {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	sideRaw, err := io.ReadAll(io.LimitReader(side, (32<<10)+1))
	var handoff soulCooperativePublishedHandoff
	if err != nil || len(sideRaw) != int(sideStat.Size) || stage2aDecodeExact(sideRaw, &handoff) != nil ||
		handoff.PublishOutcomeEnvelopeBase64URL != fd3.PublishOutcomeEnvelopeBase64URL ||
		handoff.MemberSetAssignmentEnvelopeBase64URL != fd3.MemberSetAssignmentEnvelopeBase64URL {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	outcomeBytes, err := base64.RawURLEncoding.Strict().DecodeString(fd3.PublishOutcomeEnvelopeBase64URL)
	if err != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	payloadRaw, _, err := verifySoulCooperativePurposeV3(outcomeBytes, key, soulCooperativePublishOutcomePurposeV3)
	var outcome soulCooperativePublishOutcomePayloadV3
	if err != nil || json.Unmarshal(payloadRaw, &outcome) != nil {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	bridge, err := base64.RawURLEncoding.Strict().DecodeString(handoff.BridgeAssignmentEnvelopeBase64URL)
	member, memberErr := base64.RawURLEncoding.Strict().DecodeString(handoff.MemberSetAssignmentEnvelopeBase64URL)
	if err != nil || memberErr != nil || stage2aReservationSHA256(bridge) != outcome.BridgeAssignmentSHA256 ||
		!cooperativeMemberEnvelopeMatches(member, key, reply.SHA256, outcome.BridgeAssignmentSHA256, reservation) {
		return Stage2aReserveReply{}, errSoulCooperativeAuthority
	}
	reply.BridgeAssignmentEnvelopeBase64URL = handoff.BridgeAssignmentEnvelopeBase64URL
	reply.BridgeAssignmentSHA256 = outcome.BridgeAssignmentSHA256
	reply.MemberSetAssignmentEnvelopeBase64URL = handoff.MemberSetAssignmentEnvelopeBase64URL
	reply.MemberSetAssignmentSHA256 = stage2aReservationSHA256(member)
	return reply, nil
}
