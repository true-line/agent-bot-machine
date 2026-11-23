//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

const soulCooperativeFD3SchemaV3 = "agent-bot-souls/cooperative-start/v3"

type soulCooperativeFD3V3 struct {
	Schema                               string                         `json:"schema"`
	ReservationEnvelopeBase64URL         string                         `json:"reservation_envelope_base64url"`
	ReservationSHA256                    string                         `json:"reservation_sha256"`
	MachinePinPath                       string                         `json:"machine_pin_path"`
	LaunchInputRecords                   Stage2aLaunchInputRecords      `json:"launch_input_records"`
	StateRoot                            string                         `json:"state_root"`
	AdmissionChallengeBase64URL          string                         `json:"admission_challenge_base64url"`
	MemberSocketPath                     string                         `json:"member_socket_path"`
	RelaySocketPath                      string                         `json:"relay_socket_path"`
	PublishOutcomeEnvelopeBase64URL      string                         `json:"publish_outcome_envelope_base64url"`
	RequestIdentity                      soulCooperativeRequestIdentity `json:"request_identity"`
	MemberSetAssignmentEnvelopeBase64URL string                         `json:"member_set_assignment_envelope_base64url"`
}

func cooperativeRequestIdentityFromStat(st unix.Stat_t) soulCooperativeRequestIdentity {
	birth := st.Btim.Sec*1_000_000_000 + st.Btim.Nsec
	return soulCooperativeRequestIdentity{Device: strconv.FormatUint(uint64(uint32(st.Dev)), 10),
		Inode: strconv.FormatUint(st.Ino, 10), BirthtimeNS: strconv.FormatInt(birth, 10),
		OwnerUID: int(st.Uid), GroupGID: int(st.Gid), Mode: uint32(st.Mode & 07777)}
}

// R waits on the original already-open watched request inode. The outcome is
// accepted only if A signed that inode and exact durable request bytes after
// publication; a replacement path cannot change the in-memory request.
func cooperativeFD3AfterPublishedOutcome(paths soulCooperativeLaunchPaths, requestDir, requestFD int,
	requestRaw []byte, request soulCooperativeDispatchRequest, reservation soulCooperativeReservationPayloadV3,
	pin ed25519.PublicKey, before unix.Stat_t) ([]byte, error) {
	var sidecar soulCooperativePublishedHandoff
	deadline := time.Now().Add(5 * time.Second)
	expires, err := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	if expires.Before(deadline) {
		deadline = expires
	}
	for time.Now().Before(deadline) {
		fd, openErr := unix.Openat(requestDir, filepath.Base(paths.outcome), stage2aFileOpenFlags, 0)
		if openErr == unix.ENOENT {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if openErr != nil {
			return nil, errSoulCooperativeAuthority
		}
		f := os.NewFile(uintptr(fd), paths.outcome)
		var st, after unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0440 || st.Uid != before.Uid ||
			st.Gid != before.Gid || st.Nlink != 1 || st.Size < 1 || st.Size > 32<<10 ||
			checkDarwinACLs([]string{paths.outcome}) != nil {
			f.Close()
			return nil, errSoulCooperativeAuthority
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if readErr != nil || len(raw) != int(st.Size) || unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
			f.Close()
			return nil, errSoulCooperativeAuthority
		}
		f.Close()
		canonical, canErr := jsoncanonicalizer.Transform(raw)
		if canErr != nil || !bytes.Equal(canonical, raw) || stage2aDecodeExact(raw, &sidecar) != nil {
			return nil, errSoulCooperativeAuthority
		}
		break
	}
	if sidecar.Schema != soulCooperativeOutcomeSidecarSchema ||
		sidecar.ReservationSHA256 != request.ReservationSHA256 {
		return nil, errSoulCooperativeAuthority
	}
	var after unix.Stat_t
	if unix.Fstat(requestFD, &after) != nil || !stage2aSameNode(before, after) ||
		before.Mode != unix.S_IFREG|0640 || before.Nlink != 1 || before.Btim.Sec <= 0 ||
		sidecar.RequestIdentity != cooperativeRequestIdentityFromStat(before) {
		return nil, errSoulCooperativeAuthority
	}
	outcomeBytes, err := base64.RawURLEncoding.Strict().DecodeString(sidecar.PublishOutcomeEnvelopeBase64URL)
	if err != nil || len(outcomeBytes) > 8192 {
		return nil, errSoulCooperativeAuthority
	}
	outcomeRaw, _, err := verifySoulCooperativePurposeV3(outcomeBytes, pin, soulCooperativePublishOutcomePurposeV3)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	var outcome soulCooperativePublishOutcomePayloadV3
	if stage2aDecodeExact(outcomeRaw, &outcome) != nil {
		return nil, errSoulCooperativeAuthority
	}
	requestSHA := fmt.Sprintf("sha256:%x", sha256.Sum256(requestRaw))
	published, e1 := time.Parse(time.RFC3339Nano, outcome.PublishedAt)
	outcomeExpiry, e2 := time.Parse(time.RFC3339Nano, outcome.ExpiresAt)
	if e1 != nil || e2 != nil || published.After(time.Now()) || !time.Now().Before(outcomeExpiry) ||
		outcomeExpiry.After(expires) || !published.Before(outcomeExpiry) ||
		outcome.Contract != "machine/v3" || outcome.Kind != "soul-cooperative-publish-outcome" ||
		outcome.SchemaVersion != 3 || outcome.PublicationMode != "direct" ||
		outcome.ReservationSHA256 != request.ReservationSHA256 ||
		outcome.RequestSHA256 != requestSHA || outcome.OrderSHA256 != requestSHA ||
		outcome.RequestDevice != sidecar.RequestIdentity.Device ||
		outcome.RequestInode != sidecar.RequestIdentity.Inode ||
		outcome.RequestBirthtimeNS != sidecar.RequestIdentity.BirthtimeNS ||
		outcome.InstallationID != reservation.Assignment.InstallationID ||
		outcome.StartID != reservation.Assignment.StartID ||
		outcome.LaunchID != reservation.Assignment.LaunchID {
		return nil, errSoulCooperativeAuthority
	}
	bridgeBytes, err := base64.RawURLEncoding.Strict().DecodeString(sidecar.BridgeAssignmentEnvelopeBase64URL)
	if err != nil || stage2aReservationSHA256(bridgeBytes) != outcome.BridgeAssignmentSHA256 {
		return nil, errSoulCooperativeAuthority
	}
	bridgeRaw, _, err := verifySoulCooperativePurposeV3(bridgeBytes, pin, soulCooperativeBridgeAssignmentPurposeV3)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	var bridge soulCooperativeBridgeAssignmentPayloadV3
	if stage2aDecodeExact(bridgeRaw, &bridge) != nil || bridge.ReservationSHA256 != request.ReservationSHA256 ||
		bridge.BridgeLaunchSHA256 != reservation.BridgeLaunchSHA256 ||
		bridge.InstallationID != reservation.Assignment.InstallationID ||
		bridge.StartID != reservation.Assignment.StartID || bridge.LaunchID != reservation.Assignment.LaunchID ||
		bridge.Endpoints.Member != reservation.Endpoints.Member || bridge.Endpoints.Relay != reservation.Endpoints.Relay {
		return nil, errSoulCooperativeAuthority
	}
	memberBytes, err := base64.RawURLEncoding.Strict().DecodeString(sidecar.MemberSetAssignmentEnvelopeBase64URL)
	if err != nil || !cooperativeMemberEnvelopeMatches(memberBytes, pin, request.ReservationSHA256,
		outcome.BridgeAssignmentSHA256, reservation) {
		return nil, errSoulCooperativeAuthority
	}
	fd3 := soulCooperativeFD3V3{Schema: soulCooperativeFD3SchemaV3,
		ReservationEnvelopeBase64URL: request.ReservationEnvelopeBase64URL,
		ReservationSHA256:            request.ReservationSHA256, MachinePinPath: request.MachinePinPath,
		LaunchInputRecords: request.LaunchInputRecords, StateRoot: request.StateRoot,
		AdmissionChallengeBase64URL:          request.AdmissionChallengeBase64URL,
		MemberSocketPath:                     reservation.Endpoints.Member.SocketPath,
		RelaySocketPath:                      reservation.Endpoints.Relay.SocketPath,
		PublishOutcomeEnvelopeBase64URL:      sidecar.PublishOutcomeEnvelopeBase64URL,
		RequestIdentity:                      sidecar.RequestIdentity,
		MemberSetAssignmentEnvelopeBase64URL: sidecar.MemberSetAssignmentEnvelopeBase64URL}
	raw, err := json.Marshal(fd3)
	if err != nil {
		return nil, errSoulCooperativeAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > 2<<20 {
		return nil, errSoulCooperativeAuthority
	}
	return canonical, nil
}

func cooperativeMemberEnvelopeMatches(raw []byte, pin ed25519.PublicKey, reservationSHA, bridgeSHA string,
	reservation soulCooperativeReservationPayloadV3) bool {
	var envelope soulCooperativeEnvelopeV3
	if stage2aDecodeExact(raw, &envelope) != nil || envelope.SchemaVersion != 1 ||
		envelope.Purpose != stage2aMemberSetAssignmentPurpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(pin) {
		return false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.PayloadBase64URL)
	if err != nil || stage2aReservationSHA256(payload) != envelope.PayloadSHA256 {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(envelope.SignatureBase64URL)
	if err != nil || !ed25519.Verify(pin, append([]byte(envelope.Purpose+"\x00"), payload...), sig) {
		return false
	}
	var member soulCooperativeMemberSetAssignmentV3
	if stage2aDecodeExact(payload, &member) != nil {
		return false
	}
	return member.ProfileInForce == "managed-cooperative" && member.ReservationSHA256 == reservationSHA &&
		member.BAuthority.EnvelopeSHA256 == bridgeSHA &&
		member.InstallationID == reservation.Assignment.InstallationID &&
		member.StartID == reservation.Assignment.StartID && member.HQEpoch == reservation.Assignment.HQEpoch &&
		member.PlanID == reservation.Assignment.PlanID && member.PlanDigest == reservation.Assignment.PlanDigest &&
		member.Bridge.Endpoints.Member == reservation.Endpoints.Member &&
		member.Bridge.Endpoints.Relay == reservation.Endpoints.Relay
}
