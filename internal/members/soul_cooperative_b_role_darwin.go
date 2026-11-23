//go:build darwin

package members

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const soulCooperativeBFD3Version = "agent-bot-comms/cooperative-b-start/v3"

type soulCooperativeBFD3V3 struct {
	Version                           string `json:"version"`
	MachinePinPath                    string `json:"machine_pin_path"`
	ReservationEnvelopeBase64URL      string `json:"reservation_envelope_base64url"`
	BridgeAssignmentEnvelopeBase64URL string `json:"bridge_assignment_envelope_base64url"`
}

// RunSoulCooperativeBRole is a separate fixed sudo command for B. It accepts
// only a fresh A-signed, one-use grant for its own kernel PID and challenge.
func RunSoulCooperativeBRole() int {
	me, err := os.Executable()
	if err != nil || me != SoulLauncher || os.Getuid() != os.Geteuid() ||
		os.Getuid() < 300 || os.Getuid() > 399 || os.Getgid() != os.Getegid() ||
		os.Getenv("SUDO_USER") != DarwinHQAccount {
		return harnessRefused
	}
	pub, err := readStage2aRolePin()
	if err != nil {
		return harnessRefused
	}
	input, err := stage2aRoleInput()
	if err != nil {
		return harnessRefused
	}
	defer input.Close()
	if input.SetReadDeadline(time.Now().Add(15*time.Second)) != nil {
		return harnessRefused
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return harnessRefused
	}
	challenge := stage2aExecChallenge{Role: "cooperative-bridge",
		Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), PID: os.Getpid()}
	if json.NewEncoder(os.Stdout).Encode(challenge) != nil {
		return harnessRefused
	}
	reader := bufio.NewReaderSize(input, stage2aExecMaxFrame)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > stage2aExecMaxFrame || input.SetReadDeadline(time.Time{}) != nil {
		return harnessRefused
	}
	grant, reservation, bridge, proof, err := verifySoulCooperativeBRoleGrant(line, challenge, pub,
		time.Now().UTC())
	if err != nil {
		return harnessRefused
	}
	defer clear(proof)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer cancel()
	// The grant pipe stays live for the whole B process. H closure or any
	// additional bytes terminate the supervised bridge group.
	go func() {
		_, _ = reader.ReadByte()
		cancel()
	}()
	if runSoulCooperativeBridge(ctx, grant, reservation, bridge, proof, os.Stdout, os.Stderr) != nil {
		return harnessUncontained
	}
	return harnessClosed
}

func verifySoulCooperativeBRoleGrant(line []byte, challenge stage2aExecChallenge,
	pub ed25519.PublicKey, now time.Time) (soulCooperativeBExecGrantV3,
	soulCooperativeReservationPayloadV3, soulCooperativeBridgeAssignmentPayloadV3, []byte, error) {
	var grant soulCooperativeBExecGrantV3
	var reservation soulCooperativeReservationPayloadV3
	var bridge soulCooperativeBridgeAssignmentPayloadV3
	var reply SoulCooperativeBExecReplyV3
	invalid := func() (soulCooperativeBExecGrantV3, soulCooperativeReservationPayloadV3,
		soulCooperativeBridgeAssignmentPayloadV3, []byte, error) {
		return soulCooperativeBExecGrantV3{}, soulCooperativeReservationPayloadV3{},
			soulCooperativeBridgeAssignmentPayloadV3{}, nil, errSoulCooperativeAuthority
	}
	if stage2aDecodeExact(bytes.TrimSpace(line), &reply) != nil ||
		!stage2aPrefixedDigest.MatchString(reply.SHA256) {
		return invalid()
	}
	grantBytes, e1 := base64.RawURLEncoding.Strict().DecodeString(reply.EnvelopeBase64URL)
	reservationBytes, e2 := base64.RawURLEncoding.Strict().DecodeString(reply.ReservationEnvelopeBase64URL)
	bridgeBytes, e3 := base64.RawURLEncoding.Strict().DecodeString(reply.BridgeAssignmentEnvelopeBase64URL)
	if e1 != nil || e2 != nil || e3 != nil || len(grantBytes) > 8192 ||
		len(reservationBytes) > 16<<10 || len(bridgeBytes) > 8192 ||
		stage2aReservationSHA256(grantBytes) != reply.SHA256 {
		return invalid()
	}
	grantRaw, _, e1 := verifySoulCooperativePurposeV3(grantBytes, pub, soulCooperativeBExecPurposeV3)
	reservationRaw, reservationSHA, e2 := verifySoulCooperativePurposeV3(reservationBytes, pub,
		soulCooperativeReservationPurposeV3)
	bridgeRaw, bridgeSHA, e3 := verifySoulCooperativePurposeV3(bridgeBytes, pub,
		soulCooperativeBridgeAssignmentPurposeV3)
	if e1 != nil || e2 != nil || e3 != nil ||
		stage2aDecodeExact(grantRaw, &grant) != nil ||
		stage2aDecodeExact(reservationRaw, &reservation) != nil ||
		stage2aDecodeExact(bridgeRaw, &bridge) != nil {
		return invalid()
	}
	expires, e1 := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	issued, e2 := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	reservationExpires, e3 := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !now.Before(expires) ||
		expires.After(reservationExpires) || expires.Sub(issued) > 30*time.Second ||
		grant.Contract != "machine/v3" || grant.Kind != "soul-cooperative-b-exec" ||
		grant.SchemaVersion != 3 || grant.PID != challenge.PID || grant.PID != os.Getpid() ||
		grant.Nonce != challenge.Nonce || grant.ReservationSHA256 != reservationSHA ||
		grant.BridgeAssignmentSHA256 != bridgeSHA || grant.InstallationID != bridge.InstallationID ||
		grant.StartID != bridge.StartID || grant.LaunchID != bridge.LaunchID ||
		grant.HQEpoch != bridge.HQEpoch || bridge.ReservationSHA256 != reservationSHA ||
		grant.BridgeUID != os.Getuid() || grant.BridgeGID != os.Getgid() ||
		bridge.Bridge.UID != grant.BridgeUID || bridge.Bridge.GID != grant.BridgeGID ||
		reservation.AdapterTransport != "brokered-b" ||
		reservation.Assignment.InstallationID != grant.InstallationID ||
		reservation.Assignment.StartID != grant.StartID ||
		reservation.Assignment.LaunchID != grant.LaunchID ||
		reservation.Assignment.HQEpoch != grant.HQEpoch ||
		reservation.Assignment.MachineUID != grant.MachineUID ||
		reservation.Assignment.HQUID <= 0 ||
		os.Getenv("SUDO_UID") != strconv.Itoa(reservation.Assignment.HQUID) ||
		bridge.BridgeLaunchSHA256 != reservation.BridgeLaunchSHA256 ||
		bridge.Endpoints.Member != reservation.Endpoints.Member ||
		bridge.Endpoints.Relay != reservation.Endpoints.Relay {
		return invalid()
	}
	observed, err := observeSoulProcess(grant.PID, SoulLauncher,
		[]string{SoulLauncher, "cooperative-soul-bridge"})
	if err != nil || observed.Kernel.StartSeconds != grant.PIDStartSec ||
		observed.Kernel.StartMicros != grant.PIDStartUsec ||
		observed.Kernel.RealUID != uint32(grant.BridgeUID) ||
		observed.Kernel.EffectiveUID != uint32(grant.BridgeUID) {
		return invalid()
	}
	proof, err := readCooperativeBProof(grant.InstallationID, grant.StartID,
		grant.BridgeUID, grant.BridgeGID, grant.MachineUID, grant.ProofSHA256)
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(proof)) != grant.ProofSHA256 {
		clear(proof)
		return invalid()
	}
	grant.reservationEnvelope = reservationBytes
	grant.bridgeEnvelope = bridgeBytes
	return grant, reservation, bridge, proof, nil
}

func cooperativeBFD3(reservation, bridge []byte) ([]byte, error) {
	frame := soulCooperativeBFD3V3{Version: soulCooperativeBFD3Version,
		MachinePinPath:                    SoulAuthorityPin,
		ReservationEnvelopeBase64URL:      base64.RawURLEncoding.EncodeToString(reservation),
		BridgeAssignmentEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(bridge)}
	raw, err := marshalStage2aReservationJCS(frame)
	if err != nil || len(raw) > 32<<10 {
		return nil, errSoulCooperativeAuthority
	}
	return raw, nil
}
