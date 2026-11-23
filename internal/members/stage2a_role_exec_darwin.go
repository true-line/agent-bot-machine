package members

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aExecMaxFrame = 64 << 10

type stage2aExecChallenge struct {
	Role  string `json:"role"`
	Nonce string `json:"nonce"`
	PID   int    `json:"pid"`
}

// RunStage2aRole is reached by the two fixed, digest-pinned sudo rules. The
// role advertises a freshly generated challenge, then waits for Machine's
// authorization via the already paired HQ process. HQ can only relay it.
func RunStage2aRole(command string) int {
	role := "runner"
	switch command {
	case "soul-run":
	case "soul-bridge":
		role = "bridge"
	case "soul-child":
		role = "child"
	default:
		return harnessRefused
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher || os.Geteuid() < 300 || os.Geteuid() > 399 ||
		os.Getuid() != os.Geteuid() || os.Getenv("SUDO_USER") != DarwinHQAccount {
		return harnessRefused
	}
	pub, err := readStage2aRolePin()
	if err != nil {
		return harnessRefused
	}
	inputFile, err := stage2aRoleInput()
	if err != nil {
		return harnessRefused
	}
	defer inputFile.Close()
	if err := inputFile.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return harnessRefused
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return harnessRefused
	}
	challenge := stage2aExecChallenge{Role: role, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), PID: os.Getpid()}
	if err := json.NewEncoder(os.Stdout).Encode(challenge); err != nil {
		return harnessRefused
	}
	input := bufio.NewReaderSize(inputFile, stage2aExecMaxFrame)
	line, err := input.ReadSlice('\n')
	if err != nil || inputFile.SetReadDeadline(time.Time{}) != nil {
		return harnessRefused
	}
	in, err := verifyStage2aRoleGrant(line, challenge, pub, time.Now())
	if err != nil || os.Getenv("SUDO_UID") != strconv.Itoa(in.Start.HQUID) {
		return harnessRefused
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if role == "runner" {
		run := in.RunnerExec
		runtimeRef, err := verifyStage2aRunnerReservation(*run, in, pub, time.Now())
		if err != nil {
			return harnessRefused
		}
		return runStage2aRunner(ctx, in.Request, in.Start, in.Runner, in.Bridge, in.Binding,
			in.Launch, run.Definition, run.Node, run.Entry, run.ReservationEnvelopeBase64URL,
			run.ReservationSHA256, run.MemberSetAssignmentEnvelopeBase64URL,
			runtimeRef, input, inputFile, os.Stdout, os.Stderr)
	}
	if role == "child" {
		var grant Stage2aExecReply
		if decodeStage2aRoleJSON(line, &grant) != nil {
			return harnessRefused
		}
		return runStage2aChild(ctx, in, grant.SHA256, pub,
			input, inputFile, os.Stdout, os.Stderr)
	}

	bridge := in.BridgeExec
	assignment, err := decodeStage2aRoleBase64(bridge.AssignmentBase64URL, stage2aBridgeMaxAssignment)
	if err != nil {
		return harnessRefused
	}
	proof, err := readStage2aBridgeProof(in.Start, bridge.ProofSHA256)
	if err != nil {
		return harnessRefused
	}
	defer clear(proof)

	// The bridge has no post-grant input. End the supervised group if HQ
	// closes the pipe or attempts to send anything else on it.
	go func() {
		_, _ = input.ReadByte()
		cancel()
	}()
	if err := runStage2aBridge(ctx, in.Request, in.Start, in.Runner, in.Bridge, bridge.Executable,
		in.Launch, in.Binding, assignment, proof, os.Stdout, os.Stderr); err != nil {
		return harnessUncontained
	}
	return harnessClosed
}

func stage2aRoleInput() (*os.File, error) {
	fd, err := unix.Dup(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return nil, err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFIFO:
	case unix.S_IFSOCK:
		addr, err := unix.Getsockname(fd)
		if _, ok := addr.(*unix.SockaddrUnix); err != nil || !ok {
			unix.Close(fd)
			return nil, errors.New("Soul launch requires a private Unix stream")
		}
	default:
		unix.Close(fd)
		return nil, errors.New("Soul launch requires a private input stream")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "soul-launch-input"), nil
}

func readStage2aRolePin() (ed25519.PublicKey, error) {
	if err := trustedPath(OSHost{}, SoulAuthorityPin, false); err != nil {
		return nil, err
	}
	if err := checkDarwinACLs(pathAncestry(SoulAuthorityPin)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(SoulAuthorityPin, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), SoulAuthorityPin)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode != unix.S_IFREG|0444 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size != ed25519.PublicKeySize {
		return nil, errors.New("invalid installed Soul launch authority pin")
	}
	raw, err := io.ReadAll(io.LimitReader(file, ed25519.PublicKeySize+1))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid installed Soul launch authority pin")
	}
	return ed25519.PublicKey(raw), nil
}

func verifyStage2aRoleGrant(frame []byte, challenge stage2aExecChallenge,
	pub ed25519.PublicKey, now time.Time) (Stage2aRoleInvocation, error) {
	var in Stage2aRoleInvocation
	invalid := errors.New("invalid Machine Soul exec grant")
	var reply Stage2aExecReply
	if len(frame) > stage2aExecMaxFrame || decodeStage2aRoleJSON(frame, &reply) != nil {
		return in, invalid
	}
	raw, err := decodeStage2aRoleBase64(reply.EnvelopeBase64URL, 8<<10)
	var envelope stage2aSignedReservation
	if err != nil || stage2aReservationSHA256(raw) != reply.SHA256 ||
		decodeStage2aRoleJSON(raw, &envelope) != nil ||
		envelope.SchemaVersion != 1 || envelope.Purpose != Stage2aRoleExecPurpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(pub) {
		return in, invalid
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return in, invalid
	}
	payload, err := decodeStage2aRoleBase64(envelope.PayloadBase64URL, 4<<10)
	if err != nil || stage2aReservationSHA256(payload) != envelope.PayloadSHA256 {
		return in, invalid
	}
	signature, err := decodeStage2aRoleBase64(envelope.SignatureBase64URL, ed25519.SignatureSize)
	preimage := append([]byte(Stage2aRoleExecPurpose+"\x00"), payload...)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, preimage, signature) {
		return in, invalid
	}
	var grant Stage2aRoleGrant
	if decodeStage2aRoleJSON(payload, &grant) != nil || grant.Role != challenge.Role ||
		grant.PID != challenge.PID || grant.Nonce != challenge.Nonce || !validStage2aExecDigest(grant.ReservationSHA256) {
		return in, invalid
	}
	canonical, err = marshalStage2aReservationJCS(grant)
	expiry, expiresErr := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || !bytes.Equal(payload, canonical) || expiresErr != nil ||
		!now.Before(expiry) || expiry.Sub(now) > 30*time.Second {
		return in, invalid
	}
	invocation, err := decodeStage2aRoleBase64(reply.InvocationBase64URL, stage2aExecMaxFrame)
	if err != nil || stage2aReservationSHA256(invocation) != grant.InvocationSHA256 ||
		decodeStage2aRoleJSON(invocation, &in) != nil || !in.Request.valid() ||
		in.Request.StartID != grant.StartID || in.Request.HQEpoch != grant.HQEpoch ||
		in.Request.InstallationID != grant.InstallationID || in.Start.LaunchID != grant.LaunchID ||
		(grant.Role != "child" && in.Start.ExpiresAt != grant.ExpiresAt) ||
		(grant.Role == "runner") != (in.RunnerExec != nil) ||
		(grant.Role == "bridge") != (in.BridgeExec != nil) ||
		(grant.Role == "child") != (in.ChildExec != nil) ||
		(grant.Role == "child" && (in.ChildExec.GrantExpiresAt != grant.ExpiresAt ||
			in.ChildExec.ReservationSHA256 != grant.ReservationSHA256 ||
			in.ChildExec.MemberID != grant.MemberID ||
			in.ChildExec.MemberLaunchID != grant.MemberLaunchID ||
			in.ChildExec.MemberSelector != grant.MemberSelector)) ||
		(grant.Role == "child" && !stage2aVerifyMemberChildGrant(grant, in, pub, now)) {
		return Stage2aRoleInvocation{}, invalid
	}
	return in, nil
}

func decodeStage2aRoleJSON(raw []byte, out any) error {
	if err := stage2aStrictJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func decodeStage2aRoleBase64(value string, max int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, errors.New("invalid Soul launch encoding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("invalid Soul launch encoding")
	}
	return raw, nil
}

func validStage2aExecDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && soulDigest.MatchString(value[7:])
}

// A supplies the proof in a reviewed role-private installation directory.
// HQ relays only the digest. Binding to this particular signed start happens
// before opening this file and a fresh process cannot replay an exec grant.
func readStage2aBridgeProof(start SoulStartAssignment, digest string) ([]byte, error) {
	invalid := errors.New("invalid one-use Soul bridge proof")
	if !validStage2aExecDigest(digest) || !soulInstallationID.MatchString(start.InstallationID) ||
		!soulStartID.MatchString(start.StartID) || start.BridgeUID != os.Getuid() ||
		start.BridgeUID != os.Geteuid() || start.BridgeGID != os.Getegid() || start.MachineUID <= 399 {
		return nil, invalid
	}
	path := filepath.Join(launchRuntimeDir, "b-grants", soulEndpointInstallationSlot(start.InstallationID))
	dir, err := openStage2aAdminDirectory(path, uint32(start.MachineUID))
	if err != nil {
		return nil, invalid
	}
	defer dir.Close()
	var parent unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &parent); err != nil ||
		parent.Mode != unix.S_IFDIR|02710 || parent.Uid != uint32(start.MachineUID) ||
		parent.Gid != uint32(start.BridgeGID) {
		return nil, invalid
	}
	name := soulEndpointStartSlot(start.InstallationID, start.StartID) + ".proof"
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode != unix.S_IFREG|0440 || st.Nlink != 1 ||
		st.Uid != uint32(start.MachineUID) || st.Gid != uint32(start.BridgeGID) || st.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(path, name)}) != nil {
		return nil, invalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, 33))
	var after unix.Stat_t
	if err != nil || len(raw) != 32 || stage2aReservationSHA256(raw) != digest ||
		unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
		clear(raw)
		return nil, invalid
	}
	return raw, nil
}
