//go:build darwin

package members

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type stage2aCooperativeLiveWireRequest struct {
	ID      int    `json:"id"`
	Op      string `json:"op"`
	Payload struct {
		InstallationID           string `json:"installation_id"`
		StartID                  string `json:"start_id"`
		LaunchID                 string `json:"launch_id"`
		ReservationSHA256        string `json:"reservation_sha256"`
		AssignmentEnvelopeSHA256 string `json:"assignment_envelope_sha256"`
		MemberBAuthoritySHA256   string `json:"member_b_authority_sha256"`
		MemberID                 string `json:"member_id"`
		MemberLaunchID           string `json:"member_launch_id"`
		MemberSelector           string `json:"member_selector"`
		GrantSHA256              string `json:"grant_sha256"`
		ReadySHA256              string `json:"ready_sha256"`
		LauncherPID              int    `json:"launcher_pid"`
		LauncherStartSeconds     int64  `json:"launcher_start_seconds"`
		LauncherStartMicros      int32  `json:"launcher_start_micros"`
		ChildPID                 int    `json:"child_pid"`
		ChildStartSeconds        int64  `json:"child_start_seconds"`
		ChildStartMicros         int32  `json:"child_start_micros"`
		ChallengeNonceBase64URL  string `json:"challenge_nonce_base64url"`
		AfterSequence            uint64 `json:"after_sequence"`
		PriorExpiresAt           string `json:"prior_expires_at"`
	} `json:"payload"`
}

type stage2aCooperativeLiveWireReply struct {
	ID     int  `json:"id"`
	OK     bool `json:"ok"`
	Result struct {
		ReadyEnvelopeBase64URL          string `json:"ready_envelope_base64url"`
		ReadySHA256                     string `json:"ready_sha256"`
		BridgeObservedEnvelopeBase64URL string `json:"bridge_observed_envelope_base64url"`
		BridgeObservedSHA256            string `json:"bridge_observed_sha256"`
		LeaseEnvelopeBase64URL          string `json:"lease_envelope_base64url"`
		LeaseSHA256                     string `json:"lease_sha256"`
		LeaseSequence                   uint64 `json:"lease_sequence"`
	} `json:"result"`
}

// The R wrapper, not H, originates each challenge on the existing local
// admission socket. H only relays signed A bytes. The stock ACP child never
// receives this connection and has no direct route to A or H.
func stage2aCooperativeAdmissionGate(in stage2aCooperativeChildInvocation,
	grant stage2aCooperativeChildGrant, grantSHA string,
	pub ed25519.PublicKey) (stage2aCooperativeChildGate, error) {
	invalid := errSoulCooperativeAuthority
	reservation, _, assignment, _, rSHA, _, aSHA, _, err :=
		verifyStage2aCooperativeChildSelectionFromInvocation(in, pub, time.Now())
	if err != nil || rSHA != grant.ReservationSHA256 ||
		aSHA != grant.AssignmentEnvelopeSHA256 ||
		grant.MemberBAuthoritySHA256 == "" {
		return stage2aCooperativeChildGate{}, invalid
	}
	bridge := SoulBridge{SoulID: assignment.SoulID,
		InstallationID: assignment.InstallationID,
		Account:        assignment.Bridge.Account, UID: assignment.Bridge.UID,
		GID: assignment.Bridge.GID}
	endpoints, err := DeriveSoulBridgeEndpoints(in.Runner, bridge,
		reservation.Assignment.HQUID, grant.StartID)
	if err != nil || endpoints.Admission.OwnerUID != reservation.Assignment.HQUID ||
		endpoints.Admission.GroupGID != in.Runner.GID ||
		len(endpoints.Admission.PeerUIDs) != 1 ||
		endpoints.Admission.PeerUIDs[0] != in.Runner.UID {
		return stage2aCooperativeChildGate{}, invalid
	}
	var launcher, child soulKernelProcessSnapshot
	gate := stage2aCooperativeChildGate{}
	gate.Await = func(wrapped stage2aMemberObservedLauncherProcess,
		stock stage2aMemberObservedProcess, reportedGrantSHA, challenge string,
		deadline time.Time) ([]byte, []byte, error) {
		if reportedGrantSHA != grantSHA || !time.Now().Before(deadline) ||
			deadline.After(timeMustParse(grant.ExpiresAt)) {
			return nil, nil, invalid
		}
		launcher, err = observeStage2aRoleProcess(wrapped.PID,
			in.Runner.UID, in.Runner.GID, "child")
		if err != nil || stage2aMemberLauncherIdentity(launcher) != wrapped {
			return nil, nil, invalid
		}
		child, err = observeStage2aChildProcess(stock.PID, wrapped.PID,
			in.Runner, in.Launch)
		if err != nil || stage2aMemberProcessIdentity(child, in.ExecutableSHA256) != stock {
			return nil, nil, invalid
		}
		return requestStage2aCooperativeLive(endpoints.Admission, endpoints.Relay, pub, reservation, grant,
			grantSHA, wrapped, stock, "", challenge, 0, deadline)
	}
	gate.Renew = func(readySHA, challenge string, after uint64,
		priorExpires time.Time) ([]byte, error) {
		if !validStage2aExecDigest(readySHA) ||
			after == 0 || after >= (1<<53)-1 ||
			!time.Now().Before(priorExpires) ||
			checkStage2aGrantedRoleProcess(launcher.PID, in.Runner.UID,
				in.Runner.GID, "child", launcher) != nil ||
			checkStage2aChildProcess(child.PID, launcher.PID,
				in.Runner, in.Launch, child) != nil {
			return nil, invalid
		}
		_, lease, err := requestStage2aCooperativeLive(endpoints.Admission, endpoints.Relay, pub,
			reservation, grant, grantSHA, stage2aMemberLauncherIdentity(launcher),
			stage2aMemberProcessIdentity(child, in.ExecutableSHA256),
			readySHA, challenge, after, priorExpires)
		return lease, err
	}
	return gate, nil
}

func requestStage2aCooperativeLive(endpoint, relay SoulEndpoint, pub ed25519.PublicKey,
	reservation soulCooperativeBReservationViewV3,
	grant stage2aCooperativeChildGrant, grantSHA string,
	launcher stage2aMemberObservedLauncherProcess,
	child stage2aMemberObservedProcess, readySHA, challenge string,
	after uint64, priorExpires time.Time) ([]byte, []byte, error) {
	invalid := errors.New("cooperative child live authority unavailable")
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(nonce) != 32 ||
		base64.RawURLEncoding.EncodeToString(nonce) != challenge ||
		!time.Now().Before(priorExpires) ||
		(after == 0) != (readySHA == "") ||
		(after > 0 && !validStage2aExecDigest(readySHA)) ||
		launcher.PID <= 1 || child.PID <= 1 ||
		child.ParentPID != launcher.PID ||
		endpoint.OwnerUID != reservation.Assignment.HQUID ||
		endpoint.GroupGID != reservation.Assignment.RunnerGID ||
		endpoint.DirMode != 02750 || endpoint.SocketMode != 0660 ||
		len(endpoint.PeerUIDs) != 1 ||
		endpoint.PeerUIDs[0] != reservation.Assignment.RunnerUID {
		return nil, nil, invalid
	}
	var directory, socket unix.Stat_t
	if unix.Lstat(endpoint.Directory, &directory) != nil ||
		unix.Lstat(endpoint.SocketPath, &socket) != nil ||
		directory.Mode != unix.S_IFDIR|02750 ||
		directory.Uid != uint32(endpoint.OwnerUID) ||
		directory.Gid != uint32(endpoint.GroupGID) ||
		socket.Mode != unix.S_IFSOCK|0660 ||
		socket.Uid != uint32(endpoint.OwnerUID) ||
		socket.Gid != uint32(endpoint.GroupGID) ||
		checkDarwinACLs([]string{endpoint.Directory, endpoint.SocketPath}) != nil {
		return nil, nil, invalid
	}
	timeout := time.Until(priorExpires)
	if after > 0 && timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	if timeout <= 0 {
		return nil, nil, invalid
	}
	conn, err := net.DialTimeout("unix", endpoint.SocketPath, timeout)
	if err != nil {
		return nil, nil, invalid
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, invalid
	}
	peer, err := ObserveSoulAdmissionPeer(unixConn)
	var directoryAfter, socketAfter unix.Stat_t
	if err != nil || peer.UID != endpoint.OwnerUID ||
		unix.Lstat(endpoint.Directory, &directoryAfter) != nil ||
		unix.Lstat(endpoint.SocketPath, &socketAfter) != nil ||
		directoryAfter.Dev != directory.Dev || directoryAfter.Ino != directory.Ino ||
		socketAfter.Dev != socket.Dev || socketAfter.Ino != socket.Ino ||
		socketAfter.Mode != socket.Mode || socketAfter.Uid != socket.Uid ||
		socketAfter.Gid != socket.Gid {
		return nil, nil, invalid
	}
	request := stage2aCooperativeLiveWireRequest{ID: 1, Op: "launch.cooperative.live"}
	p := &request.Payload
	p.InstallationID, p.StartID, p.LaunchID = grant.InstallationID, grant.StartID,
		reservation.Assignment.LaunchID
	p.ReservationSHA256 = grant.ReservationSHA256
	p.AssignmentEnvelopeSHA256 = grant.AssignmentEnvelopeSHA256
	p.MemberBAuthoritySHA256 = grant.MemberBAuthoritySHA256
	p.MemberID, p.MemberLaunchID, p.MemberSelector = grant.MemberID,
		grant.MemberLaunchID, grant.MemberSelector
	p.GrantSHA256, p.ReadySHA256 = grantSHA, readySHA
	p.LauncherPID, p.LauncherStartSeconds, p.LauncherStartMicros =
		launcher.PID, launcher.StartSeconds, launcher.StartMicros
	p.ChildPID, p.ChildStartSeconds, p.ChildStartMicros =
		child.PID, child.StartSeconds, child.StartMicros
	p.ChallengeNonceBase64URL, p.AfterSequence = challenge, after
	p.PriorExpiresAt = priorExpires.UTC().Format(time.RFC3339Nano)
	body, err := json.Marshal(request)
	if err != nil || len(body) > 4095 || conn.SetDeadline(priorExpires) != nil {
		return nil, nil, invalid
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
		return nil, nil, invalid
	}
	reader := bufio.NewReaderSize(conn, 32<<10)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 32<<10 || reader.Buffered() != 0 {
		return nil, nil, invalid
	}
	var response stage2aCooperativeLiveWireReply
	if stage2aDecodeExact(line, &response) != nil || response.ID != 1 ||
		!response.OK || response.Result.LeaseSequence != after+1 {
		return nil, nil, invalid
	}
	lease, err := decodeStage2aRoleBase64(response.Result.LeaseEnvelopeBase64URL, 8<<10)
	if err != nil || stage2aReservationSHA256(lease) != response.Result.LeaseSHA256 {
		return nil, nil, invalid
	}
	if after > 0 {
		if response.Result.ReadySHA256 != "" ||
			response.Result.ReadyEnvelopeBase64URL != "" ||
			response.Result.BridgeObservedSHA256 != "" ||
			response.Result.BridgeObservedEnvelopeBase64URL != "" ||
			!time.Now().Before(priorExpires) {
			return nil, nil, invalid
		}
		return nil, lease, nil
	}
	ready, err := decodeStage2aRoleBase64(response.Result.ReadyEnvelopeBase64URL, 16<<10)
	if err != nil || stage2aReservationSHA256(ready) != response.Result.ReadySHA256 ||
		!time.Now().Before(priorExpires) {
		return nil, nil, invalid
	}
	observed, err := decodeStage2aRoleBase64(response.Result.BridgeObservedEnvelopeBase64URL, 8<<10)
	if err != nil || stage2aReservationSHA256(observed) != response.Result.BridgeObservedSHA256 ||
		verifyStage2aCooperativeRelayForR(ready, observed, relay, reservation, grant,
			pub, time.Now()) != nil {
		return nil, nil, invalid
	}
	return ready, lease, nil
}

// R verifies the A-observed B/relay identity before releasing stock ACP
// input. H only transports these signed bytes; a substituted socket or birth
// time cannot ride on a valid Ready digest.
func verifyStage2aCooperativeRelayForR(readyEnvelope, observedEnvelope []byte,
	relay SoulEndpoint, reservation soulCooperativeBReservationViewV3,
	grant stage2aCooperativeChildGrant, pub ed25519.PublicKey, now time.Time) error {
	invalid := errSoulCooperativeAuthority
	readyRaw, err := verifyStage2aStoredARecordV3(readyEnvelope,
		stage2aCooperativeReadyPurpose, 3, pub)
	var ready soulCooperativeReadyPayloadV3
	observedRaw, observedErr := verifyStage2aStoredARecordV3(observedEnvelope,
		soulCooperativeBObservedPurposeV3, 3, pub)
	var observed soulCooperativeBObservedPayloadV3
	if err != nil || observedErr != nil ||
		stage2aDecodeExact(readyRaw, &ready) != nil ||
		stage2aDecodeExact(observedRaw, &observed) != nil ||
		ready.ProfileInForce != "managed-cooperative" ||
		ready.BridgeObservedSHA256 != stage2aReservationSHA256(observedEnvelope) ||
		ready.ReservationSHA256 != grant.ReservationSHA256 ||
		observed.ReservationSHA256 != grant.ReservationSHA256 ||
		observed.BridgeAssignmentSHA256 != grant.BridgeAssignmentSHA256 ||
		observed.InstallationID != grant.InstallationID || observed.StartID != grant.StartID ||
		observed.LaunchID != reservation.Assignment.LaunchID ||
		observed.HQEpoch != grant.HQEpoch ||
		observed.RelaySocket.Path != relay.SocketPath ||
		!stage2aPositiveDecimal(observed.RelaySocketBirthtimeNS) ||
		relay.Directory == "" || relay.OwnerUID <= 0 || relay.GroupGID <= 0 ||
		relay.SocketMode != 0660 {
		return invalid
	}
	readyUntil, e1 := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	observedUntil, e2 := time.Parse(time.RFC3339Nano, observed.ExpiresAt)
	if e1 != nil || e2 != nil || !now.Before(readyUntil) || !now.Before(observedUntil) {
		return invalid
	}
	var directory, socket unix.Stat_t
	if unix.Lstat(relay.Directory, &directory) != nil ||
		unix.Lstat(relay.SocketPath, &socket) != nil ||
		directory.Mode != unix.S_IFDIR|uint16(relay.DirMode) ||
		directory.Uid != uint32(relay.OwnerUID) ||
		directory.Gid != uint32(relay.GroupGID) ||
		socket.Mode != unix.S_IFSOCK|uint16(relay.SocketMode) ||
		socket.Uid != uint32(relay.OwnerUID) ||
		socket.Gid != uint32(relay.GroupGID) ||
		observed.RelaySocket.Socket.UID != socket.Uid ||
		observed.RelaySocket.Socket.GID != socket.Gid ||
		observed.RelaySocket.Socket.Mode != uint32(socket.Mode&07777) ||
		observed.RelaySocket.Socket.Device != strconv.FormatUint(uint64(uint32(socket.Dev)), 10) ||
		observed.RelaySocket.Socket.Inode != strconv.FormatUint(socket.Ino, 10) ||
		socket.Btim.Sec <= 0 || socket.Btim.Nsec < 0 || socket.Btim.Nsec >= 1_000_000_000 ||
		socket.Btim.Sec > (1<<63-1)/1_000_000_000 ||
		observed.RelaySocketBirthtimeNS !=
			strconv.FormatInt(socket.Btim.Sec*1_000_000_000+socket.Btim.Nsec, 10) ||
		checkDarwinACLs([]string{relay.Directory, relay.SocketPath}) != nil {
		return invalid
	}
	return nil
}
