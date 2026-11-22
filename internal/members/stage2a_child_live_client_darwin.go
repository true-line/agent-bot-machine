//go:build darwin

package members

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

type stage2aChildLiveWire struct {
	ID     int  `json:"id"`
	OK     bool `json:"ok"`
	Result struct {
		LeaseEnvelopeBase64URL string `json:"lease_envelope_base64url"`
		LeaseSHA256            string `json:"lease_sha256"`
		LeaseSequence          uint64 `json:"lease_sequence"`
	} `json:"result"`
}

func requestStage2aChildLive(in Stage2aRoleInvocation, receiptSHA256 string,
	launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	after uint64) (Stage2aLiveLeasePayload, error) {
	invalid := errors.New("protected child Live lease unavailable")
	if in.ChildExec == nil || !validStage2aExecDigest(receiptSHA256) ||
		in.Start.Admission.OwnerUID != in.Start.HQUID ||
		in.Start.Admission.GroupGID != in.Runner.GID ||
		in.Start.Admission.DirMode != 02750 || in.Start.Admission.SocketMode != 0660 ||
		len(in.Start.Admission.PeerUIDs) != 1 || in.Start.Admission.PeerUIDs[0] != in.Runner.UID ||
		filepath.Dir(in.Start.Admission.SocketPath) != in.Start.Admission.Directory {
		return Stage2aLiveLeasePayload{}, invalid
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.Runner, in.Bridge, in.Start.HQUID, in.Request.StartID)
	if err != nil || !reflect.DeepEqual(startEndpoint(endpoints.Admission), in.Start.Admission) {
		return Stage2aLiveLeasePayload{}, invalid
	}
	var directory, socket unix.Stat_t
	if unix.Lstat(in.Start.Admission.Directory, &directory) != nil ||
		unix.Lstat(in.Start.Admission.SocketPath, &socket) != nil ||
		directory.Mode != unix.S_IFDIR|02750 || directory.Uid != uint32(in.Start.HQUID) ||
		directory.Gid != uint32(in.Runner.GID) ||
		socket.Mode != unix.S_IFSOCK|0660 || socket.Uid != uint32(in.Start.HQUID) ||
		socket.Gid != uint32(in.Runner.GID) ||
		checkDarwinACLs([]string{in.Start.Admission.Directory, in.Start.Admission.SocketPath}) != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	conn, err := net.DialTimeout("unix", in.Start.Admission.SocketPath, 1500*time.Millisecond)
	if err != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Stage2aLiveLeasePayload{}, invalid
	}
	peer, err := ObserveSoulAdmissionPeer(unixConn)
	if err != nil || peer.UID != in.Start.HQUID ||
		unix.Lstat(in.Start.Admission.Directory, &socket) != nil ||
		socket.Dev != directory.Dev || socket.Ino != directory.Ino {
		return Stage2aLiveLeasePayload{}, invalid
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	challenge := base64.RawURLEncoding.EncodeToString(nonce[:])
	request := struct {
		ID      int    `json:"id"`
		Op      string `json:"op"`
		Payload struct {
			InstallationID    string `json:"installation_id"`
			StartID           string `json:"start_id"`
			LaunchID          string `json:"launch_id"`
			ReservationSHA256 string `json:"reservation_sha256"`
			Challenge         string `json:"challenge"`
		} `json:"payload"`
	}{ID: 1, Op: "launch.live"}
	request.Payload.InstallationID = in.Request.InstallationID
	request.Payload.StartID = in.Request.StartID
	request.Payload.LaunchID = in.Start.LaunchID
	request.Payload.ReservationSHA256 = in.ChildExec.ReservationSHA256
	request.Payload.Challenge = challenge
	body, err := json.Marshal(request)
	if err != nil || len(body) > 4095 || conn.SetDeadline(time.Now().Add(1500*time.Millisecond)) != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
		return Stage2aLiveLeasePayload{}, invalid
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 16<<10 || reader.Buffered() != 0 {
		return Stage2aLiveLeasePayload{}, invalid
	}
	var response stage2aChildLiveWire
	if decodeStage2aRoleJSON(line, &response) != nil || response.ID != 1 || !response.OK ||
		!validStage2aExecDigest(response.Result.LeaseSHA256) || response.Result.LeaseSequence <= after {
		return Stage2aLiveLeasePayload{}, invalid
	}
	reply := Stage2aLiveReply{LeaseEnvelopeBase64URL: response.Result.LeaseEnvelopeBase64URL,
		LeaseSHA256: response.Result.LeaseSHA256, LeaseSequence: response.Result.LeaseSequence}
	lease, err := verifyStage2aChildLiveLease(reply, challenge, in, receiptSHA256,
		launcher, child, pub, after, time.Now())
	if err != nil || lease.ExpiresAtMS <= time.Now().UnixMilli() {
		return Stage2aLiveLeasePayload{}, invalid
	}
	return lease, nil
}
