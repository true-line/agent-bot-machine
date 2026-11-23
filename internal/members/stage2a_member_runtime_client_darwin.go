//go:build darwin

package members

import (
	"bufio"
	"context"
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

// HQ sends this exact frame on the already authenticated child control stream.
// Its digest is only a selector; A must bind it into each signed runtime lease.
type stage2aProtectedMemberReadyFrame struct {
	Observation          Stage2aHelloReply `json:"observation"`
	Ready                Stage2aHelloReply `json:"ready"`
	HQFinalizationSHA256 string            `json:"hq_finalization_sha256"`
}

func runStage2aProtectedMemberReady(ctx context.Context, cancel context.CancelFunc, line []byte,
	in Stage2aRoleInvocation, grantSHA256 string, launcher, child soulKernelProcessSnapshot,
	pub ed25519.PublicKey, reporter *harnessReporter) error {
	invalid := errors.New("protected two-member Ready unavailable")
	var frame stage2aProtectedMemberReadyFrame
	if decodeStage2aRoleJSON(line, &frame) != nil ||
		!stage2aPrefixedDigest.MatchString(frame.HQFinalizationSHA256) {
		return invalid
	}
	ready, err := verifyStage2aProtectedMemberReady(frame.Ready, frame.Observation,
		in, grantSHA256, launcher, child, pub, time.Now())
	if err != nil {
		return invalid
	}
	readyExpires, err := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	if err != nil || !time.Now().Before(readyExpires) {
		return invalid
	}
	first, firstSHA, err := requestStage2aProtectedMemberRuntime(in, ready,
		frame.Ready.SHA256, frame.Observation.SHA256, frame.HQFinalizationSHA256,
		grantSHA256, launcher, child, pub, 0, nil, readyExpires)
	if err != nil {
		return invalid
	}
	firstExpires, err := time.Parse(time.RFC3339Nano, first.ExpiresAt)
	if err != nil || time.Until(firstExpires) <= time.Second {
		return invalid
	}
	// The timer cancels the stock child if renewal fails or stalls. ACP stdin is
	// still held by superviseHarnessStarted until this first A-signed lease.
	go watchStage2aProtectedMemberRuntime(ctx, cancel, in, ready, frame,
		grantSHA256, launcher, child, pub, first, firstSHA)
	if reporter.write(struct {
		Kind                 string `json:"kind"`
		ReadySHA256          string `json:"ready_sha256"`
		HQFinalizationSHA256 string `json:"hq_finalization_sha256"`
		LeaseSequence        uint64 `json:"lease_sequence"`
	}{"child-accepted", frame.Ready.SHA256, frame.HQFinalizationSHA256, first.Sequence}) != nil {
		return invalid
	}
	if ctx.Err() != nil || time.Until(firstExpires) <= time.Second {
		return invalid
	}
	return nil
}

func requestStage2aProtectedMemberRuntime(in Stage2aRoleInvocation,
	ready stage2aMemberReadyPayload, readySHA256, observationSHA256, hqFinalizationSHA256,
	grantSHA256 string, launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	after uint64, previousSHA256 *string, priorExpires time.Time,
) (stage2aProtectedMemberRuntimeLease, string, error) {
	invalid := errors.New("protected two-member runtime lease unavailable")
	var empty stage2aProtectedMemberRuntimeLease
	exec := in.ChildExec
	if exec == nil || exec.MemberID == "" || !time.Now().Before(priorExpires) ||
		in.Start.Admission.OwnerUID != in.Start.HQUID ||
		in.Start.Admission.GroupGID != in.Runner.GID ||
		in.Start.Admission.DirMode != 02750 || in.Start.Admission.SocketMode != 0660 ||
		len(in.Start.Admission.PeerUIDs) != 1 || in.Start.Admission.PeerUIDs[0] != in.Runner.UID ||
		filepath.Dir(in.Start.Admission.SocketPath) != in.Start.Admission.Directory {
		return empty, "", invalid
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.Runner, in.Bridge, in.Start.HQUID, in.Request.StartID)
	if err != nil || !reflect.DeepEqual(startEndpoint(endpoints.Admission), in.Start.Admission) {
		return empty, "", invalid
	}
	var directory, socket unix.Stat_t
	if unix.Lstat(in.Start.Admission.Directory, &directory) != nil ||
		unix.Lstat(in.Start.Admission.SocketPath, &socket) != nil ||
		directory.Mode != unix.S_IFDIR|02750 || directory.Uid != uint32(in.Start.HQUID) ||
		directory.Gid != uint32(in.Runner.GID) ||
		socket.Mode != unix.S_IFSOCK|0660 || socket.Uid != uint32(in.Start.HQUID) ||
		socket.Gid != uint32(in.Runner.GID) ||
		checkDarwinACLs([]string{in.Start.Admission.Directory, in.Start.Admission.SocketPath}) != nil {
		return empty, "", invalid
	}
	timeout := time.Until(priorExpires)
	if timeout > 1500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	if timeout <= 0 {
		return empty, "", invalid
	}
	conn, err := net.DialTimeout("unix", in.Start.Admission.SocketPath, timeout)
	if err != nil {
		return empty, "", invalid
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return empty, "", invalid
	}
	peer, err := ObserveSoulAdmissionPeer(unixConn)
	if err != nil || peer.UID != in.Start.HQUID ||
		unix.Lstat(in.Start.Admission.Directory, &socket) != nil ||
		socket.Dev != directory.Dev || socket.Ino != directory.Ino {
		return empty, "", invalid
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, "", invalid
	}
	challenge := base64.RawURLEncoding.EncodeToString(nonce[:])
	request := struct {
		ID      int    `json:"id"`
		Op      string `json:"op"`
		Payload struct {
			InstallationID                 string  `json:"installation_id"`
			StartID                        string  `json:"start_id"`
			LaunchID                       string  `json:"launch_id"`
			ReservationSHA256              string  `json:"reservation_sha256"`
			MemberID                       string  `json:"member_id"`
			MemberSelector                 string  `json:"member_selector"`
			MemberLaunchID                 string  `json:"member_launch_id"`
			GrantSHA256                    string  `json:"grant_sha256"`
			ChildObservationEnvelopeSHA256 string  `json:"child_observation_envelope_sha256"`
			LauncherPID                    int     `json:"launcher_pid"`
			ChildPID                       int     `json:"child_pid"`
			ChallengeNonceBase64URL        string  `json:"challenge_nonce_base64url"`
			AfterSequence                  uint64  `json:"after_sequence"`
			PriorExpiresAt                 string  `json:"prior_expires_at"`
			ReadyEnvelopeSHA256            string  `json:"ready_envelope_sha256"`
			HQFinalizationSHA256           string  `json:"hq_finalization_sha256"`
			PreviousLeaseEnvelopeSHA256    *string `json:"previous_lease_envelope_sha256"`
		} `json:"payload"`
	}{ID: 1, Op: "launch.member.runtime"}
	p := &request.Payload
	p.InstallationID, p.StartID, p.LaunchID = in.Request.InstallationID, in.Request.StartID, in.Start.LaunchID
	p.ReservationSHA256 = exec.ReservationSHA256
	p.MemberID, p.MemberSelector, p.MemberLaunchID = exec.MemberID, exec.MemberSelector, exec.MemberLaunchID
	p.GrantSHA256, p.ChildObservationEnvelopeSHA256 = grantSHA256, observationSHA256
	p.LauncherPID, p.ChildPID = launcher.PID, child.PID
	p.ChallengeNonceBase64URL, p.AfterSequence = challenge, after
	p.PriorExpiresAt = priorExpires.UTC().Format(time.RFC3339Nano)
	p.ReadyEnvelopeSHA256, p.HQFinalizationSHA256 = readySHA256, hqFinalizationSHA256
	p.PreviousLeaseEnvelopeSHA256 = previousSHA256
	body, err := json.Marshal(request)
	deadline := time.Now().Add(1500 * time.Millisecond)
	if deadline.After(priorExpires) {
		deadline = priorExpires
	}
	if err != nil || len(body) > 4095 || !time.Now().Before(deadline) || conn.SetDeadline(deadline) != nil {
		return empty, "", invalid
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return empty, "", invalid
	}
	reader := bufio.NewReaderSize(conn, 16<<10)
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > 16<<10 || reader.Buffered() != 0 {
		return empty, "", invalid
	}
	var response stage2aChildLiveWire
	if decodeStage2aRoleJSON(line, &response) != nil || response.ID != 1 || !response.OK ||
		!stage2aPrefixedDigest.MatchString(response.Result.LeaseSHA256) ||
		response.Result.LeaseSequence != after+1 {
		return empty, "", invalid
	}
	reply := Stage2aLiveReply{LeaseEnvelopeBase64URL: response.Result.LeaseEnvelopeBase64URL,
		LeaseSHA256: response.Result.LeaseSHA256, LeaseSequence: response.Result.LeaseSequence}
	verifiedAt := time.Now()
	if !verifiedAt.Before(priorExpires) {
		return empty, "", invalid
	}
	lease, err := verifyStage2aProtectedMemberRuntimeLease(reply, ready, readySHA256,
		observationSHA256, hqFinalizationSHA256, grantSHA256, challenge,
		in, launcher, child, pub, after, previousSHA256, priorExpires, verifiedAt)
	if err != nil || !time.Now().Before(priorExpires) {
		return empty, "", invalid
	}
	return lease, reply.LeaseSHA256, nil
}

func watchStage2aProtectedMemberRuntime(ctx context.Context, cancel context.CancelFunc,
	in Stage2aRoleInvocation, ready stage2aMemberReadyPayload,
	frame stage2aProtectedMemberReadyFrame, grantSHA256 string,
	launcher, child soulKernelProcessSnapshot, pub ed25519.PublicKey,
	first stage2aProtectedMemberRuntimeLease, firstSHA256 string) {
	last, lastSHA256 := first, firstSHA256
	for {
		expires, err := time.Parse(time.RFC3339Nano, last.ExpiresAt)
		if err != nil || !time.Now().Before(expires) {
			cancel()
			return
		}
		expiryTimer := time.AfterFunc(time.Until(expires), cancel)
		wait := time.Until(expires) - 2*time.Second
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			expiryTimer.Stop()
			return
		case <-time.After(wait):
		}
		for {
			if ctx.Err() != nil || !time.Now().Before(expires) {
				expiryTimer.Stop()
				cancel()
				return
			}
			next, nextSHA256, err := requestStage2aProtectedMemberRuntime(in, ready,
				frame.Ready.SHA256, frame.Observation.SHA256, frame.HQFinalizationSHA256,
				grantSHA256, launcher, child, pub, last.Sequence, &lastSHA256, expires)
			if ctx.Err() != nil || !time.Now().Before(expires) {
				expiryTimer.Stop()
				cancel()
				return
			}
			if err == nil {
				if !expiryTimer.Stop() {
					cancel()
					return
				}
				last, lastSHA256 = next, nextSHA256
				break
			}
			select {
			case <-ctx.Done():
				expiryTimer.Stop()
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}
