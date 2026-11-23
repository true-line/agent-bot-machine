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
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

const soulCooperativeDispatchSchema = "agent-bot-souls/cooperative-start/v1"

// The A-owned request supplies the exact bytes streamed through FD3 to Souls.
// R may read but cannot replace it; both R and Souls verify the pinned A signature.
type soulCooperativeDispatchRequest struct {
	Schema                       string                    `json:"schema"`
	ReservationEnvelopeBase64URL string                    `json:"reservation_envelope_base64url"`
	ReservationSHA256            string                    `json:"reservation_sha256"`
	MachinePinPath               string                    `json:"machine_pin_path"`
	LaunchInputRecords           Stage2aLaunchInputRecords `json:"launch_input_records"`
	StateRoot                    string                    `json:"state_root"`
	AdmissionChallengeBase64URL  string                    `json:"admission_challenge_base64url"`
}

type soulCooperativeDispatchCompletion struct {
	Schema             string `json:"schema"`
	ReservationSHA256  string `json:"reservation_sha256"`
	StartID            string `json:"start_id"`
	LaunchID           string `json:"launch_id"`
	DispatcherPID      int    `json:"dispatcher_pid"`
	RunnerPID          int    `json:"runner_pid"`
	ExitCode           int    `json:"exit_code"`
	StartedAt          string `json:"started_at"`
	FinishedAt         string `json:"finished_at"`
	DescendantsStopped bool   `json:"descendants_stopped"`
	CancelSHA256       string `json:"cancel_sha256,omitempty"`
}

func decodeSoulCooperativeDispatchRequest(raw []byte, pin ed25519.PublicKey,
	installationID string, uid, gid int, now time.Time) (soulCooperativeDispatchRequest,
	soulCooperativeReservationPayloadV3, error) {
	var request soulCooperativeDispatchRequest
	var payload soulCooperativeReservationPayloadV3
	if stage2aStrictJSONBounded(raw, 64<<10, stage2aV3MaxJSONNodes) != nil {
		return request, payload, errSoulCooperativeAuthority
	}
	canonicalRequest, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonicalRequest) {
		return request, payload, errSoulCooperativeAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF ||
		request.Schema != soulCooperativeDispatchSchema || request.MachinePinPath != SoulAuthorityPin ||
		request.StateRoot == "" || !stage2aPrefixedDigest.MatchString(request.ReservationSHA256) {
		return soulCooperativeDispatchRequest{}, payload, errSoulCooperativeAuthority
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(request.ReservationEnvelopeBase64URL)
	if err != nil || len(envelope) > 2<<20 ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(envelope)) != request.ReservationSHA256 {
		return soulCooperativeDispatchRequest{}, payload, errSoulCooperativeAuthority
	}
	canonical, _, err := verifySoulCooperativeEnvelopeV3(envelope, pin)
	if err != nil || stage2aStrictJSONBounded(canonical, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return soulCooperativeDispatchRequest{}, payload, errSoulCooperativeAuthority
	}
	decoder = json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF ||
		payload.Contract != "machine/v3" || payload.Kind != "soul-cooperative-reservation" ||
		payload.SchemaVersion != 3 || payload.AdapterTransport != "brokered-b" ||
		payload.Assignment.InstallationID != installationID ||
		payload.Assignment.RunnerUID != uid || payload.Assignment.RunnerGID != gid ||
		payload.Assignment.StateRoot != request.StateRoot ||
		payload.MeasurementBinding.ProfileInForce != "managed-cooperative" ||
		payload.Assignment.PackageRoot != payload.MeasurementBinding.Snapshots.Definition.RootPath ||
		payload.Assignment.LaunchInputsRoot != payload.MeasurementBinding.Snapshots.LaunchInputs.RootPath ||
		payload.Assignment.RuntimeRoot != payload.MeasurementBinding.RInventory.Snapshot.Path ||
		payload.Assignment.NodePath != path.Join(payload.Assignment.RuntimeRoot, "bin/node") ||
		payload.Assignment.EntryPath != path.Join(payload.Assignment.RuntimeRoot, "bin/agent-bot-souls.mjs") ||
		payload.MeasurementBinding.LaunchInputMeasurement == "" {
		return soulCooperativeDispatchRequest{}, soulCooperativeReservationPayloadV3{}, errSoulCooperativeAuthority
	}
	expires, err := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil || !now.Before(expires) || expires.Sub(now) > 30*time.Second {
		return soulCooperativeDispatchRequest{}, soulCooperativeReservationPayloadV3{}, errSoulCooperativeAuthority
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(request.AdmissionChallengeBase64URL)
	if err != nil || len(challenge) != 32 ||
		fmt.Sprintf("sha256:%x", sha256.Sum256(challenge)) != payload.AdmissionChallengeSHA256 {
		return soulCooperativeDispatchRequest{}, soulCooperativeReservationPayloadV3{}, errSoulCooperativeAuthority
	}
	digest, _, err := Stage2aLaunchInputDigest(request.LaunchInputRecords)
	if err != nil || digest != payload.MeasurementBinding.LaunchInputMeasurement ||
		request.LaunchInputRecords.AdapterTransport != payload.AdapterTransport ||
		request.LaunchInputRecords.BridgeLaunchSHA256 != payload.BridgeLaunchSHA256 {
		return soulCooperativeDispatchRequest{}, soulCooperativeReservationPayloadV3{}, errSoulCooperativeAuthority
	}
	return request, payload, nil
}

// RunSoulCooperativeDispatch is reached only by the installed launchd job as
// the per-Soul R UID. It has no sudo path or privileged network capability.
func RunSoulCooperativeDispatch(installationID string) int {
	if !soulInstallationID.MatchString(installationID) || os.Getuid() < 300 ||
		os.Getuid() > 399 || os.Geteuid() != os.Getuid() || os.Getgid() != os.Getuid() ||
		os.Getegid() != os.Getgid() {
		return 78
	}
	paths, err := cooperativeLaunchPaths(installationID)
	if err != nil {
		return 78
	}
	requestDir, err := unix.Open(paths.requestDir, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return 78
	}
	defer unix.Close(requestDir)
	var dirStat unix.Stat_t
	if unix.Fstat(requestDir, &dirStat) != nil || dirStat.Mode != unix.S_IFDIR|02750 ||
		dirStat.Gid != uint32(os.Getgid()) || dirStat.Uid < 400 ||
		checkDarwinACLs([]string{paths.requestDir}) != nil {
		return 78
	}
	fd, err := unix.Openat(requestDir, "request.json", stage2aFileOpenFlags, 0)
	if err != nil {
		return 78
	}
	file := os.NewFile(uintptr(fd), paths.request)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0640 ||
		before.Uid != dirStat.Uid || before.Gid != dirStat.Gid || before.Nlink != 1 ||
		before.Size < 1 || before.Size > 64<<10 || checkDarwinACLs([]string{paths.request}) != nil {
		return 78
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) {
		return 78
	}
	pin, err := os.ReadFile(SoulAuthorityPin)
	if err != nil || len(pin) != ed25519.PublicKeySize {
		return 78
	}
	request, payload, err := decodeSoulCooperativeDispatchRequest(raw, ed25519.PublicKey(pin),
		installationID, os.Getuid(), os.Getgid(), time.Now())
	if err != nil || !cooperativeDispatchArgv(payload, request.LaunchInputRecords) {
		return 78
	}
	fd3, err := cooperativeFD3AfterPublishedOutcome(paths, requestDir, fd, raw,
		request, payload, ed25519.PublicKey(pin), before)
	if err != nil {
		return 78
	}
	if !cooperativeBParentReady(payload.Endpoints.Member) ||
		!cooperativeBParentReady(payload.Endpoints.Relay) {
		return 78
	}
	profile, err := stage2aReadRootFile(SoulRunnerSandbox, int64(len(soulRunnerProfile)), 0444)
	if err != nil || !bytes.Equal(profile, soulRunnerProfile) ||
		request.LaunchInputRecords.SandboxPolicyDigest != "sha256:"+harnessSHA(profile) ||
		!stage2aSystemImageSelected(request.LaunchInputRecords, "/usr/bin/sandbox-exec") {
		return 78
	}
	// HQ cannot bind C until it verifies this A-signed reservation. The
	// WatchPaths dispatcher waits only for the two exact H-owned local sockets;
	// an absent or replaced endpoint fails without starting the Soul.
	if waitSoulCooperativeHQEndpoints(payload, paths, requestDir, ed25519.PublicKey(pin),
		request.ReservationSHA256, time.Now()) != nil {
		return 78
	}
	start := time.Now().UTC()
	argv := request.LaunchInputRecords.Argv
	sandboxArgs := []string{
		"-D", "ADMISSION_SOCKET=" + payload.Endpoints.Admission.SocketPath,
		"-D", "MEMBER_SOCKET=" + payload.Endpoints.Member.SocketPath,
		"-D", "RELAY_SOCKET=" + payload.Endpoints.Relay.SocketPath,
		"-f", SoulRunnerSandbox}
	sandboxArgs = append(sandboxArgs, argv...)
	cmd := exec.Command("/usr/bin/sandbox-exec", sandboxArgs...)
	cmd.Dir = request.StateRoot
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + request.StateRoot,
		"AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH=1"}
	// Souls requires a FIFO on FD3. The verified request is a regular
	// A-owned file, so pass its already checked canonical bytes over a pipe.
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		return 78
	}
	cmd.ExtraFiles = []*os.File{pipeRead}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		pipeRead.Close()
		pipeWrite.Close()
		return 78
	}
	pipeRead.Close()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := pipeWrite.Write(fd3)
		if closeErr := pipeWrite.Close(); writeErr == nil {
			writeErr = closeErr
		}
		writeDone <- writeErr
	}()
	pid := cmd.Process.Pid
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	var cancelSHA string
	for running := true; running; {
		select {
		case err = <-waited:
			running = false
		case <-poll.C:
			want := soulCooperativeCancelPayloadV3{ReservationSHA256: request.ReservationSHA256,
				InstallationID: payload.Assignment.InstallationID,
				StartID:        payload.Assignment.StartID, LaunchID: payload.Assignment.LaunchID,
				RunnerPID: pid}
			found, digest, checkErr := readSoulCooperativeCancel(requestDir, paths,
				ed25519.PublicKey(pin), want, time.Now().UTC())
			if !found && checkErr == nil {
				continue
			}
			if checkErr == nil {
				cancelSHA = digest
			}
			// A malformed A-owned selector is also a reason to terminate.
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			select {
			case err = <-waited:
			case <-time.After(500 * time.Millisecond):
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				err = <-waited
			}
			running = false
		}
	}
	// The dispatcher terminates the child's process group; A independently
	// observes that this exact group is gone before signing completion. A
	// descendant may retain FD3 without reading, so terminate the group
	// before boundedly collecting the pipe writer rather than waiting forever.
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	stopped := syscall.Kill(-pid, 0) == syscall.ESRCH
	if finishSoulCooperativePipeWrite(pipeWrite, writeDone, 300*time.Millisecond) != nil {
		err = errSoulCooperativeAuthority
	}
	code := 0
	if err != nil {
		code = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
			if code < 0 {
				code = 255
			}
		}
	}
	completion := soulCooperativeDispatchCompletion{Schema: "agent-bot-machine/cooperative-dispatch-completion/v1",
		ReservationSHA256: request.ReservationSHA256, StartID: payload.Assignment.StartID,
		LaunchID: payload.Assignment.LaunchID, DispatcherPID: os.Getpid(), RunnerPID: pid,
		ExitCode: code, StartedAt: start.Format(time.RFC3339Nano),
		FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), DescendantsStopped: stopped,
		CancelSHA256: cancelSHA}
	if writeSoulCooperativeDispatchCompletion(paths, completion) != nil {
		return 78
	}
	return code
}

func finishSoulCooperativePipeWrite(writer *os.File, done <-chan error, limit time.Duration) error {
	if writer == nil || done == nil || limit <= 0 {
		return errSoulCooperativeAuthority
	}
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		// A Close can itself wait on an in-progress write. The dispatcher
		// remains bounded and fails closed even if a descendant held FD3.
		go writer.Close()
		return errSoulCooperativeAuthority
	}
}

func waitSoulCooperativeHQEndpoints(p soulCooperativeReservationPayloadV3,
	paths soulCooperativeLaunchPaths, requestDir int, key ed25519.PublicKey,
	reservationSHA string, start time.Time) error {
	expires, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		return errSoulCooperativeAuthority
	}
	deadline := start.Add(18 * time.Second)
	if expires.Add(-5 * time.Second).Before(deadline) {
		deadline = expires.Add(-5 * time.Second)
	}
	for time.Now().Before(deadline) {
		want := soulCooperativeCancelPayloadV3{ReservationSHA256: reservationSHA,
			InstallationID: p.Assignment.InstallationID, StartID: p.Assignment.StartID,
			LaunchID: p.Assignment.LaunchID, RunnerPID: 0}
		if canceled, _, e := readSoulCooperativeCancel(requestDir, paths, key, want, time.Now()); e != nil || canceled {
			return errSoulCooperativeAuthority
		}
		if cooperativeHQEndpointReady(p.Endpoints.Admission) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errSoulCooperativeAuthority
}

func cooperativeHQEndpointReady(e soulCooperativeEndpointV3) bool {
	if filepath.Dir(e.SocketPath) != e.Directory || e.OwnerUID < 300 ||
		e.GroupGID < 300 || e.DirMode != 02750 || e.SocketMode != 0660 {
		return false
	}
	dir, err := unix.Open(e.Directory, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	var parent, socket unix.Stat_t
	if unix.Fstat(dir, &parent) != nil {
		return false
	}
	return parent.Mode == unix.S_IFDIR|uint16(e.DirMode) &&
		parent.Uid == uint32(e.OwnerUID) && parent.Gid == uint32(e.GroupGID) &&
		checkDarwinACLs([]string{e.Directory}) == nil &&
		unix.Fstatat(dir, filepath.Base(e.SocketPath), &socket, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		socket.Mode == unix.S_IFSOCK|uint16(e.SocketMode) &&
		socket.Uid == uint32(e.OwnerUID) && socket.Gid == uint32(e.GroupGID) &&
		checkDarwinACLs([]string{e.SocketPath}) == nil
}

func cooperativeBParentReady(e soulCooperativeBEndpointV3) bool {
	if filepath.Dir(e.SocketPath) != e.Directory || e.OwnerUID < 300 ||
		e.GroupGID < 300 || e.DirMode != 02750 || e.SocketMode != 0660 ||
		e.ParentDevice == "" || e.ParentInode == "" || e.ParentBirthtimeNS == "" {
		return false
	}
	dir, err := unix.Open(e.Directory, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	var parent unix.Stat_t
	if unix.Fstat(dir, &parent) != nil {
		return false
	}
	birth := parent.Btim.Sec*1_000_000_000 + parent.Btim.Nsec
	return parent.Mode == unix.S_IFDIR|uint16(e.DirMode) &&
		parent.Uid == uint32(e.OwnerUID) && parent.Gid == uint32(e.GroupGID) &&
		e.ParentDevice == strconv.FormatUint(uint64(uint32(parent.Dev)), 10) &&
		e.ParentInode == strconv.FormatUint(parent.Ino, 10) &&
		e.ParentBirthtimeNS == strconv.FormatInt(birth, 10) &&
		checkDarwinACLs([]string{e.Directory}) == nil
}

func cooperativeDispatchArgv(p soulCooperativeReservationPayloadV3, in Stage2aLaunchInputRecords) bool {
	want := []string{p.Assignment.NodePath, p.Assignment.EntryPath, "run", "--soul",
		p.Assignment.PackageRoot, "--admission-socket", p.Endpoints.Admission.SocketPath,
		"--member-socket", p.Endpoints.Member.SocketPath,
		"--relay-socket", p.Endpoints.Relay.SocketPath,
		"--profile", "managed-cooperative",
		"--cooperative-start-fd", "3"}
	if len(in.Argv) != len(want) || in.SelectedCommand != p.Assignment.NodePath ||
		len(in.Environment) != 3 || in.Environment["PATH"] != "/usr/bin:/bin" ||
		in.Environment["HOME"] != p.Assignment.StateRoot ||
		in.Environment["AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH"] != "1" {
		return false
	}
	for i := range want {
		if in.Argv[i] != want[i] {
			return false
		}
	}
	return true
}

func writeSoulCooperativeDispatchCompletion(paths soulCooperativeLaunchPaths,
	completion soulCooperativeDispatchCompletion) error {
	raw, err := json.Marshal(completion)
	if err != nil || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return errSoulCooperativeAuthority
	}
	f, err := os.CreateTemp(paths.completionDir, ".completion-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0444); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := unix.RenamexNp(f.Name(), path.Join(paths.completionDir, "completion.json"), unix.RENAME_EXCL); err != nil {
		return err
	}
	return syncUpgradeDir(paths.completionDir)
}
