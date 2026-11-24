//go:build darwin

package members

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"time"

	"github.com/qwts/managed-machine/internal/provider/brew"
	"golang.org/x/sys/unix"
)

const stage2aT03DirectChildWitnessVerb = "stage2a-t03-child-credential-witness"

// The R-UID child wrapper sends the same metadata record directly to the
// existing A-owned Machine channel before reporting it to HQ. A authenticates
// this connection's kernel UID/PID/start; HQ never sees or controls its peer.
func sendStage2aT03DirectChildWitness(in Stage2aRoleInvocation, expiresAtMS int64,
	q Stage2aT03SiblingCredentialWitnessRequest) error {
	invalid := errors.New("direct sibling child credential witness unavailable")
	if in.ChildExec == nil || in.Start.MachineUID <= 399 ||
		q.Stage2aStopRequest != stage2aT03ChildStopSelectors(in) ||
		!validStage2aT03SiblingWitnessRequest(q) || time.Now().UnixMilli() >= expiresAtMS {
		return invalid
	}
	prefix := brew.DefaultPrefix(runtime.GOOS + "/" + runtime.GOARCH)
	dir := filepath.Join(prefix, "var", "agent-machine")
	path := filepath.Join(dir, "daemon.sock")
	var directory, socket unix.Stat_t
	if prefix == "" || unix.Lstat(dir, &directory) != nil || unix.Lstat(path, &socket) != nil ||
		directory.Mode != unix.S_IFDIR|0755 || directory.Uid != uint32(in.Start.MachineUID) ||
		socket.Mode != unix.S_IFSOCK|0666 || socket.Uid != uint32(in.Start.MachineUID) ||
		checkDarwinACLs([]string{dir, path}) != nil {
		return invalid
	}
	deadline := time.UnixMilli(expiresAtMS)
	if short := time.Now().Add(1500 * time.Millisecond); deadline.After(short) {
		deadline = short
	}
	if !time.Now().Before(deadline) {
		return invalid
	}
	conn, err := net.DialTimeout("unix", path, time.Until(deadline))
	if err != nil {
		return invalid
	}
	defer conn.Close()
	peer, err := ObserveSoulAdmissionPeer(conn.(*net.UnixConn))
	if err != nil || peer.UID != in.Start.MachineUID ||
		unix.Lstat(dir, &socket) != nil || !stage2aSameNode(directory, socket) ||
		conn.SetDeadline(deadline) != nil {
		return invalid
	}
	frame, err := json.Marshal(Stage2aT03DirectChildWitnessRequest{
		Verb: stage2aT03DirectChildWitnessVerb, Stage2aT03SiblingCredentialWitnessRequest: q})
	if err != nil || len(frame) > 8191 {
		return invalid
	}
	if _, err := conn.Write(append(frame, '\n')); err != nil {
		return invalid
	}
	reader := bufio.NewReaderSize(conn, 8192)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > 8192 || reader.Buffered() != 0 {
		return invalid
	}
	if !bytes.Equal(line, []byte("{\"ok\":true}\n")) {
		return invalid
	}
	return nil
}

func stage2aT03ChildStopSelectors(in Stage2aRoleInvocation) Stage2aStopRequest {
	if in.ChildExec == nil {
		return Stage2aStopRequest{}
	}
	return Stage2aStopRequest{
		ReservationSHA256: in.ChildExec.ReservationSHA256,
		InstallationID:    in.Request.InstallationID, StartID: in.Request.StartID,
		LaunchID: in.Start.LaunchID, PlanID: in.Start.PlanID,
		PlanDigest: in.Request.PlanDigest, HQEpoch: in.Request.HQEpoch,
	}
}
