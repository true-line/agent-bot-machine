//go:build darwin

package members

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// This listener is a one-use transport for raw qualification observations.
// Its parent must have been installed by root as A:Q-group mode 02710; the
// setgid bit gives A-created sockets the Q group without adding A to Q.
// The owner-reviewed plan must pin that exact parent and Q numeric identity.
type stage2aQualificationListenerV1 struct {
	listener *net.UnixListener
	path     string
	qGID     int
}

func newStage2aQualificationListenerV1(parent string, qGID int) (*stage2aQualificationListenerV1, error) {
	if os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || qGID <= 0 || qGID == os.Getgid() ||
		!stage2aAbsolutePath(parent) {
		return nil, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(parent, uint32(os.Getuid()))
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer dir.Close()
	var parentStat unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parentStat) != nil ||
		parentStat.Mode != unix.S_IFDIR|unix.S_ISGID|0710 ||
		parentStat.Uid != uint32(os.Getuid()) || parentStat.Gid != uint32(qGID) {
		return nil, errStage2aReservationAuthority
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errStage2aReservationAuthority
	}
	path := filepath.Join(parent, "q-"+hex.EncodeToString(nonce[:])+".sock")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, errStage2aReservationAuthority
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	closeOnFailure := func() (*stage2aQualificationListenerV1, error) {
		listener.Close()
		os.Remove(path)
		return nil, errStage2aReservationAuthority
	}
	if os.Chmod(path, 0660) != nil {
		return closeOnFailure()
	}
	var socketStat unix.Stat_t
	if unix.Lstat(path, &socketStat) != nil || socketStat.Mode != unix.S_IFSOCK|0660 ||
		socketStat.Uid != uint32(os.Getuid()) || socketStat.Gid != uint32(qGID) ||
		checkDarwinACLs([]string{path}) != nil {
		return closeOnFailure()
	}
	return &stage2aQualificationListenerV1{listener: listener, path: path, qGID: qGID}, nil
}

func (l *stage2aQualificationListenerV1) close() {
	if l != nil && l.listener != nil {
		l.listener.Close()
		os.Remove(l.path)
		l.listener = nil
	}
}

// accept consumes the listener before challenge disclosure. The connecting
// kernel PID/UID and live primary GID must match A's exact pinned child.
// Extra queued connections are closed with the listener and never read.
func (l *stage2aQualificationListenerV1) accept(ctx context.Context, pid, uid, gid int,
	executable string, argv []string) (*net.UnixConn, stage2aQualificationPeerV1, error) {
	var refused stage2aQualificationPeerV1
	if l == nil || l.listener == nil || ctx == nil || gid != l.qGID {
		return nil, refused, errStage2aReservationAuthority
	}
	deadline := time.Now().Add(10 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	if l.listener.SetDeadline(deadline) != nil {
		l.close()
		return nil, refused, errStage2aReservationAuthority
	}
	conn, err := l.listener.AcceptUnix()
	l.close()
	if err != nil {
		return nil, refused, errStage2aReservationAuthority
	}
	peer, err := authenticateStage2aQualificationPeerV1(conn, pid, uid, gid, executable, argv)
	if err != nil {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	if conn.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	return conn, peer, nil
}
