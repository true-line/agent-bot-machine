//go:build darwin

package members

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// This listener is a one-use transport for raw qualification observations.
// Its parent must have been installed by root as A:Q-group mode 02710; the
// setgid bit gives A-created sockets the Q group without adding A to Q.
// The owner-reviewed plan must pin that exact parent and Q numeric identity.
type stage2aQualificationListenerV1 struct {
	listener           *net.UnixListener
	path               string
	qGID               int
	socketDev          uint64
	socketInode        uint64
	socketBirthSeconds int64
	socketBirthNanos   int64
}

func newStage2aQualificationListenerV1(parent string, qGID int) (*stage2aQualificationListenerV1, error) {
	if os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || qGID <= 0 || qGID == os.Getgid() ||
		parent != stage2aQualificationQSocket {
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
	path := stage2aQualificationQSessionPath
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, errStage2aReservationAuthority
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	listener.SetUnlinkOnClose(false)
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
		socketStat.Dev <= 0 || socketStat.Ino == 0 || socketStat.Btim.Sec <= 0 ||
		socketStat.Btim.Nsec < 0 || socketStat.Btim.Nsec >= 1_000_000_000 ||
		checkDarwinACLs([]string{path}) != nil {
		return closeOnFailure()
	}
	return &stage2aQualificationListenerV1{listener: listener, path: path, qGID: qGID,
		socketDev: uint64(socketStat.Dev), socketInode: socketStat.Ino,
		socketBirthSeconds: socketStat.Btim.Sec, socketBirthNanos: socketStat.Btim.Nsec}, nil
}

func (l *stage2aQualificationListenerV1) close() {
	if l != nil && l.listener != nil {
		l.listener.Close()
		var stat unix.Stat_t
		if unix.Lstat(l.path, &stat) == nil && uint64(stat.Dev) == l.socketDev &&
			stat.Ino == l.socketInode && stat.Btim.Sec == l.socketBirthSeconds &&
			stat.Btim.Nsec == l.socketBirthNanos {
			os.Remove(l.path)
		}
		l.listener = nil
	}
}

// accept consumes the listener before challenge disclosure. The connecting
// kernel PID/UID and live primary GID must match A's exact pinned child.
// Extra queued connections are closed with the listener and never read.
func (l *stage2aQualificationListenerV1) accept(ctx context.Context, pid, uid, gid int,
	executable string, argv []string, reviewedArgvProof bool) (*net.UnixConn, stage2aQualificationPeerV1, error) {
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
	var socketStat unix.Stat_t
	if err == nil && (unix.Lstat(l.path, &socketStat) != nil ||
		socketStat.Mode != unix.S_IFSOCK|0660 || socketStat.Uid != uint32(os.Getuid()) ||
		socketStat.Gid != uint32(l.qGID) || uint64(socketStat.Dev) != l.socketDev ||
		socketStat.Ino != l.socketInode || socketStat.Btim.Sec != l.socketBirthSeconds ||
		socketStat.Btim.Nsec != l.socketBirthNanos || checkDarwinACLs([]string{l.path}) != nil) {
		conn.Close()
		l.close()
		return nil, refused, errStage2aReservationAuthority
	}
	l.close()
	if err != nil {
		return nil, refused, errStage2aReservationAuthority
	}
	peer, err := authenticateStage2aQualificationPeerV1(conn, pid, uid, gid, executable, argv, reviewedArgvProof)
	if err != nil {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	peer.socketPath = l.path
	peer.socketDev = l.socketDev
	peer.socketInode = l.socketInode
	peer.socketBirthSeconds = l.socketBirthSeconds
	peer.socketBirthNanos = l.socketBirthNanos
	if conn.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	return conn, peer, nil
}
