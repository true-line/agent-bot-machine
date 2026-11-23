//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aQualificationDriverSocketName = "qualification-driver.sock"

// A owns this transport inside its existing private Machine state directory.
// Creating a listener conveys no Q permission, observation verdict, or T credit.
type stage2aQualificationDriverListener struct {
	listener    *net.UnixListener
	path        string
	uid, gid    int
	parentDev   int32
	parentInode uint64
	parentBirth unix.Timespec
	dev         int32
	inode       uint64
	birth       unix.Timespec
}

type stage2aQualificationDriverPeer struct {
	pid      int
	kernel   soulKernelProcessSnapshot
	execPath string
	argv     []string
}

func stage2aQualificationDriverPath(home string) string {
	return filepath.Join(home, ".config", "agent-machine", stage2aQualificationDriverSocketName)
}

// The caller must supply A's installed account identity and the exact
// owner-reviewed driver executable/argv. The peer is authenticated at accept.
func newStage2aQualificationDriverListener(adminHome string, adminUID, adminGID int) (*stage2aQualificationDriverListener, error) {
	if os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getuid() != adminUID ||
		os.Getgid() != os.Getegid() || os.Getgid() != adminGID ||
		adminHome == "" || filepath.Clean(adminHome) != adminHome || !filepath.IsAbs(adminHome) {
		return nil, errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(adminUID))
	if err != nil || account.HomeDir != adminHome || account.Gid != strconv.Itoa(adminGID) {
		return nil, errStage2aReservationAuthority
	}
	path := stage2aQualificationDriverPath(adminHome)
	// Darwin's sockaddr_un.sun_path holds 104 bytes including the NUL.
	if len(path) >= 104 {
		return nil, errStage2aReservationAuthority
	}
	parent := filepath.Dir(path)
	dir, err := openStage2aAdminDirectory(parent, uint32(adminUID))
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	defer dir.Close()
	var parentStat unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parentStat) != nil ||
		parentStat.Mode != unix.S_IFDIR|0700 || parentStat.Uid != uint32(adminUID) ||
		parentStat.Gid != uint32(adminGID) {
		return nil, errStage2aReservationAuthority
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, errStage2aReservationAuthority
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errStage2aReservationAuthority
	}
	listener.SetUnlinkOnClose(false)
	closeOnFailure := func() (*stage2aQualificationDriverListener, error) {
		listener.Close()
		// Leave an unverified occupant in place for explicit recovery. Removing
		// by name here could delete a socket swapped in after bind.
		return nil, errStage2aReservationAuthority
	}
	if os.Chmod(path, 0600) != nil {
		return closeOnFailure()
	}
	var socket unix.Stat_t
	if unix.Lstat(path, &socket) != nil || socket.Mode != unix.S_IFSOCK|0600 ||
		socket.Uid != uint32(adminUID) || socket.Gid != uint32(adminGID) ||
		socket.Dev <= 0 || socket.Ino == 0 || socket.Btim.Sec <= 0 ||
		socket.Btim.Nsec < 0 || socket.Btim.Nsec >= 1_000_000_000 ||
		checkDarwinACLs([]string{path}) != nil {
		return closeOnFailure()
	}
	// On Darwin fstat(listener FD) and lstat(socket path) report different
	// inodes. Prove that this pathname reaches this listener before recording
	// the pathname inode. Later accept/close require that exact inode.
	if proveStage2aQualificationDriverListener(listener, path) != nil {
		return closeOnFailure()
	}
	var currentParent, currentSocket unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &currentParent) != nil ||
		currentParent.Dev != parentStat.Dev || currentParent.Ino != parentStat.Ino ||
		currentParent.Btim != parentStat.Btim ||
		unix.Lstat(path, &currentSocket) != nil || currentSocket.Dev != socket.Dev ||
		currentSocket.Ino != socket.Ino || currentSocket.Btim != socket.Btim {
		return closeOnFailure()
	}
	return &stage2aQualificationDriverListener{listener: listener, path: path,
		uid: adminUID, gid: adminGID, parentDev: parentStat.Dev,
		parentInode: parentStat.Ino, parentBirth: parentStat.Btim,
		dev: socket.Dev, inode: socket.Ino, birth: socket.Btim}, nil
}

func proveStage2aQualificationDriverListener(listener *net.UnixListener, path string) error {
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return errStage2aReservationAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialDone := make(chan error, 1)
	go func() {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			dialDone <- err
			return
		}
		defer conn.Close()
		if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err == nil {
			_, err = conn.Write(challenge[:])
		}
		if err == nil {
			var ack [1]byte
			_, err = io.ReadFull(conn, ack[:])
			if err == nil && ack[0] != 0xa5 {
				err = errStage2aReservationAuthority
			}
		}
		dialDone <- err
	}()
	if listener.SetDeadline(time.Now().Add(2*time.Second)) != nil {
		return fmt.Errorf("driver listener probe deadline: %w", errStage2aReservationAuthority)
	}
	conn, err := listener.AcceptUnix()
	if err != nil {
		return fmt.Errorf("driver listener probe accept: %w", err)
	}
	defer conn.Close()
	if conn.SetDeadline(time.Now().Add(2*time.Second)) != nil {
		return fmt.Errorf("driver listener probe connection deadline: %w", errStage2aReservationAuthority)
	}
	peer, err := ObserveSoulAdmissionPeer(conn)
	if err != nil || peer.PID != os.Getpid() || peer.UID != os.Getuid() {
		return fmt.Errorf("driver listener probe peer pid=%d uid=%d err=%v: %w", peer.PID, peer.UID, err, errStage2aReservationAuthority)
	}
	var observed [32]byte
	if _, err := io.ReadFull(conn, observed[:]); err != nil ||
		!bytes.Equal(observed[:], challenge[:]) {
		return fmt.Errorf("driver listener probe challenge err=%v: %w", err, errStage2aReservationAuthority)
	}
	if _, err := conn.Write([]byte{0xa5}); err != nil {
		return fmt.Errorf("driver listener probe acknowledgement: %w", err)
	}
	if err := <-dialDone; err != nil || ctx.Err() != nil {
		return fmt.Errorf("driver listener probe dial err=%v context=%v: %w", err, ctx.Err(), errStage2aReservationAuthority)
	}
	return nil
}

func (l *stage2aQualificationDriverListener) parentMatches() bool {
	dir, err := openStage2aAdminDirectory(filepath.Dir(l.path), uint32(l.uid))
	if err != nil {
		return false
	}
	defer dir.Close()
	var current unix.Stat_t
	return unix.Fstat(int(dir.Fd()), &current) == nil &&
		current.Mode == unix.S_IFDIR|0700 && current.Uid == uint32(l.uid) &&
		current.Gid == uint32(l.gid) && current.Dev == l.parentDev &&
		current.Ino == l.parentInode && current.Btim == l.parentBirth
}

func (l *stage2aQualificationDriverListener) close() {
	if l == nil || l.listener == nil {
		return
	}
	l.listener.Close()
	var socket unix.Stat_t
	if l.parentMatches() && unix.Lstat(l.path, &socket) == nil && socket.Dev == l.dev &&
		socket.Ino == l.inode && socket.Btim == l.birth {
		_ = os.Remove(l.path)
	}
	l.listener = nil
}

// The caller must still compare the driver's code and signed review before
// interpreting any message. A self-reported PID or verdict is never trusted.
func (l *stage2aQualificationDriverListener) accept(ctx context.Context, execPath string, argv []string) (*net.UnixConn, stage2aQualificationDriverPeer, error) {
	var refused stage2aQualificationDriverPeer
	if l == nil || l.listener == nil || ctx == nil || ctx.Err() != nil ||
		validateSoulExpectedArguments(execPath, argv) != nil || argv[0] != execPath {
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
	if err != nil || ctx.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		l.close()
		return nil, refused, errStage2aReservationAuthority
	}
	var socket unix.Stat_t
	if !l.parentMatches() || unix.Lstat(l.path, &socket) != nil || socket.Mode != unix.S_IFSOCK|0600 ||
		socket.Uid != uint32(l.uid) || socket.Gid != uint32(l.gid) ||
		socket.Dev != l.dev || socket.Ino != l.inode || socket.Btim != l.birth ||
		checkDarwinACLs([]string{l.path}) != nil {
		conn.Close()
		l.close()
		return nil, refused, errStage2aReservationAuthority
	}
	l.close()
	identity, err := ObserveSoulAdmissionPeer(conn)
	if err != nil || identity.PID <= 1 || identity.UID != l.uid {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(identity.PID, execPath, argv)
	if err != nil || !stage2aQualificationKernelMatches(observed.Kernel, identity.PID, l.uid, l.gid) {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	if conn.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		conn.Close()
		return nil, refused, errStage2aReservationAuthority
	}
	return conn, stage2aQualificationDriverPeer{pid: identity.PID, kernel: observed.Kernel,
		execPath: execPath, argv: append([]string(nil), argv...)}, nil
}

func (p stage2aQualificationDriverPeer) recheck() error {
	observed, err := observeSoulProcess(p.pid, p.execPath, p.argv)
	if err != nil || !sameSoulKernelProcess(p.kernel, observed.Kernel) {
		return errStage2aReservationAuthority
	}
	return nil
}
