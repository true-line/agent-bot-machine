//go:build darwin

package members

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// SoulAdmissionPeer is the kernel identity of the process that connected to
// one accepted admission socket. It is only one input to a later Machine
// finalization; an inherited or passed connected descriptor can outlive the
// original peer, so this value alone cannot authorize a protected start.
type SoulAdmissionPeer struct {
	PID int
	UID int
}

// ObserveSoulAdmissionPeer reads Darwin's local peer credentials and original
// connecting PID from the accepted descriptor. The caller must keep the
// connection alive, bind a one-use challenge to the spent start, enforce
// launcher-supervised channel custody against descriptor handoff, and compare
// a bracketed live kernel process observation before trusting a Hello.
func ObserveSoulAdmissionPeer(conn *net.UnixConn) (SoulAdmissionPeer, error) {
	if conn == nil {
		return SoulAdmissionPeer{}, errors.New("missing Soul admission connection")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return SoulAdmissionPeer{}, errors.New("Soul admission descriptor unavailable")
	}
	var peer SoulAdmissionPeer
	var observeErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, observeErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if observeErr != nil {
			return
		}
		// Darwin's XUCRED_VERSION is 0. Reject malformed or future credential
		// layouts instead of interpreting them as a current kernel identity.
		if cred == nil || cred.Version != 0 || cred.Ngroups < 0 || int(cred.Ngroups) > len(cred.Groups) {
			observeErr = errors.New("invalid Soul admission peer credential")
			return
		}
		peer.PID, observeErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if observeErr == nil {
			peer.UID = int(cred.Uid)
		}
	}); err != nil || observeErr != nil || peer.PID <= 0 || peer.UID <= 0 {
		return SoulAdmissionPeer{}, errors.New("Soul admission peer identity unavailable")
	}
	return peer, nil
}
