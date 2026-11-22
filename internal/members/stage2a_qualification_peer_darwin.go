//go:build darwin

package members

import (
	"net"
	"os"
)

// stage2aQualificationPeerV1 binds an accepted one-use Unix connection to
// A's already spawned, owner-plan-pinned independent qualification process.
// The caller must create and retire the A-owned one-use listener, verify the
// pinned executable/code bytes and keep the child under supervision. Kernel
// peer identity alone never authenticates the observations or grants T credit.
type stage2aQualificationPeerV1 struct {
	pid, uid, gid      int
	executable         string
	argv               []string
	socketPath         string
	socketDev          uint64
	socketInode        uint64
	socketBirthSeconds int64
	socketBirthNanos   int64
	kernel             soulKernelProcessSnapshot
}

func authenticateStage2aQualificationPeerV1(conn *net.UnixConn, pid, uid, gid int,
	executable string, argv []string) (stage2aQualificationPeerV1, error) {
	var refused stage2aQualificationPeerV1
	if conn == nil || pid <= 1 || uid <= 399 || gid <= 0 || uid == os.Getuid() ||
		uid == 0 || len(argv) < 3 || argv[0] != executable ||
		validateSoulExpectedArguments(executable, argv) != nil {
		return refused, errStage2aReservationAuthority
	}
	peer, err := ObserveSoulAdmissionPeer(conn)
	if err != nil || peer.PID != pid || peer.UID != uid {
		return refused, errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(pid, executable, argv)
	if err != nil || !stage2aQualificationKernelMatches(observed.Kernel, pid, uid, gid) {
		return refused, errStage2aReservationAuthority
	}
	return stage2aQualificationPeerV1{pid: pid, uid: uid, gid: gid,
		executable: executable, argv: append([]string(nil), argv...), kernel: observed.Kernel}, nil
}

func stage2aQualificationKernelMatches(k soulKernelProcessSnapshot, pid, uid, gid int) bool {
	return k.PID == pid && k.ParentPID > 0 && k.StartSeconds > 0 &&
		k.RealUID == uint32(uid) && k.EffectiveUID == uint32(uid) && k.SavedUID == uint32(uid) &&
		k.RealGID == uint32(gid) && k.PrimaryGroupGID == uint32(gid) && k.SavedGID == uint32(gid)
}

// recheck brackets each frame with live process identity to detect child exit,
// credential changes and PID reuse. The A caller must also verify the current
// installed plan and exact Q executable/code measurements before signing.
func (p stage2aQualificationPeerV1) recheck() error {
	observed, err := observeSoulProcess(p.pid, p.executable, p.argv)
	if err != nil || !stage2aQualificationKernelMatches(observed.Kernel, p.pid, p.uid, p.gid) ||
		!sameSoulKernelProcess(p.kernel, observed.Kernel) {
		return errStage2aReservationAuthority
	}
	return nil
}
