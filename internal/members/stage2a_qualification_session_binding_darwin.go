//go:build darwin

package members

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

const stage2aQualificationSessionBindingSchemaV1 = "agent-bot-machine/stage2a-q-session-binding/v1"

// The claim is spent before Q starts. Only after A authenticates Q's Ready
// may it bind that one claim to the actual Q session and kernel/socket peer.
// This A-owned record is local replay authority, not a driver receipt or verdict.
type stage2aQualificationSessionBindingV1 struct {
	Schema            string   `json:"schema"`
	InstallationID    string   `json:"installation_id"`
	StartID           string   `json:"start_id"`
	ReservationSHA256 string   `json:"reservation_sha256"`
	SessionID         string   `json:"session_id"`
	ChallengeSHA256   string   `json:"challenge_sha256"`
	QPID              int      `json:"q_pid"`
	QUID              int      `json:"q_uid"`
	QGID              int      `json:"q_gid"`
	QParentPID        int      `json:"q_parent_pid"`
	QStartSeconds     int64    `json:"q_start_seconds"`
	QStartMicros      int32    `json:"q_start_micros"`
	QSocketPath       string   `json:"q_socket_path"`
	QSocketDevice     uint64   `json:"q_socket_device"`
	QSocketInode      uint64   `json:"q_socket_inode"`
	QSocketBirthSec   int64    `json:"q_socket_birth_seconds"`
	QSocketBirthNsec  int64    `json:"q_socket_birth_nanos"`
	QExecutable       string   `json:"q_executable"`
	QArgv             []string `json:"q_argv"`
}

func stage2aQualificationSessionBindingBytes(begin stage2aQualificationBeginV1,
	challengeSHA string, peer stage2aQualificationPeerV1) ([]byte, error) {
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(begin.ChallengeBase64URL)
	if !soulInstallationID.MatchString(begin.InstallationID) ||
		!soulStartID.MatchString(begin.StartID) || len(begin.SessionID) != 32 ||
		!stage2aQualificationHex(begin.SessionID) ||
		!stage2aQualificationDigest(begin.ReservationSHA256) ||
		!stage2aQualificationDigest(challengeSHA) || err != nil || len(challenge) != 32 ||
		stage2aQualificationSHA256(challenge) != challengeSHA ||
		begin.QUID != peer.uid || begin.QGID != peer.gid ||
		begin.RequireArgvProof != peer.reviewedArgvProof ||
		!stage2aQualificationKernelMatches(peer.kernel, peer.pid, peer.uid, peer.gid) ||
		peer.kernel.StartMicros < 0 || peer.kernel.StartMicros >= 1_000_000 ||
		peer.socketPath == "" || !stage2aAbsolutePath(peer.socketPath) ||
		filepath.Clean(peer.socketPath) != peer.socketPath ||
		peer.socketDev == 0 || peer.socketInode == 0 || peer.socketBirthSeconds <= 0 ||
		peer.socketBirthNanos < 0 || peer.socketBirthNanos >= 1_000_000_000 ||
		peer.executable == "" || len(peer.argv) < 3 || peer.argv[0] != peer.executable ||
		validateSoulExpectedArguments(peer.executable, peer.argv) != nil {
		return nil, errStage2aReservationAuthority
	}
	return marshalStage2aReservationJCS(stage2aQualificationSessionBindingV1{
		Schema:         stage2aQualificationSessionBindingSchemaV1,
		InstallationID: begin.InstallationID, StartID: begin.StartID,
		ReservationSHA256: begin.ReservationSHA256, SessionID: begin.SessionID,
		ChallengeSHA256: challengeSHA, QPID: peer.pid, QUID: peer.uid, QGID: peer.gid,
		QParentPID: peer.kernel.ParentPID, QStartSeconds: peer.kernel.StartSeconds,
		QStartMicros: peer.kernel.StartMicros, QSocketPath: peer.socketPath,
		QSocketDevice: peer.socketDev, QSocketInode: peer.socketInode,
		QSocketBirthSec: peer.socketBirthSeconds, QSocketBirthNsec: peer.socketBirthNanos,
		QExecutable: peer.executable, QArgv: append([]string(nil), peer.argv...),
	})
}

func bindStage2aQualificationSessionV3(store stage2aAdminClaimStore,
	begin stage2aQualificationBeginV1, challengeSHA string,
	peer stage2aQualificationPeerV1, reservation []byte) error {
	if begin.ReservationSHA256 != stage2aQualificationSHA256(reservation) ||
		len(reservation) == 0 || len(reservation) > 64<<10 {
		return errStage2aReservationAuthority
	}
	record, err := stage2aQualificationSessionBindingBytes(begin, challengeSHA, peer)
	if err != nil || len(record) > 8192 {
		return errStage2aReservationAuthority
	}
	dir, err := store.open()
	if err != nil {
		return errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, begin.InstallationID)
	if err != nil {
		return errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(begin.InstallationID, begin.StartID)
	if store.checkDirectory(dir) != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(begin.InstallationID), store.uid, store.gid) != nil ||
		requireUnspentStage2aReservation(dir, ".stage2a-closed-"+slot) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, store.uid, store.gid) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-admin-envelope-"+slot,
			store.uid, store.gid, reservation, 64<<10) != nil {
		return errStage2aReservationAuthority
	}
	return commitStage2aReservation(dir, ".stage2a-q-binding-"+slot+".json", record)
}

func checkStage2aQualificationSessionBinding(dir *os.File, store stage2aAdminClaimStore,
	session stage2aQualificationSessionResultV1) error {
	slot := soulStartClaimName(session.begin.InstallationID, session.begin.StartID)
	record, err := stage2aQualificationSessionBindingBytes(session.begin, session.challengeSHA256, session.peer)
	if err != nil || len(record) > 8192 ||
		stage2aCheckSpentClaim(dir, ".stage2a-q-session-"+slot, store.uid, store.gid) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-q-binding-"+slot+".json",
			store.uid, store.gid, record, 8192) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}
