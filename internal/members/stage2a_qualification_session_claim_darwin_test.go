//go:build darwin

package members

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestQualificationQSessionClaimIsDurableAndExact(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(base, "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(claims, &st); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{path: claims, uid: st.Uid, gid: st.Gid,
		device: st.Dev, inode: st.Ino, birthtime: st.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	begin := stage2aQualificationBeginV1{
		InstallationID: "inst_0123456789abcdef", StartID: "st_0123456789abcdef01234567",
	}
	reservation := []byte(`{"signed":"synthetic-only"}`)
	begin.ReservationSHA256 = stage2aQualificationSHA256(reservation)
	dir, err := store.open()
	if err != nil {
		t.Fatal(err)
	}
	slot := soulStartClaimName(begin.InstallationID, begin.StartID)
	if err := commitStage2aReservation(dir, ".stage2a-admin-envelope-"+slot, reservation); err != nil {
		t.Fatal(err)
	}
	if err := claimStage2aQualificationSessionV3(store, begin, reservation); err == nil {
		t.Fatal("Q session claimed without an active start")
	}
	if err := spendStage2aAdminName(dir, stage2aActiveClaimName(begin.InstallationID), store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	if err := claimStage2aQualificationSessionV3(store, begin, []byte(`{"signed":"changed"}`)); err == nil {
		t.Fatal("changed reservation claimed Q session")
	}
	if err := claimStage2aQualificationSessionV3(store, begin, reservation); err != nil {
		t.Fatalf("exact A reservation was refused: %v", err)
	}
	if err := claimStage2aQualificationSessionV3(store, begin, reservation); err == nil {
		t.Fatal("Q session replayed after durable claim")
	}
	reopened, err := store.open()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := stage2aCheckSpentClaim(reopened, ".stage2a-q-session-"+slot, store.uid, store.gid); err != nil {
		t.Fatalf("one-use Q claim was not durable: %v", err)
	}
	begin.SessionID = strings.Repeat("a", 32)
	begin.QUID, begin.QGID = 650, 651
	challenge := "sha256:" + strings.Repeat("b", 64)
	challengeRaw := bytes.Repeat([]byte{0xbb}, 32)
	begin.ChallengeBase64URL = base64.RawURLEncoding.EncodeToString(challengeRaw)
	challenge = stage2aQualificationSHA256(challengeRaw)
	peer := stage2aQualificationPeerV1{
		pid: 42, uid: 650, gid: 651, executable: "/usr/local/bin/node",
		argv:       []string{"/usr/local/bin/node", "/opt/q/qualification-runner.mjs", "--once"},
		socketPath: "/private/tmp/q-session.sock", socketDev: 1, socketInode: 4242,
		socketBirthSeconds: 1795327200,
		kernel: soulKernelProcessSnapshot{PID: 42, ParentPID: 40, StartSeconds: 1795327200,
			RealUID: 650, EffectiveUID: 650, SavedUID: 650,
			RealGID: 651, PrimaryGroupGID: 651, SavedGID: 651},
	}
	if err := bindStage2aQualificationSessionV3(store, begin, challenge, peer, reservation); err != nil {
		t.Fatalf("authenticated Q session was not durably bound: %v", err)
	}
	if err := bindStage2aQualificationSessionV3(store, begin, challenge, peer, reservation); err == nil {
		t.Fatal("a second Q session binding replaced the first")
	}
	result := stage2aQualificationSessionResultV1{begin: begin, challengeSHA256: challenge, peer: peer}
	if err := checkStage2aQualificationSessionBinding(reopened, store, result); err != nil {
		t.Fatalf("exact Q session binding was refused: %v", err)
	}
	result.begin.SessionID = strings.Repeat("c", 32)
	if err := checkStage2aQualificationSessionBinding(reopened, store, result); err == nil {
		t.Fatal("a different Q session inherited the spent claim")
	}
	closed := begin
	closed.StartID = "st_0123456789abcdef01234568"
	closedSlot := soulStartClaimName(closed.InstallationID, closed.StartID)
	if err := commitStage2aReservation(reopened, ".stage2a-admin-envelope-"+closedSlot, reservation); err != nil {
		t.Fatal(err)
	}
	if err := spendStage2aAdminName(reopened, ".stage2a-closed-"+closedSlot, store.uid, store.gid); err != nil {
		t.Fatal(err)
	}
	if err := claimStage2aQualificationSessionV3(store, closed, reservation); err == nil {
		t.Fatal("Q session claimed after the start was closed")
	}
}
