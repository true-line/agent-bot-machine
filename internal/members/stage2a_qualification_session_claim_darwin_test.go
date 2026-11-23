//go:build darwin

package members

import (
	"os"
	"path/filepath"
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
