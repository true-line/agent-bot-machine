//go:build darwin

package members

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func cooperativeClaimFixture(t *testing.T) (stage2aAdminClaimStore, *os.File, SoulCooperativeReserveRequest) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{path: path, uid: st.Uid, gid: st.Gid,
		device: st.Dev, inode: st.Ino, birthtime: st.Btim,
		legacyUnspent: func(string, string) error { return nil }}
	if err := store.checkDirectory(dir); err != nil {
		t.Fatalf("test claim directory mode=%o uid=%d gid=%d: %v", st.Mode, st.Uid, st.Gid, err)
	}
	q := SoulCooperativeReserveRequest{Profile: "managed-cooperative", HostID: "test-host",
		PlanDigest: strings.Repeat("1", 64), InstallationID: "installation-1",
		StartID: "st_1234567890abcdef12345678", HQEpoch: strings.Repeat("a", 64),
		PackagePath: "/var/agent-bot-hq/candidates/hello.soul"}
	return store, dir, q
}

func TestSoulCooperativeDurableClaimAndContainmentFence(t *testing.T) {
	store, dir, q := cooperativeClaimFixture(t)
	if err := spendSoulCooperativeStartIn(store, dir, q); err != nil {
		t.Fatalf("spend first start: %v", err)
	}
	if err := spendSoulCooperativeStartIn(store, dir, q); err == nil {
		t.Fatal("replayed start accepted")
	}
	other := q
	other.StartID = "st_aaaaaaaaaaaaaaaaaaaaaaaa"
	if err := spendSoulCooperativeStartIn(store, dir, other); err == nil {
		t.Fatal("second active start accepted for same installation")
	}
	if err := releaseSoulCooperativeStartIn(store, dir, other, func() (bool, error) { return true, nil }); err == nil {
		t.Fatal("wrong start released active installation")
	}
	if err := releaseSoulCooperativeStartIn(store, dir, q, func() (bool, error) { return false, nil }); err == nil {
		t.Fatal("uncontained runner released active installation")
	}
	if err := releaseSoulCooperativeStartIn(store, dir, q, func() (bool, error) { return false, errors.New("kernel unknown") }); err == nil {
		t.Fatal("uncertain kernel state released active installation")
	}
	if err := releaseSoulCooperativeStartIn(store, dir, q, func() (bool, error) { return true, nil }); err != nil {
		t.Fatalf("release contained start: %v", err)
	}
	if err := spendSoulCooperativeStartIn(store, dir, q); err == nil {
		t.Fatal("spent start was reused after containment")
	}
	if err := spendSoulCooperativeStartIn(store, dir, other); err != nil {
		t.Fatalf("fresh start after containment: %v", err)
	}
}

func TestSoulCooperativeClaimChecksHistoricalFenceBeforeSpend(t *testing.T) {
	store, dir, q := cooperativeClaimFixture(t)
	store.legacyUnspent = func(string, string) error { return errors.New("protected start already spent") }
	if err := spendSoulCooperativeStartIn(store, dir, q); err == nil {
		t.Fatal("historical cross-profile replay accepted")
	}
	store.legacyUnspent = func(string, string) error { return nil }
	if err := spendSoulCooperativeStartIn(store, dir, q); err != nil {
		t.Fatalf("historical check did not leave claim unspent: %v", err)
	}
}
