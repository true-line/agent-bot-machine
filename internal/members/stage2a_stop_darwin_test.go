//go:build darwin

package members

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStage2aRetiredActiveClaimSurvivesRetry(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	q := Stage2aStopRequest{InstallationID: "soul-one", StartID: "st_0123456789abcdef01234567"}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	active := stage2aActiveClaimName(q.InstallationID)
	closed := ".stage2a-closed-" + soulStartClaimName(q.InstallationID, q.StartID)
	if err := spendStage2aAdminName(dir, active, uid, gid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := stage2aRetireActiveClaim(dir, q, uid, gid); err != nil {
			t.Fatalf("retirement attempt %d: %v", i+1, err)
		}
	}
	if err := requireUnspentStage2aReservation(dir, active); err != nil {
		t.Fatalf("active claim remained after retirement: %v", err)
	}
	if err := stage2aCheckSpentClaim(dir, closed, uid, gid); err != nil {
		t.Fatalf("closed claim was not durably recognizable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir.Name(), active), []byte("replay"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage2aRetireActiveClaim(dir, q, uid, gid); err == nil {
		t.Fatal("retirement accepted simultaneous active and closed claims")
	}
}

func TestStage2aStopEnvelopePublishesCompleteBytes(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	name := ".stage2a-stop-" + strings.Repeat("a", 16) + ".json"
	body := []byte(`{"signed":"complete"}`)
	if err := stage2aStoreStopEnvelope(dir, name, uint32(os.Getuid()), uint32(os.Getgid()), body); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir.Name(), name))
	if err != nil || string(got) != string(body) {
		t.Fatalf("published stop record: %q, %v", got, err)
	}
	if err := stage2aStoreStopEnvelope(dir, name, uint32(os.Getuid()), uint32(os.Getgid()), body); err == nil {
		t.Fatal("stop record was overwritten")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode != unix.S_IFREG|0600 {
		t.Fatalf("stop record mode: %#o, %v", st.Mode, err)
	}
}
