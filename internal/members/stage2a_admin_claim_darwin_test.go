package members

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStage2aAdminSpendPrecedesSignerAndFencesReplay(t *testing.T) {
	req, _, _, _ := stage2aReservationFixture()
	dir, gid := stage2aReservationTestDir(t)
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	store := stage2aAdminClaimStore{uid: st.Uid, gid: gid, device: st.Dev, inode: st.Ino, birthtime: st.Btim}
	store.legacyUnspent = func(string, string) error { return errStage2aReservationSpent }
	signCalls := 0
	failedSigner := errors.New("signer not available")
	sign := func(*os.File) error {
		signCalls++
		name := soulStartClaimName(req.start.InstallationID, req.start.StartID)
		if raw, err := os.ReadFile(filepath.Join(dir.Name(), name)); err != nil || string(raw) != "stage2a-admin-spent/v1\n" {
			t.Fatalf("missing spend before signing: %q, %v", raw, err)
		}
		return failedSigner
	}
	auth := func() error { return nil }
	if err := stage2aAdminSpendIn(store, dir, req, auth, sign); !errors.Is(err, errStage2aReservationSpent) || signCalls != 0 {
		t.Fatalf("legacy spend reopened: %v, %d", err, signCalls)
	}
	store.legacyUnspent = func(string, string) error { return nil }
	wrong := store
	wrong.inode++
	if err := stage2aAdminSpendIn(wrong, dir, req, auth, sign); err == nil || signCalls != 0 {
		t.Fatal("wrong claims directory reached signer")
	}
	if err := stage2aAdminSpendIn(store, dir, req, auth, sign); !errors.Is(err, failedSigner) || signCalls != 1 {
		t.Fatalf("signer failure did not propagate: %v, %d", err, signCalls)
	}
	if err := stage2aAdminSpendIn(store, dir, req, auth, sign); !errors.Is(err, errStage2aReservationSpent) || signCalls != 1 {
		t.Fatalf("signer failure unspent the start: %v, %d", err, signCalls)
	}
}

func TestStage2aAdminBindingRejectsSelfClaimedOwner(t *testing.T) {
	req, in, _, at := stage2aReservationFixture()
	in.binding.Contract, in.binding.SchemaVersion = "machine/v2", 2
	pinned := uint32(in.machineUID)
	group := uint32(in.runner.GID)
	in.binding.Snapshots.Definition.OwnerUID = pinned
	in.binding.Snapshots.LaunchInputs.OwnerUID = pinned
	if _, err := prepareStage2aReservationForOwner(req, in, at, pinned, group); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareStage2aReservation(req, in, at); err == nil {
		t.Fatal("an admin record passed the v1 gate")
	}
	in.machineUID++
	in.binding.Snapshots.Definition.OwnerUID++
	in.binding.Snapshots.LaunchInputs.OwnerUID++
	if _, err := prepareStage2aReservationForOwner(req, in, at, pinned, group); err == nil {
		t.Fatal("internally consistent rewritten owner overrode installed A")
	}
}

func TestStage2aAdminSnapshotsWithPinnedNamespaceAndOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Machine admin producer requires nonroot")
	}
	source, approved := stage2aObservedFixture(t)
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0750); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(parent, &st); err != nil {
		t.Fatal(err)
	}
	a := stage2aAdminSnapshots{
		uid: st.Uid, runnerReadGID: st.Gid, namespace: parent,
		namespaceDev: st.Dev, namespaceInode: st.Ino, namespaceBirth: st.Btim,
		verifyInstalledGroup: func() error { return nil },
	}
	const name = "snap_111111111111111111111111"
	t.Cleanup(func() { stage2aCleanPrivateStage(filepath.Join(parent, name)) })
	id, published, err := publishStage2aAdminSnapshot(a, source, st.Uid, st.Gid, name, approved)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := observeStage2aAdminSnapshot(a, name, id, approved); err != nil || digest != published {
		t.Fatalf("pinned admin snapshot failed: %q %v", digest, err)
	}
	selfClaim := id
	selfClaim.OwnerUID++
	if _, err := observeStage2aAdminSnapshot(a, name, selfClaim, approved); err == nil {
		t.Fatal("self-claimed admin UID passed")
	}
	wrong := a
	wrong.namespaceInode++
	if _, err := observeStage2aAdminSnapshot(wrong, name, id, approved); err == nil {
		t.Fatal("a replacement namespace passed")
	}
	wrong = a
	wrong.verifyInstalledGroup = func() error { return errors.New("unexpected group member") }
	if _, err := observeStage2aAdminSnapshot(wrong, name, id, approved); err == nil {
		t.Fatal("live group membership failure passed")
	}
}

func TestStage2aAdminProducerPersistsEnvelopeAndRejectsReplay(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Machine admin producer requires nonroot")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	namespace, claims := filepath.Join(base, "snapshots"), filepath.Join(base, "claims")
	if err := os.Mkdir(namespace, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	var ns, cs unix.Stat_t
	if err := unix.Stat(namespace, &ns); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(claims, &cs); err != nil {
		t.Fatal(err)
	}
	a := stage2aAdminSnapshots{uid: ns.Uid, runnerReadGID: ns.Gid, namespace: namespace,
		namespaceDev: ns.Dev, namespaceInode: ns.Ino, namespaceBirth: ns.Btim,
		verifyInstalledGroup: func() error { return nil }}
	store := stage2aAdminClaimStore{path: claims, uid: cs.Uid, gid: cs.Gid, inode: cs.Ino,
		device: cs.Dev, birthtime: cs.Btim, legacyUnspent: func(string, string) error { return nil }}
	req, in, key, _ := stage2aReservationFixture()
	in.machineUID = int(cs.Uid)
	in.expires = time.Now().Add(20 * time.Second)
	in.binding.Contract, in.binding.SchemaVersion = "machine/v2", 2
	source, inventory := stage2aObservedFixture(t)
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	for i, identity := range []*Stage2aSnapshotIdentity{&in.binding.Snapshots.Definition, &in.binding.Snapshots.LaunchInputs} {
		name := []string{"snap_111111111111111111111111", "snap_222222222222222222222222"}[i]
		t.Cleanup(func() { stage2aCleanPrivateStage(filepath.Join(namespace, name)) })
		observed, _, err := publishStage2aAdminSnapshot(a, source, cs.Uid, ns.Gid, name, inventory)
		if err != nil {
			t.Fatal(err)
		}
		*identity = observed
	}
	// As in the v1 fixture, this seam represents fixture measurements from
	// the installed authority loader. TestStage2aAdminSnapshots exercises
	// local publication and observation against actual descriptors.
	auth := stage2aReservationFixtureAuthority(req, in, key)
	got, err := reserveStage2aAdminStart(store, a, req, auth)
	if err != nil {
		t.Fatal(err)
	}
	name := ".stage2a-admin-envelope-" + soulStartClaimName(req.start.InstallationID, req.start.StartID)
	stored, err := os.ReadFile(filepath.Join(claims, name))
	if err != nil || !bytes.Equal(stored, got.envelope) || got.sha256 != stage2aReservationSHA256(stored) {
		t.Fatalf("returned and persisted admin envelope differ: %v", err)
	}
	if _, err := reserveStage2aAdminStart(store, a, req, auth); !errors.Is(err, errStage2aReservationSpent) {
		t.Fatalf("admin producer replay returned %v", err)
	}
}
