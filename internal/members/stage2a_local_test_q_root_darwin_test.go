//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage2aLocalTestQRootSpendRefusals(t *testing.T) {
	q, approval, key, ownerSHA, qDigest, now := stage2aLocalTestQApprovalFixture(t)
	public := key.Public().(ed25519.PublicKey)
	payload, _, err := stage2aLocalTestQApprovalForReview(q, approval,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, public, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestQApprovalPurpose, payload)
	ref := payload.ApprovalReference
	if path, err := stage2aLocalTestQRootEnvelopePath(ref); err != nil ||
		path != filepath.Join(stage2aLocalTestQRootDir, ref.PlanID+".stage2a-local-test-q-approval.json") {
		t.Fatal("root Q envelope path is not fixed by the reviewed reference")
	}
	record, raw, err := stage2aLocalTestQRootSpendRecord(envelope, public, q, ref,
		ownerSHA, approval.MachineFingerprint, approval.PairCommitment, q.HostUUID, now)
	if err != nil || record.QPlanSHA256 != qDigest || len(raw) == 0 {
		t.Fatalf("matching root Q spend refused: %v", err)
	}
	badRef := ref
	badRef.PairCommitment = strings.Repeat("b", 64)
	if _, err := stage2aLocalTestQRootEnvelopePath(badRef); err != nil {
		// The path format accepts a syntactically valid pair; semantic equality
		// is checked against the signed payload at the spend boundary.
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		envelope []byte
		ref      stage2aLocalTestQApprovalReference
		host     string
		at       time.Time
	}{
		{"forged correct digest", stage2aLocalTestSignedForTest(t,
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize)),
			stage2aLocalTestQApprovalPurpose, payload), ref, q.HostUUID, now},
		{"wrong host", envelope, ref, "FFFFFFFF-BBBB-4CCC-8DDD-EEEEEEEEEEEE", now},
		{"wrong pair", envelope, badRef, q.HostUUID, now},
		{"expired", envelope, ref, q.HostUUID, now.Add(10 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := stage2aLocalTestQRootSpendRecord(tc.envelope, public, q, tc.ref,
				ownerSHA, approval.MachineFingerprint, approval.PairCommitment,
				tc.host, tc.at); err == nil {
				t.Fatal("forged, wrong-host, wrong-pair or stale root Q approval accepted")
			}
		})
	}
	// The root loader uses this exclusive full-sync primitive under its
	// verified receipt directory. Reopening it simulates daemon restart.
	claims := filepath.Join(t.TempDir(), "claims")
	if err := os.Mkdir(claims, 0700); err != nil {
		t.Fatal(err)
	}
	name := ".stage2a-local-test-q-spent-" + ref.PlanID + ".json"
	first, err := os.Open(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitStage2aReservation(first, name, raw); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := os.Open(claims)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := commitStage2aReservation(second, name, raw); err == nil {
		t.Fatal("restarted root install reused spent Q approval")
	}
}
