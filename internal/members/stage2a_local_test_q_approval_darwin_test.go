//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aLocalTestQDriverFixture = `{"contracts_source":{"commit":"` + stage2aLocalTestContractsCommit + `","digest":"` + stage2aLocalTestContractsDigest + `","digest_algorithm":"sha256-manifest-v1","files":658,"paths":["errors","fixtures","schemas"],"repository":"https://github.com/true-line/soul-contracts.git","tag":"v0.10.3"},"driver":{"kind":"fixture"},"schema":"agent-bot-machine/stage2a-observed-body-local-test-driver-plan/v1"}`

func stage2aLocalTestQApprovalFixture(t *testing.T) (stage2aLocalTestQPlan, Approval,
	ed25519.PrivateKey, string, string, time.Time) {
	t.Helper()
	owner, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	ownerRaw, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	_, ownerSHA, err := parseStage2aLocalTestOwnerPlan(ownerRaw, fixture, approvedUntil)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	q := stage2aLocalTestQPlan{
		Schema: stage2aLocalTestQSchema, Purpose: stage2aLocalTestQPurpose,
		HostUUID:       "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
		InstallationID: "inst.fixture", InstalledPlanID: "plan-20261124T120000Z-abcd",
		InstalledPlanDigest: strings.Repeat("3", 64), OwnerPlanSHA256: ownerSHA,
		SourceRevision: owner.Revision, CandidateManifestSHA256: owner.Members[0].AdapterManifestSHA256,
		DriverPlanSHA256: stage2aReservationSHA256([]byte(stage2aLocalTestQDriverFixture)),
		AKeyID:           stage2aReservationSHA256(key.Public().(ed25519.PublicKey)), ExpiresAt: owner.ExpiresAt,
	}
	qRaw, err := marshalStage2aReservationJCS(q)
	if err != nil {
		t.Fatal(err)
	}
	_, qDigest, err := parseStage2aLocalTestQPlan(qRaw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 12, 0, 30, 0, time.UTC)
	a := Approval{Purpose: stage2aLocalTestQPurpose,
		PlanID: "plan-20261124T120001Z-abcd", PlanDigest: strings.TrimPrefix(qDigest, "sha256:"),
		MachineFingerprint: strings.Repeat("f", 64), PairCommitment: strings.Repeat("a", 64),
		ApprovedAt: now.Add(-time.Minute).Format(approvalTime),
		ExpiresAt:  now.Add(9 * time.Minute).Format(approvalTime),
	}
	return q, a, key, ownerSHA, qDigest, now
}

func TestStage2aLocalTestQApprovalSignedProvenance(t *testing.T) {
	q, approval, key, ownerSHA, qDigest, now := stage2aLocalTestQApprovalFixture(t)
	public := key.Public().(ed25519.PublicKey)
	payload, raw, err := stage2aLocalTestQApprovalForReview(q, approval,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, public, now)
	if err != nil || payload.PlanSHA256 != qDigest {
		t.Fatalf("reviewed Q approval refused: %v", err)
	}
	if _, err := parseStage2aLocalTestQApprovalPayload(raw); err != nil {
		t.Fatal(err)
	}
	envelope := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestQApprovalPurpose, payload)
	if _, err := verifyStage2aLocalTestQApprovalEnvelope(envelope, public, q,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Approval, *stage2aLocalTestQPlan, *string, *time.Time){
		"schema2 purpose": func(a *Approval, _ *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			a.Purpose = HarnessQualificationPurpose
		},
		"wrong digest": func(a *Approval, _ *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			a.PlanDigest = strings.Repeat("b", 64)
		},
		"wrong pair": func(a *Approval, _ *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			a.PairCommitment = strings.Repeat("b", 64)
		},
		"wrong host": func(_ *Approval, q *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			q.HostUUID = "FFFFFFFF-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
		},
		"changed owner object": func(_ *Approval, q *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			q.OwnerPlanSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"expired approval": func(_ *Approval, _ *stage2aLocalTestQPlan, _ *string, now *time.Time) {
			*now = now.Add(10 * time.Minute)
		},
		"expired Q": func(_ *Approval, q *stage2aLocalTestQPlan, _ *string, _ *time.Time) {
			q.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
		},
		"wrong fingerprint": func(_ *Approval, _ *stage2aLocalTestQPlan, fp *string, _ *time.Time) { *fp = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			a, plan, fp, at := approval, q, approval.MachineFingerprint, now
			change(&a, &plan, &fp, &at)
			if _, _, err := stage2aLocalTestQApprovalForReview(plan, a, q.HostUUID,
				q.InstallationID, ownerSHA, fp, approval.PairCommitment, public, at); err == nil {
				t.Fatal("unreviewed or stale Q approval accepted")
			}
		})
	}
	for name, edit := range map[string]func(*stage2aLocalTestQApprovalPayload){
		"changed host": func(p *stage2aLocalTestQApprovalPayload) { p.Plan.HostUUID = "FFFFFFFF-BBBB-4CCC-8DDD-EEEEEEEEEEEE" },
		"changed owner digest": func(p *stage2aLocalTestQApprovalPayload) {
			p.Plan.OwnerPlanSHA256 = "sha256:" + strings.Repeat("b", 64)
		},
		"changed pair": func(p *stage2aLocalTestQApprovalPayload) {
			p.ApprovalReference.PairCommitment = strings.Repeat("b", 64)
		},
		"changed plan digest": func(p *stage2aLocalTestQApprovalPayload) { p.PlanSHA256 = "sha256:" + strings.Repeat("b", 64) },
		"expired":             func(p *stage2aLocalTestQApprovalPayload) { p.ExpiresAt = now.Format(time.RFC3339Nano) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := payload
			edit(&changed)
			signed := stage2aLocalTestSignedForTest(t, key, stage2aLocalTestQApprovalPurpose, changed)
			if _, err := verifyStage2aLocalTestQApprovalEnvelope(signed, public, q,
				q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
				approval.PairCommitment, now); err == nil {
				t.Fatal("re-signed stale or wrong-host Q approval accepted")
			}
		})
	}
	forged := stage2aLocalTestSignedForTest(t,
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize)),
		stage2aLocalTestQApprovalPurpose, payload)
	if _, err := verifyStage2aLocalTestQApprovalEnvelope(forged, public, q,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, now); err == nil {
		t.Fatal("forged Q signature accepted")
	}
}

func TestStage2aLocalTestQApprovalClaimBeforeSign(t *testing.T) {
	q, approval, key, ownerSHA, _, now := stage2aLocalTestQApprovalFixture(t)
	public := key.Public().(ed25519.PublicKey)
	sign := func(input []byte) ([]byte, error) { return ed25519.Sign(key, input), nil }
	for _, failSign := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "signer failure"}[failSign], func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "claims")
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
			physicalName, err := filepath.EvalSymlinks(name)
			if err != nil {
				t.Fatal(err)
			}
			driverPath, err := stage2aLocalTestQDriverPlanPath(physicalName, approval.PlanID)
			if err != nil || os.WriteFile(driverPath, []byte(stage2aLocalTestQDriverFixture), 0600) != nil {
				t.Fatal("cannot stage fixed reviewed driver plan")
			}
			dir, err := os.Open(physicalName)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			var stat unix.Stat_t
			if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
				t.Fatal(err)
			}
			store := stage2aAdminClaimStore{path: physicalName, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()),
				device: stat.Dev, inode: stat.Ino, birthtime: stat.Btim}
			if got, err := stage2aLocalTestQReviewedDriverSHA(store.path, approval.PlanID,
				store.uid, store.gid); err != nil || got != q.DriverPlanSHA256 {
				t.Fatalf("reviewed driver refused before Q claim: got %q, want %q, err %v", got, q.DriverPlanSHA256, err)
			}
			actualSign := sign
			if failSign {
				actualSign = func([]byte) ([]byte, error) { return nil, errors.New("test signer unavailable") }
			}
			envelope, err := commitAndSignStage2aLocalTestQApproval(store, dir, q, approval,
				q.HostUUID, ownerSHA, approval.MachineFingerprint, approval.PairCommitment,
				public, now, actualSign)
			if failSign {
				if err == nil || len(envelope) != 0 {
					t.Fatal("failed signer returned Q approval")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if _, err := verifyStage2aLocalTestQApprovalEnvelope(envelope,
				public, q, q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
				approval.PairCommitment, now); err != nil {
				t.Fatal(err)
			}
			claimName := ".stage2a-local-test-q-" + soulEndpointInstallationSlot(q.InstallationID) + "-" + approval.PlanID + ".json"
			if _, err := os.ReadFile(filepath.Join(name, claimName)); err != nil {
				t.Fatal("Q claim not committed before signing")
			}
			if second, err := commitAndSignStage2aLocalTestQApproval(store, dir, q, approval,
				q.HostUUID, ownerSHA, approval.MachineFingerprint, approval.PairCommitment,
				public, now, sign); err == nil || len(second) != 0 {
				t.Fatal("restarted Q approval claim issued a second envelope")
			}
		})
	}
}

func TestStage2aLocalTestQDriverProvenanceBeforeSpend(t *testing.T) {
	q, approval, key, ownerSHA, _, now := stage2aLocalTestQApprovalFixture(t)
	for name, change := range map[string]func(t *testing.T, path string, q *stage2aLocalTestQPlan) string{
		"changed content": func(t *testing.T, path string, _ *stage2aLocalTestQPlan) string {
			t.Helper()
			if err := os.WriteFile(path, []byte(`{"driver":"changed"}`), 0600); err != nil {
				t.Fatal(err)
			}
			return ""
		},
		"symlink": func(t *testing.T, path string, _ *stage2aLocalTestQPlan) string {
			t.Helper()
			if err := os.Rename(path, path+".original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".original", path); err != nil {
				t.Fatal(err)
			}
			return ""
		},
		"false claimed digest": func(_ *testing.T, _ string, q *stage2aLocalTestQPlan) string {
			q.DriverPlanSHA256 = "sha256:" + strings.Repeat("b", 64)
			return ""
		},
		"wrong contracts source": func(t *testing.T, path string, q *stage2aLocalTestQPlan) string {
			t.Helper()
			var reviewed stage2aLocalTestQDriverPlan
			if err := stage2aDecodeExact([]byte(stage2aLocalTestQDriverFixture), &reviewed); err != nil {
				t.Fatal(err)
			}
			reviewed.ContractsSource.Tag = "v0.10.2"
			raw, err := marshalStage2aReservationJCS(reviewed)
			if err != nil || os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("cannot stage changed contracts pin")
			}
			q.DriverPlanSHA256 = stage2aReservationSHA256(raw)
			return ""
		},
		"alternate A-owned directory": func(t *testing.T, path string, _ *stage2aLocalTestQPlan) string {
			t.Helper()
			other := filepath.Join(filepath.Dir(filepath.Dir(path)), "other-claims")
			if err := os.Mkdir(other, 0700); err != nil {
				t.Fatal(err)
			}
			physicalOther, err := filepath.EvalSymlinks(other)
			if err != nil {
				t.Fatal(err)
			}
			otherDriver := filepath.Join(physicalOther, filepath.Base(path))
			if err := os.WriteFile(otherDriver, []byte(stage2aLocalTestQDriverFixture), 0600); err != nil {
				t.Fatal(err)
			}
			return physicalOther
		},
	} {
		t.Run(name, func(t *testing.T) {
			claimPath := filepath.Join(t.TempDir(), "claims")
			if err := os.Mkdir(claimPath, 0700); err != nil {
				t.Fatal(err)
			}
			physicalClaim, err := filepath.EvalSymlinks(claimPath)
			if err != nil {
				t.Fatal(err)
			}
			driverPath, err := stage2aLocalTestQDriverPlanPath(physicalClaim, approval.PlanID)
			if err != nil || os.WriteFile(driverPath, []byte(stage2aLocalTestQDriverFixture), 0600) != nil {
				t.Fatal("cannot write driver fixture")
			}
			candidate := q
			override := change(t, driverPath, &candidate)
			dir, err := os.Open(physicalClaim)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			var st unix.Stat_t
			if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
				t.Fatal(err)
			}
			store := stage2aAdminClaimStore{path: physicalClaim, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()),
				device: st.Dev, inode: st.Ino, birthtime: st.Btim}
			if override != "" {
				store.path = override
			}
			signed := false
			envelope, err := commitAndSignStage2aLocalTestQApproval(store, dir,
				candidate, approval, q.HostUUID, ownerSHA, approval.MachineFingerprint,
				approval.PairCommitment, key.Public().(ed25519.PublicKey), now,
				func(input []byte) ([]byte, error) { signed = true; return ed25519.Sign(key, input), nil })
			if err == nil || len(envelope) != 0 || signed {
				t.Fatal("unreviewed driver bytes reached the Q signer")
			}
			claimName := ".stage2a-local-test-q-" + soulEndpointInstallationSlot(q.InstallationID) + "-" + approval.PlanID + ".json"
			if _, err := os.Lstat(filepath.Join(claimPath, claimName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unreviewed driver spent the Q claim: %v", err)
			}
		})
	}
}
