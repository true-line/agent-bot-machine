//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage2aLocalTestQCLIPlanDerivesOwnerBoundFields(t *testing.T) {
	owner, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	ownerRaw, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	policy := stage2aInstalledPolicy{ApprovedUntil: approvedUntil.Format(time.RFC3339Nano),
		BridgeQualification: fixture, LocalTestQPlanID: "plan-20261124T120001Z-abcd",
		ObservedBodyLocalTest: ownerRaw}
	policy.Binding.InstallationID = "inst.fixture"
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	saved := Saved{PlanID: "plan-20261124T120000Z-abcd", PlanDigest: strings.Repeat("3", 64),
		SoulProtectedLaunch: &SoulProtectedLaunchInstall{Schema: stage2aLocalTestInstallSchema,
			LocalTestQPlanID: policy.LocalTestQPlanID, Policy: policyRaw}}
	q, raw, digest, err := stage2aLocalTestQCLIPlan(saved,
		"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", "sha256:"+strings.Repeat("4", 64), key,
		approvedUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if q.Purpose != stage2aLocalTestQPurpose || q.InstalledPlanID != saved.PlanID ||
		q.InstalledPlanDigest != saved.PlanDigest || q.AKeyID != stage2aReservationSHA256(key) ||
		q.CandidateManifestSHA256 != owner.Members[0].AdapterManifestSHA256 ||
		q.DriverPlanSHA256 != "sha256:"+strings.Repeat("4", 64) ||
		q.ExpiresAt != owner.ExpiresAt || stage2aReservationSHA256(raw) != digest {
		t.Fatal("Q CLI plan omitted or changed an owner-bound field")
	}
	changed := saved
	request := *saved.SoulProtectedLaunch
	request.LocalTestQPlanID = "plan-20261124T120002Z-abcd"
	changed.SoulProtectedLaunch = &request
	if _, _, _, err := stage2aLocalTestQCLIPlan(changed, q.HostUUID, q.DriverPlanSHA256,
		key, approvedUntil.Add(-time.Minute)); err == nil {
		t.Fatal("accepted Q ID different from saved owner plan")
	}
}

func TestStage2aLocalTestQCLIWriteOrCheckIsImmutable(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	name := "plan-20261124T120001Z-abcd.stage2a-local-test-q-plan.json"
	raw := []byte(`{"schema":"fixed"}`)
	if err := stage2aLocalTestQWriteOrCheck(f, name, raw, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := stage2aLocalTestQWriteOrCheck(f, name, raw, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := stage2aLocalTestQWriteOrCheck(f, name, []byte(`{"schema":"changed"}`), uid, gid); err == nil {
		t.Fatal("changed Q source replaced an occupied path")
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("occupied Q source changed")
	}
}

func TestStage2aLocalTestQCLIReplyBindsExactEnvelope(t *testing.T) {
	planID := "plan-20261124T120001Z-abcd"
	envelope := []byte(`{"signed":"fixture"}`)
	reply := Stage2aLocalTestQApprovalReply{PlanID: planID,
		PlanSHA256:                "sha256:" + strings.Repeat("3", 64),
		ApprovalEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		ApprovalEnvelopeSHA256:    stage2aReservationSHA256(envelope)}
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	got, decoded, err := stage2aLocalTestQCLIReply(raw, planID)
	if err != nil || got != reply || !bytes.Equal(decoded, envelope) {
		t.Fatalf("exact Q issue body refused: %v", err)
	}
	bad := reply
	bad.ApprovalEnvelopeSHA256 = "sha256:" + strings.Repeat("4", 64)
	badRaw, _ := json.Marshal(bad)
	if _, _, err := stage2aLocalTestQCLIReply(badRaw, planID); err == nil {
		t.Fatal("mismatched envelope digest accepted")
	}
	if _, _, err := stage2aLocalTestQCLIReply(raw, "plan-20261124T120002Z-abcd"); err == nil {
		t.Fatal("Q issue body for another plan accepted")
	}
}

func TestStage2aLocalTestQCleanHostPlanStageAndSpend(t *testing.T) {
	q, approval, privateKey, ownerSHA, qDigest, now := stage2aLocalTestQApprovalFixture(t)
	key := privateKey.Public().(ed25519.PublicKey)
	approval.MachineFingerprint = fmt.Sprintf("%x", sha256.Sum256(key))
	owner, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	ownerRaw, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	policy := stage2aInstalledPolicy{ApprovedUntil: approvedUntil.Format(time.RFC3339Nano),
		BridgeQualification: fixture, LocalTestQPlanID: approval.PlanID,
		ObservedBodyLocalTest: ownerRaw}
	policy.Binding.InstallationID = q.InstallationID
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	request := &SoulProtectedLaunchInstall{Schema: stage2aLocalTestInstallSchema,
		MachinePublicKey: hex.EncodeToString(key), LocalTestQPlanID: approval.PlanID,
		Policy: policyRaw}
	saved := Saved{PlanID: q.InstalledPlanID, PlanDigest: q.InstalledPlanDigest,
		SoulProtectedLaunch: request}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(parent, "not-yet-installed", "soul-authority.pub")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	reviewed, err := stage2aLocalTestQReviewedMachineKey(request,
		approval.MachineFingerprint, pinPath, uid, gid)
	if err != nil || !bytes.Equal(reviewed, key) {
		t.Fatalf("clean host could not use the owner-reviewed key: %v", err)
	}
	derived, _, digest, err := stage2aLocalTestQCLIPlan(saved, q.HostUUID,
		q.DriverPlanSHA256, reviewed, now)
	if err != nil || derived != q || digest != qDigest {
		t.Fatalf("clean-host Q plan differed from reviewed source: %v", err)
	}
	payload, _, err := stage2aLocalTestQApprovalForReview(derived, approval,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, reviewed, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope := stage2aLocalTestSignedForTest(t, privateKey,
		stage2aLocalTestQApprovalPurpose, payload)
	reply := Stage2aLocalTestQApprovalReply{PlanID: approval.PlanID,
		PlanSHA256: qDigest, ApprovalEnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		ApprovalEnvelopeSHA256: stage2aReservationSHA256(envelope)}
	replyRaw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	parsedReply, stagedEnvelope, err := stage2aLocalTestQCLIReply(replyRaw, approval.PlanID)
	if err != nil || parsedReply != reply || !bytes.Equal(stagedEnvelope, envelope) {
		t.Fatalf("clean-host Q issue reply could not be staged: %v", err)
	}
	stagedQ, ref, err := stage2aLocalTestQApprovalForInstall(stagedEnvelope, reviewed,
		saved.PlanID, saved.PlanDigest, approval.PlanID, q.InstallationID,
		ownerSHA, owner.Revision, owner.Members[0].AdapterManifestSHA256,
		approval.MachineFingerprint, approval.PairCommitment, now)
	if err != nil || stagedQ != q || ref.PlanID != approval.PlanID {
		t.Fatalf("clean-host root staging rejected reviewed Q: %v", err)
	}
	if _, _, err := stage2aLocalTestQRootSpendRecord(stagedEnvelope, reviewed,
		stagedQ, ref, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, q.HostUUID, now); err != nil {
		t.Fatalf("clean-host root apply could not spend staged Q: %v", err)
	}
	if _, err := stage2aLocalTestQReviewedMachineKey(request,
		strings.Repeat("0", 64), pinPath, uid, gid); err == nil {
		t.Fatal("reviewed key accepted a different install approval fingerprint")
	}
	changed := *request
	changed.MachinePublicKey = hex.EncodeToString(bytes.Repeat([]byte{0x99}, ed25519.PublicKeySize))
	if _, err := stage2aLocalTestQReviewedMachineKey(&changed,
		approval.MachineFingerprint, pinPath, uid, gid); err == nil {
		t.Fatal("changed saved Machine key accepted")
	}
	if _, _, err := stage2aLocalTestQApprovalForInstall(stagedEnvelope, reviewed,
		saved.PlanID, saved.PlanDigest, approval.PlanID, q.InstallationID,
		ownerSHA, owner.Revision, owner.Members[0].AdapterManifestSHA256,
		approval.MachineFingerprint, strings.Repeat("b", 64), now); err == nil {
		t.Fatal("different paired commitment accepted")
	}
	if err := os.Mkdir(filepath.Dir(pinPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, bytes.Repeat([]byte{0x99}, ed25519.PublicKeySize), 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := stage2aLocalTestQReviewedMachineKey(request,
		approval.MachineFingerprint, pinPath, uid, gid); err == nil {
		t.Fatal("conflicting existing pin accepted")
	}
	if err := os.Chmod(pinPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, key, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pinPath, 0444); err != nil {
		t.Fatal(err)
	}
	if matched, err := stage2aLocalTestQReviewedMachineKey(request,
		approval.MachineFingerprint, pinPath, uid, gid); err != nil || !bytes.Equal(matched, key) {
		t.Fatalf("matching existing pin refused: %v", err)
	}
}
