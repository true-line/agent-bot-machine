//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
