//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStage2aLocalTestInstalledLeadUsesSealedAdapterRows(t *testing.T) {
	owner, _, _ := stage2aLocalTestOwnerPlanFixture(t)
	lead := &owner.Members[0]
	lead.CommandPath = "/sealed/runtime/bin/claude-agent-acp"
	lead.AdjacentCLIPath = "/sealed/runtime/bin/claude"
	ref := stage2aDomainInventoryRefV3{Domain: "R-runtime", InstallationID: "inst.fixture",
		Snapshot: stage2aDomainNodeRefV3{Path: "/sealed"}}
	inv := stage2aDomainInventoryV3{Domain: "R-runtime", InstallationID: ref.InstallationID,
		Files: []stage2aDomainFileV3{
			{Path: "runtime/manifest.json", Kind: "regular", ComponentID: "adapter",
				ReleasePath: lead.AdapterManifestRelpath, SHA256: lead.AdapterManifestSHA256},
			{Path: "runtime/bin/claude-agent-acp", Kind: "regular", Mode: "0550", ComponentID: "adapter",
				ReleasePath: "adapter", SHA256: lead.CommandSHA256},
			{Path: "runtime/bin/claude", Kind: "regular", Mode: "0550", ComponentID: "adapter",
				ReleasePath: "stock-client", SHA256: lead.AdjacentCLISHA256},
		}}
	got, err := stage2aLocalTestMeasuredLeadFromRuntime(owner, ref, inv)
	if err != nil || got.AdapterManifestSHA256 != lead.AdapterManifestSHA256 ||
		got.CommandSHA256 != lead.CommandSHA256 || got.AdjacentCLISHA256 != lead.AdjacentCLISHA256 {
		t.Fatalf("sealed lead rows refused: %v", err)
	}
	for name, mutate := range map[string]func(*stage2aDomainInventoryV3){
		"manifest from sibling component": func(x *stage2aDomainInventoryV3) { x.Files[0].ComponentID = "souls" },
		"second matching manifest":        func(x *stage2aDomainInventoryV3) { x.Files = append(x.Files, x.Files[0]) },
		"changed stock CLI":               func(x *stage2aDomainInventoryV3) { x.Files[2].SHA256 = "sha256:" + strings.Repeat("b", 64) },
		"wrong executable path":           func(x *stage2aDomainInventoryV3) { x.Files[1].Path = "runtime/bin/other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := inv
			changed.Files = append([]stage2aDomainFileV3(nil), inv.Files...)
			mutate(&changed)
			if _, err := stage2aLocalTestMeasuredLeadFromRuntime(owner, ref, changed); err == nil {
				t.Fatal("unreviewed adapter row accepted")
			}
		})
	}
}

func TestStage2aLocalTestRootReceiptReopensSignedQAndSpend(t *testing.T) {
	q, approval, privateKey, ownerSHA, _, now := stage2aLocalTestQApprovalFixture(t)
	key := privateKey.Public().(ed25519.PublicKey)
	approval.MachineFingerprint = fmt.Sprintf("%x", sha256.Sum256(key))
	owner, fixture, approvedUntil := stage2aLocalTestOwnerPlanFixture(t)
	ownerRaw, err := json.Marshal(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, observedOwnerSHA, err := parseStage2aLocalTestOwnerPlan(ownerRaw, fixture, approvedUntil); err != nil || observedOwnerSHA != ownerSHA {
		t.Fatal("owner fixture changed")
	}
	payload, _, err := stage2aLocalTestQApprovalForReview(q, approval,
		q.HostUUID, q.InstallationID, ownerSHA, approval.MachineFingerprint,
		approval.PairCommitment, key, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope := stage2aLocalTestSignedForTest(t, privateKey, stage2aLocalTestQApprovalPurpose, payload)
	ref := payload.ApprovalReference
	parsedQ, parsedRef, err := stage2aLocalTestQApprovalForInstall(envelope, key,
		q.InstalledPlanID, q.InstalledPlanDigest, ref.PlanID, q.InstallationID,
		ownerSHA, owner.Revision, owner.Members[0].AdapterManifestSHA256,
		approval.MachineFingerprint, approval.PairCommitment, now)
	if err != nil || parsedQ != q || parsedRef != ref {
		t.Fatalf("exact signed Q install approval refused: %v", err)
	}
	if _, _, err := stage2aLocalTestQApprovalForInstall(envelope, key,
		q.InstalledPlanID, q.InstalledPlanDigest, "plan-20261124T120002Z-abcd",
		q.InstallationID, ownerSHA, owner.Revision,
		owner.Members[0].AdapterManifestSHA256, approval.MachineFingerprint,
		approval.PairCommitment, now); err == nil {
		t.Fatal("different root-reviewed Q ID accepted")
	}
	spent, spentRaw, err := stage2aLocalTestQRootSpendRecord(envelope, key, q, ref,
		ownerSHA, approval.MachineFingerprint, approval.PairCommitment, q.HostUUID, now)
	if err != nil || spent.ApprovalEnvelopeSHA256 != stage2aReservationSHA256(envelope) {
		t.Fatal("root Q spend fixture failed")
	}
	measured := stage2aLocalTestMeasuredLead{
		AdapterManifestSHA256: owner.Members[0].AdapterManifestSHA256,
		CommandSHA256:         owner.Members[0].CommandSHA256,
		AdjacentCLISHA256:     owner.Members[0].AdjacentCLISHA256,
	}
	localReceipt, err := stage2aLocalTestInstallReceiptFor(owner, ownerSHA, q,
		"sha256:"+ref.PlanDigest, ref, measured, q.InstalledPlanID,
		q.InstalledPlanDigest, q.InstallationID, key)
	if err != nil {
		t.Fatal(err)
	}
	localRaw, err := marshalStage2aReservationJCS(localReceipt)
	if err != nil {
		t.Fatal(err)
	}
	policy := stage2aInstalledPolicy{LocalTestQPlanID: ref.PlanID,
		ObservedBodyLocalTest: ownerRaw, ObservedBodyLocalTestReceipt: &localReceipt,
		RuntimeV3: &stage2aDomainInventoryRefV3{}, ApprovedUntil: approvedUntil.Format(time.RFC3339Nano),
		BridgeQualification: fixture, Runner: SoulRunner{Account: soulRunnerName(q.InstallationID)},
		Binding: Stage2aMeasurementBinding{PlanID: q.InstalledPlanID,
			InstalledPlanDigest: q.InstalledPlanDigest, InstallationID: q.InstallationID},
	}
	root := Receipt{Stage2aLocalTestQApprovalEnvelope: base64.RawURLEncoding.EncodeToString(envelope),
		Stage2aLocalTestQSpend: spentRaw, Stage2aLocalTestReceipt: localRaw}
	if _, _, _, err := stage2aVerifyLocalTestRootReceipt(policy, root, key); err != nil {
		t.Fatalf("matching root Q and install receipt refused: %v", err)
	}
	for name, mutate := range map[string]func(*stage2aInstalledPolicy, *Receipt){
		"missing root spend": func(_ *stage2aInstalledPolicy, r *Receipt) { r.Stage2aLocalTestQSpend = nil },
		"different root envelope": func(_ *stage2aInstalledPolicy, r *Receipt) {
			r.Stage2aLocalTestQApprovalEnvelope = base64.RawURLEncoding.EncodeToString([]byte("other"))
		},
		"wrong local receipt": func(_ *stage2aInstalledPolicy, r *Receipt) { r.Stage2aLocalTestReceipt = []byte(`{"schema":"wrong"}`) },
		"changed Q ID":        func(p *stage2aInstalledPolicy, _ *Receipt) { p.LocalTestQPlanID = "plan-20261124T120002Z-abcd" },
		"changed owner":       func(p *stage2aInstalledPolicy, _ *Receipt) { p.ObservedBodyLocalTest = []byte(`{"enabled":false}`) },
	} {
		t.Run(name, func(t *testing.T) {
			changedPolicy, changedRoot := policy, root
			mutate(&changedPolicy, &changedRoot)
			if _, _, _, err := stage2aVerifyLocalTestRootReceipt(changedPolicy, changedRoot, key); err == nil {
				t.Fatal("changed root authority accepted")
			}
		})
	}
	forged := stage2aLocalTestSignedForTest(t,
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize)),
		stage2aLocalTestQApprovalPurpose, payload)
	root.Stage2aLocalTestQApprovalEnvelope = base64.RawURLEncoding.EncodeToString(forged)
	if _, _, _, err := stage2aVerifyLocalTestRootReceipt(policy, root, key); err == nil {
		t.Fatal("Q approval signed by another key accepted")
	}
}
