package members

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRetainedCooperativeHReceiptSurvivesInstallApprovalExpiry(t *testing.T) {
	service, _ := stage2aHQTestService(t)
	s := service.Stage2a
	s.CooperativeOnly = true
	s.RuntimeInstallationID = ""
	owner := "owner"
	launch, err := s.launch(owner, s.AuthorityKeySHA256)
	if err != nil {
		t.Fatal(err)
	}
	launch.LauncherSHA256 = s.AuthorityKeySHA256
	rec := launchRecord{Service: service, Stage2a: launch,
		Plist: renderHQStage2aPlist(renderLaunchPlist(service, 501, owner, launchControlV2), launch.OuterArgv), OwnerUID: 501}
	previousID := "plan-20261122T141516Z-abcd"
	previous := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir}
	priorDigest, err := previous.Digest()
	if err != nil {
		t.Fatal(err)
	}
	step, err := json.Marshal(launchUpgrade{PreviousID: previousID, PreviousDigest: priorDigest, Next: rec})
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir, Steps: []Step{
		{Kind: KindHQAccount}, {Kind: KindService, Action: upgradeAction, Target: launchLabel, Owner: owner, Content: string(step)},
	}}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	saved := Saved{PlanID: "plan-20261122T141517Z-abcd", PlanDigest: digest, HQService: &service,
		UpgradeFrom: &priorServicePlan{ID: previousID, Plan: previous}, Plan: plan}
	approvedAt := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)
	fingerprint := strings.Repeat("f", 64)
	approval := Approval{Purpose: UpgradePurpose, PlanID: saved.PlanID, PlanDigest: digest,
		MachineFingerprint: fingerprint, PairCommitment: strings.Repeat("e", 64),
		ApprovedAt: approvedAt.Format(approvalTime), ExpiresAt: approvedAt.Add(ApprovalTTL).Format(approvalTime)}
	witness := stage2aDomainSidecarRefV3{stage2aDomainNodeRefV3: stage2aDomainNodeRefV3{
		Path: hqStage2aDescriptor, OwnerUID: uint32(s.MachineUID), OwnerGID: uint32(s.ReaderGID), Mode: "0440"},
		SizeBytes: 10, SHA256: "sha256:" + strings.Repeat("a", 64)}
	journal, err := json.Marshal(hqStage2aJournalDescriptor{Descriptor: &witness})
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{PlanID: saved.PlanID, PlanDigest: digest, Owner: owner,
		HQAccount: DarwinHQAccount, Dir: DarwinDir, Result: "applied",
		StartedAt:  approvedAt.Add(time.Minute).Format(approvalTime),
		FinishedAt: approvedAt.Add(2 * time.Minute).Format(approvalTime),
		Upgrade:    &upgradeReceiptEvidence{Approval: approval, ProtectedDescriptor: journal}}
	if _, got, _, err := retainedCooperativeHReceipt(saved, receipt, owner, fingerprint); err != nil || got != approval {
		t.Fatalf("applied H receipt lost its expired install approval: %v", err)
	}
	for _, mutate := range []func(*Receipt){
		func(r *Receipt) { r.Result = "started" },
		func(r *Receipt) { r.StartedAt = approvedAt.Add(ApprovalTTL).Format(approvalTime) },
		func(r *Receipt) { r.Upgrade = &upgradeReceiptEvidence{Approval: approval} },
		func(r *Receipt) {
			withRuntime := stage2aDomainInventoryRefV3{}
			wrongJournal, _ := json.Marshal(hqStage2aJournalDescriptor{Descriptor: &witness, Runtime: &withRuntime})
			r.Upgrade = &upgradeReceiptEvidence{Approval: approval, ProtectedDescriptor: wrongJournal}
		},
		func(r *Receipt) {
			changed := approval
			changed.MachineFingerprint = strings.Repeat("0", 64)
			r.Upgrade = &upgradeReceiptEvidence{Approval: changed, ProtectedDescriptor: journal}
		},
	} {
		changed := receipt
		mutate(&changed)
		if _, _, _, err := retainedCooperativeHReceipt(saved, changed, owner, fingerprint); err == nil {
			t.Fatal("changed or incomplete applied H receipt was accepted")
		}
	}
}

func TestCooperativeHQJournalRequiresHOnlyWitness(t *testing.T) {
	service, _ := stage2aHQTestService(t)
	service.Stage2a.CooperativeOnly = true
	service.Stage2a.RuntimeInstallationID = ""
	rec := launchRecord{Service: service}
	var emptyRuntime stage2aDomainInventoryRefV3
	if !hqStage2aRuntimeEvidenceMatches(rec, emptyRuntime) {
		t.Fatal("H-only publication rejected without an R runtime")
	}
	witness := stage2aDomainSidecarRefV3{}
	j := upgradeJournal{ProtectedDescriptor: &hqStage2aJournalDescriptor{Descriptor: &witness}}
	if err := j.checkProtectedHQCandidate(rec, func(launchRecord, Approval, *hqStage2aJournalDescriptor) error { return nil }); err != nil {
		t.Fatalf("H-only durable journal was refused: %v", err)
	}
	j.ProtectedDescriptor.Runtime = &emptyRuntime
	if err := j.checkProtectedHQCandidate(rec, func(launchRecord, Approval, *hqStage2aJournalDescriptor) error { return nil }); err == nil {
		t.Fatal("H-only journal accepted an R runtime field")
	}
	service.Stage2a.CooperativeOnly = false
	rec.Service = service
	if hqStage2aRuntimeEvidenceMatches(rec, emptyRuntime) {
		t.Fatal("protected publication accepted a missing R runtime")
	}
}

func TestStage2aHQCooperativePlanSeparatesRuntimeMode(t *testing.T) {
	s, _ := stage2aHQTestService(t)
	if err := s.Stage2a.validate(); err != nil {
		t.Fatal(err)
	}
	runtime := s.Stage2a.RuntimeInstallationID
	s.Stage2a.RuntimeInstallationID = ""
	if s.Stage2a.validate() == nil {
		t.Fatal("protected setup accepted without R selector")
	}
	s.Stage2a.CooperativeOnly = true
	if err := s.Stage2a.validate(); err != nil {
		t.Fatal("H-only setup requires R", err)
	}
	raw, err := json.Marshal(s.Stage2a)
	if err != nil || strings.Contains(string(raw), "runtime_installation_id") {
		t.Fatal("H-only plan retained an R selector", err)
	}
	rawWithRuntime := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"runtime_installation_id":""}`)...)
	var decoded hqStage2aService
	if json.Unmarshal(rawWithRuntime, &decoded) == nil {
		t.Fatal("H-only JSON accepted an explicit empty runtime selector")
	}
	if _, err := runStage2aHQEvidence(hqStage2aWorkerRequest{}, launchRecord{Service: s}, nil, "", nil); err == nil {
		t.Fatal("protected worker accepted the H-only mode")
	}
	s.Stage2a.RuntimeInstallationID = runtime
	if s.Stage2a.validate() == nil {
		t.Fatal("H-only plan accepted an R selector")
	}
}

func TestStage2aHQCooperativeProofRejectsUnboundAuthority(t *testing.T) {
	now := time.Now()
	d := strings.Repeat("d", 64)
	h := "sha256:" + strings.Repeat("a", 64)
	proof := stage2aCooperativeHProofV3{verified: true, hostID: "fixture-host",
		hqInstallationID: "inst_0123456789abcdef", hOwnerPlanDigest: h,
		cooperativePlanID: "plan-20261122T141517Z-abcd", cooperativePlanDigest: d, pairCommitment: d,
		machineUID: 501, hqUID: 302, readerGID: 302,
		components:    []stage2aHReleaseComponentV3{{ComponentID: "hq", ReleaseArtifactSHA256: h}},
		approvedUntil: now.Add(time.Minute), withLivePair: func(_ string, _ func() error) error { return nil }}
	payload := stage2aHServiceDescriptorPayloadV3{HostID: proof.hostID, HQInstallationID: proof.hqInstallationID,
		OwnerPlanDigest: h, Components: append([]stage2aHReleaseComponentV3(nil), proof.components...),
		HInventory: stage2aDomainInventoryRefV3{Domain: "H-code", InstallationID: proof.hqInstallationID,
			OwnerPlanDigest: h, MachineUID: 501, ReaderUID: 302, ReaderGID: 302}}
	if !proof.valid(now) || !proof.matches(payload) {
		t.Fatal("exact independently approved H identity refused")
	}
	if _, err := loadStage2aCooperativeHV3(proof, nil); err == nil {
		t.Fatal("pair guard that performed no live load returned authority")
	}
	payload.Components[0].ReleaseArtifactSHA256 = "sha256:" + d
	if proof.matches(payload) {
		t.Fatal("different H archive matched cooperative approval")
	}
	proof.withLivePair = nil
	if proof.valid(now) {
		t.Fatal("cooperative proof accepted without live pairing")
	}
}
