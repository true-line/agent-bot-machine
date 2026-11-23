package members

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
