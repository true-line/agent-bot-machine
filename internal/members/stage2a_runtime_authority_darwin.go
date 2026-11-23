package members

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// The ordinary protected Soul install persists its exact canonical owner plan
// and root-completed receipt. The receipt, not the H request, identifies R.
func loadStage2aHQInstalledRuntime(key ed25519.PublicKey, service hqStage2aService) (stage2aVerifiedDomainRefV3, error) {
	var empty stage2aVerifiedDomainRefV3
	path, err := stage2aAuthorityPath(service.RuntimeInstallationID)
	if err != nil {
		return empty, err
	}
	data, err := stage2aReadAdminPolicy(path, 1<<20)
	var observed stage2aInstalledPolicy
	if err != nil || stage2aDecodeExact(data, &observed) != nil {
		return empty, errStage2aReservationAuthority
	}
	p, _, err := loadStage2aInstalledPolicyForStop(key, service.ReaderUID, observed.Binding.HQEpoch, service.RuntimeInstallationID)
	if err != nil || p.MachineUID != service.MachineUID || p.MachineGID != service.MachineGID || p.MachineAccount != service.MachineAccount ||
		p.Binding.HostID != service.HostID || p.Runner.UID == service.ReaderUID || p.Runner.GID == service.ReaderGID {
		return empty, errStage2aReservationAuthority
	}
	approvedUntil, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if err != nil || !time.Now().Before(approvedUntil) {
		return empty, errStage2aReservationAuthority
	}
	// The installed-policy loader has already authenticated both full records.
	// Read only the selected v3 fields here; their enclosing schemas belong to
	// the separately reviewed R producer.
	var approved struct {
		SoulProtectedLaunch *struct {
			RuntimeV3 *struct {
				InventoryDigest string                         `json:"inventory_digest"`
				Limits          stage2aDomainInventoryLimitsV3 `json:"limits"`
				Components      []stage2aReleaseComponent      `json:"components"`
			} `json:"runtime_v3"`
		} `json:"soul_protected_launch"`
	}
	var receipt struct {
		RuntimeV3 json.RawMessage `json:"stage2a_runtime_v3"`
	}
	if json.Unmarshal(p.Plan, &approved) != nil || approved.SoulProtectedLaunch == nil || approved.SoulProtectedLaunch.RuntimeV3 == nil ||
		json.Unmarshal(p.Receipt, &receipt) != nil {
		return empty, errStage2aReservationAuthority
	}
	plan := approved.SoulProtectedLaunch.RuntimeV3
	var ref stage2aDomainInventoryRefV3
	if !stage2aPrefixedDigest.MatchString(plan.InventoryDigest) || len(plan.Components) == 0 || stage2aDecodeExact(receipt.RuntimeV3, &ref) != nil || ref.Domain != "R-runtime" || ref.InstallationID != service.RuntimeInstallationID ||
		ref.OwnerPlanDigest != "sha256:"+p.Binding.InstalledPlanDigest || ref.InventoryDigest != plan.InventoryDigest || !matchesHQStage2aRuntimeNames(ref) ||
		ref.MachineUID != uint32(p.MachineUID) || ref.ReaderUID != uint32(p.Runner.UID) || ref.ReaderGID != uint32(p.Runner.GID) {
		return empty, errStage2aReservationAuthority
	}
	r, err := stage2aObserveInstalledDomainV3(ref.Snapshot.Path, ref.Sidecar.Path, ref.MachineUID, ref.ReaderUID, ref.ReaderGID, ref.OwnerPlanDigest, plan.InventoryDigest)
	if err != nil || r.ref != ref {
		return empty, errStage2aReservationAuthority
	}
	_, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil {
		return empty, err
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != plan.InventoryDigest || inv.Limits != plan.Limits || checkStage2aApprovedReleaseSources(plan.Components, inv) != nil {
		return empty, errStage2aReservationAuthority
	}
	return r, nil
}
