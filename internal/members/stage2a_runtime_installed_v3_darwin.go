//go:build darwin

package members

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

// This narrow A-side API supplies the v3 reservation issuer with the R proof
// from installed authority. Caller metadata cannot select or replace it.
type stage2aInstalledRuntimeV3 struct {
	Policy    stage2aInstalledPolicy
	PolicyRaw []byte
	Plan      stage2aRuntimeV3Install
	Inventory stage2aDomainInventoryV3
	VerifiedR stage2aVerifiedDomainRefV3
	LocalTest *stage2aInstalledLocalTestV1
}

type stage2aInstalledLocalTestV1 struct {
	Owner                  stage2aLocalTestOwnerPlan
	Q                      stage2aLocalTestQPlan
	Approval               stage2aLocalTestQApprovalReference
	ApprovalEnvelopeSHA256 string
}

func stage2aLoadInstalledRuntimeV3(key ed25519.PublicKey, hqUID int, epoch,
	installationID string) (stage2aInstalledRuntimeV3, error) {
	var empty stage2aInstalledRuntimeV3
	// The stop loader checks the installed A policy against the exact root
	// owner plan and applied receipt without the legacy positive-start gate.
	p, raw, err := loadStage2aInstalledPolicyForStop(key, hqUID, epoch, installationID)
	if err != nil || p.RuntimeV3 == nil || !stage2aProtectedPackageMeasurementV3(p) {
		return empty, errStage2aReservationAuthority
	}
	lease, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if err != nil || !lease.After(time.Now()) {
		return empty, errStage2aReservationAuthority
	}
	var approved Plan
	if json.Unmarshal(p.Plan, &approved) != nil || approved.SoulProtectedLaunch == nil ||
		(approved.SoulProtectedLaunch.Schema != stage2aRuntimeInstallSchemaV3 &&
			approved.SoulProtectedLaunch.Schema != stage2aLocalTestInstallSchema) ||
		approved.SoulProtectedLaunch.RuntimeV3 == nil {
		return empty, errStage2aReservationAuthority
	}
	spec := *approved.SoulProtectedLaunch.RuntimeV3
	ref := *p.RuntimeV3
	if ref.ReviewedSourceInventoryDigest != spec.InventoryDigest ||
		ref.InventoryDigest != spec.InventoryDigest ||
		ref.OwnerPlanDigest != "sha256:"+p.Binding.InstalledPlanDigest {
		return empty, errStage2aReservationAuthority
	}
	verified, err := stage2aObserveInstalledDomainV3(ref.Snapshot.Path, ref.Sidecar.Path,
		ref.MachineUID, ref.ReaderUID, ref.ReaderGID,
		ref.OwnerPlanDigest, ref.ReviewedSourceInventoryDigest)
	if err != nil || verified.ref != ref {
		return empty, errStage2aReservationAuthority
	}
	_, inventoryBytes, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(inventoryBytes)
	if err != nil || digest != spec.InventoryDigest || inv.Domain != "R-runtime" ||
		inv.InstallationID != installationID || inv.Limits != spec.Limits ||
		stage2aRuntimeNeedsQualificationV3(inv) != spec.QualificationOnly ||
		!stage2aRuntimeSourcesMatchInventory(inv, spec.SourceRoots) ||
		stage2aRecheckVerifiedDomainV3(verified) != nil ||
		!stage2aSelectedCommandRecordedV3(p, inv) {
		return empty, errStage2aReservationAuthority
	}
	var localTest *stage2aInstalledLocalTestV1
	if approved.SoulProtectedLaunch.Schema == stage2aLocalTestInstallSchema {
		var root Receipt
		if json.Unmarshal(p.Receipt, &root) != nil {
			return empty, errStage2aReservationAuthority
		}
		owner, q, approval, err := stage2aVerifyLocalTestRootReceipt(p, root, key)
		if err != nil {
			return empty, errStage2aReservationAuthority
		}
		qExpires, qErr := time.Parse(time.RFC3339Nano, q.ExpiresAt)
		ownerExpires, ownerErr := time.Parse(time.RFC3339Nano, owner.ExpiresAt)
		if qErr != nil || ownerErr != nil || !time.Now().Before(qExpires) ||
			!time.Now().Before(ownerExpires) {
			return empty, errStage2aReservationAuthority
		}
		measured, err := stage2aLocalTestMeasuredLeadFromRuntime(owner, ref, inv)
		if err != nil {
			return empty, errStage2aReservationAuthority
		}
		want, err := stage2aLocalTestInstallReceiptFor(owner,
			p.ObservedBodyLocalTestReceipt.OwnerPlanSHA256, q,
			"sha256:"+approval.PlanDigest, approval, measured,
			p.Binding.PlanID, p.Binding.InstalledPlanDigest, installationID, key)
		if err != nil || want != *p.ObservedBodyLocalTestReceipt {
			return empty, errStage2aReservationAuthority
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		hostErr := observeStage2aQualificationHost(ctx, q.HostUUID)
		cancel()
		if hostErr != nil {
			return empty, errStage2aReservationAuthority
		}
		approvalEnvelope, err := base64.RawURLEncoding.Strict().DecodeString(root.Stage2aLocalTestQApprovalEnvelope)
		if err != nil {
			return empty, errStage2aReservationAuthority
		}
		localTest = &stage2aInstalledLocalTestV1{Owner: owner, Q: q, Approval: approval,
			ApprovalEnvelopeSHA256: stage2aReservationSHA256(approvalEnvelope)}
	}
	return stage2aInstalledRuntimeV3{Policy: p, PolicyRaw: raw,
		Plan: spec, Inventory: inv, VerifiedR: verified, LocalTest: localTest}, nil
}
