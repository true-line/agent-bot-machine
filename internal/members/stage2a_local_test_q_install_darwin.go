//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"
)

// The R seal has already remeasured every installed byte against its reviewed
// inventory. Select the exact lead files from that sealed tree; a matching
// digest in an unrelated file or release component cannot satisfy the plan.
func stage2aLocalTestMeasuredLeadFromRuntime(owner stage2aLocalTestOwnerPlan,
	ref stage2aDomainInventoryRefV3, inv stage2aDomainInventoryV3) (stage2aLocalTestMeasuredLead, error) {
	var result stage2aLocalTestMeasuredLead
	if !owner.Enabled || len(owner.Members) != 2 || ref.Domain != "R-runtime" ||
		inv.Domain != "R-runtime" || ref.InstallationID != inv.InstallationID ||
		!stage2aAbsolutePath(ref.Snapshot.Path) {
		return result, errStage2aReservationAuthority
	}
	lead := owner.Members[0]
	if lead.AdjacentCLIPath != filepath.Join(ref.Snapshot.Path, "runtime/bin/claude") ||
		stage2aChildCodeRowsV3(ref, inv, lead.CommandPath, lead.CommandSHA256) != nil {
		return result, errStage2aReservationAuthority
	}
	var manifests, commands, clients int
	for _, row := range inv.Files {
		if row.ComponentID != "adapter" || row.Kind != "regular" {
			continue
		}
		installed := filepath.Join(ref.Snapshot.Path, filepath.FromSlash(row.Path))
		if row.ReleasePath == lead.AdapterManifestRelpath {
			manifests++
			result.AdapterManifestSHA256 = row.SHA256
		}
		if installed == lead.CommandPath {
			commands++
			result.CommandSHA256 = row.SHA256
		}
		if installed == lead.AdjacentCLIPath {
			clients++
			result.AdjacentCLISHA256 = row.SHA256
		}
	}
	if manifests != 1 || commands != 1 || clients != 1 ||
		result.AdapterManifestSHA256 != lead.AdapterManifestSHA256 ||
		result.CommandSHA256 != lead.CommandSHA256 ||
		result.AdjacentCLISHA256 != lead.AdjacentCLISHA256 {
		return stage2aLocalTestMeasuredLead{}, errStage2aReservationAuthority
	}
	return result, nil
}

func stage2aLocalTestReceiptFromSealedRuntime(policy stage2aInstalledPolicy,
	owner stage2aLocalTestOwnerPlan, ownerSHA256 string, q stage2aLocalTestQPlan,
	approval stage2aLocalTestQApprovalReference, key ed25519.PublicKey) (stage2aLocalTestInstallReceipt, error) {
	var empty stage2aLocalTestInstallReceipt
	if policy.RuntimeV3 == nil || policy.RuntimeV3.Domain != "R-runtime" {
		return empty, errStage2aReservationAuthority
	}
	ref := *policy.RuntimeV3
	side, raw, err := stage2aV3SidecarAt(ref.Sidecar.Path, ref.MachineUID, ref.ReaderGID)
	if err != nil || side != ref.Sidecar {
		return empty, errStage2aReservationAuthority
	}
	inv, digest, err := stage2aDomainInventoryDigestV3(raw)
	if err != nil || digest != ref.InventoryDigest {
		return empty, errStage2aReservationAuthority
	}
	identity, observedDigest, err := stage2aObserveDomainV3At(ref.Snapshot.Path,
		ref.MachineUID, ref.ReaderGID, raw)
	if err != nil || observedDigest != digest || stage2aV3SnapshotRef(identity) != ref.Snapshot {
		return empty, errStage2aReservationAuthority
	}
	measured, err := stage2aLocalTestMeasuredLeadFromRuntime(owner, ref, inv)
	if err != nil {
		return empty, err
	}
	return stage2aLocalTestInstallReceiptFor(owner, ownerSHA256, q,
		"sha256:"+approval.PlanDigest, approval, measured,
		policy.Binding.PlanID, policy.Binding.InstalledPlanDigest,
		policy.Binding.InstallationID, key)
}

// The root apply receipt carries the exact A-signed Q approval and the root
// spend record. A can therefore verify the historical authorization without
// access to the root-only approval file. Positive execution separately
// remeasures the entire sealed R tree before using the receipt.
func stage2aVerifyLocalTestRootReceipt(policy stage2aInstalledPolicy,
	root Receipt, key ed25519.PublicKey) (stage2aLocalTestOwnerPlan,
	stage2aLocalTestQPlan, stage2aLocalTestQApprovalReference, error) {
	var emptyOwner stage2aLocalTestOwnerPlan
	var emptyQ stage2aLocalTestQPlan
	var emptyRef stage2aLocalTestQApprovalReference
	if policy.LocalTestQPlanID == "" {
		if policy.ObservedBodyLocalTestReceipt != nil || len(policy.ObservedBodyLocalTest) != 0 ||
			root.Stage2aLocalTestQApprovalEnvelope != "" || len(root.Stage2aLocalTestQSpend) != 0 ||
			len(root.Stage2aLocalTestReceipt) != 0 {
			return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
		}
		return emptyOwner, emptyQ, emptyRef, nil
	}
	if policy.ObservedBodyLocalTestReceipt == nil || policy.RuntimeV3 == nil ||
		root.Stage2aLocalTestQApprovalEnvelope == "" || len(root.Stage2aLocalTestQSpend) == 0 ||
		len(root.Stage2aLocalTestReceipt) == 0 {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	approvedUntil, err := time.Parse(time.RFC3339Nano, policy.ApprovedUntil)
	if err != nil {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	owner, ownerSHA, err := parseStage2aLocalTestOwnerPlan(policy.ObservedBodyLocalTest,
		policy.BridgeQualification, approvedUntil)
	if err != nil || owner.RunnerHomeLexical != darwinSoulRunnerHome(policy.Runner.Account) {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(root.Stage2aLocalTestQApprovalEnvelope)
	if err != nil || base64.RawURLEncoding.EncodeToString(envelope) != root.Stage2aLocalTestQApprovalEnvelope ||
		stage2aStrictJSON(root.Stage2aLocalTestQSpend) != nil ||
		stage2aStrictJSON(root.Stage2aLocalTestReceipt) != nil {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	var spent stage2aLocalTestQRootSpend
	var recorded stage2aLocalTestInstallReceipt
	if stage2aDecodeExact(root.Stage2aLocalTestQSpend, &spent) != nil ||
		stage2aDecodeExact(root.Stage2aLocalTestReceipt, &recorded) != nil ||
		recorded != *policy.ObservedBodyLocalTestReceipt {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	spentAt, err := time.Parse(time.RFC3339Nano, spent.SpentAt)
	if err != nil || spentAt.IsZero() {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(key))
	q, ref, err := stage2aLocalTestQApprovalForInstall(envelope, key,
		policy.Binding.PlanID, policy.Binding.InstalledPlanDigest,
		policy.LocalTestQPlanID, policy.Binding.InstallationID, ownerSHA,
		owner.Revision, owner.Members[0].AdapterManifestSHA256,
		fingerprint, spent.ApprovalReference.PairCommitment, spentAt)
	if err != nil || spent.HostUUID != q.HostUUID || spent.ApprovalReference != ref ||
		spent.ApprovalEnvelopeSHA256 != stage2aReservationSHA256(envelope) {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	_, spentRaw, err := stage2aLocalTestQRootSpendRecord(envelope, key, q, ref,
		ownerSHA, fingerprint, ref.PairCommitment, q.HostUUID, spentAt)
	if err != nil || !bytes.Equal(spentRaw, root.Stage2aLocalTestQSpend) {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	measured := stage2aLocalTestMeasuredLead{
		AdapterManifestSHA256: recorded.AdapterManifestSHA256,
		CommandSHA256:         recorded.CommandSHA256,
		AdjacentCLISHA256:     recorded.AdjacentCLISHA256,
	}
	want, err := stage2aLocalTestInstallReceiptFor(owner, ownerSHA, q,
		"sha256:"+ref.PlanDigest, ref, measured, policy.Binding.PlanID,
		policy.Binding.InstalledPlanDigest, policy.Binding.InstallationID, key)
	if err != nil || want != recorded {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(recorded)
	if err != nil || !bytes.Equal(canonical, root.Stage2aLocalTestReceipt) {
		return emptyOwner, emptyQ, emptyRef, errStage2aReservationAuthority
	}
	return owner, q, ref, nil
}
