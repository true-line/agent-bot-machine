//go:build darwin

package members

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"time"

	"github.com/qwts/managed-machine/internal/plan"
	"golang.org/x/sys/unix"
)

const stage2aLocalTestQRootDir = "/private" + DarwinReceiptsDir

func stage2aLocalTestQRootEnvelopePath(ref stage2aLocalTestQApprovalReference) (string, error) {
	if !ValidApproval(ref.PlanID, ref.PlanDigest) || !digestPattern.MatchString(ref.PairCommitment) {
		return "", errStage2aReservationAuthority
	}
	return stage2aLocalTestQRootEnvelopePathForPlan(ref.PlanID)
}

func stage2aLocalTestQRootEnvelopePathForPlan(planID string) (string, error) {
	if !plan.ValidID(planID) {
		return "", errStage2aReservationAuthority
	}
	return filepath.Join(stage2aLocalTestQRootDir, planID+".stage2a-local-test-q-approval.json"), nil
}

// Root has only the separately approved Q plan ID in the saved install plan.
// Decode the fixed root file, then validate the signed Q plan against the
// complete owner-reviewed installation. No path, Q digest or host claim from
// HQ selects a different approval.
func stage2aLocalTestQApprovalForInstall(envelope []byte, key ed25519.PublicKey,
	installedPlanID, installedPlanDigest, qPlanID, installationID, ownerPlanSHA256,
	sourceRevision, candidateManifestSHA256, machineFingerprint, pairCommitment string,
	now time.Time) (stage2aLocalTestQPlan, stage2aLocalTestQApprovalReference, error) {
	var emptyQ stage2aLocalTestQPlan
	var emptyRef stage2aLocalTestQApprovalReference
	raw, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestQApprovalPurpose, key)
	if err != nil {
		return emptyQ, emptyRef, errStage2aReservationAuthority
	}
	payload, err := parseStage2aLocalTestQApprovalPayload(raw)
	if err != nil || payload.ApprovalReference.PlanID != qPlanID ||
		payload.Plan.InstalledPlanID != installedPlanID ||
		payload.Plan.InstalledPlanDigest != installedPlanDigest ||
		payload.Plan.InstallationID != installationID ||
		payload.Plan.OwnerPlanSHA256 != ownerPlanSHA256 ||
		payload.Plan.SourceRevision != sourceRevision ||
		payload.Plan.CandidateManifestSHA256 != candidateManifestSHA256 ||
		payload.Plan.AKeyID != stage2aReservationSHA256(key) {
		return emptyQ, emptyRef, errStage2aReservationAuthority
	}
	if _, _, err := stage2aLocalTestQRootSpendRecord(envelope, key, payload.Plan,
		payload.ApprovalReference, ownerPlanSHA256, machineFingerprint,
		pairCommitment, payload.Plan.HostUUID, now); err != nil {
		return emptyQ, emptyRef, errStage2aReservationAuthority
	}
	return payload.Plan, payload.ApprovalReference, nil
}

type stage2aLocalTestQRootSpend struct {
	Schema                 string                             `json:"schema"`
	QPlanSHA256            string                             `json:"q_plan_sha256"`
	ApprovalReference      stage2aLocalTestQApprovalReference `json:"approval_reference"`
	ApprovalEnvelopeSHA256 string                             `json:"approval_envelope_sha256"`
	HostUUID               string                             `json:"host_uuid"`
	InstallationID         string                             `json:"installation_id"`
	InstalledPlanID        string                             `json:"installed_plan_id"`
	InstalledPlanDigest    string                             `json:"installed_plan_digest"`
	SpentAt                string                             `json:"spent_at"`
}

func stage2aLocalTestQRootSpendRecord(envelope []byte, key ed25519.PublicKey,
	q stage2aLocalTestQPlan, ref stage2aLocalTestQApprovalReference,
	ownerPlanSHA256, machineFingerprint, pairCommitment, observedHostUUID string,
	now time.Time) (stage2aLocalTestQRootSpend, []byte, error) {
	var empty stage2aLocalTestQRootSpend
	if ref.PairCommitment != pairCommitment || !ValidApproval(ref.PlanID, ref.PlanDigest) ||
		!digestPattern.MatchString(pairCommitment) || !ValidApproval(q.InstalledPlanID, q.InstalledPlanDigest) {
		return empty, nil, errStage2aReservationAuthority
	}
	payload, err := verifyStage2aLocalTestQApprovalEnvelope(envelope, key, q,
		observedHostUUID, q.InstallationID, ownerPlanSHA256, machineFingerprint,
		pairCommitment, now)
	if err != nil || payload.ApprovalReference != ref ||
		payload.PlanSHA256 != "sha256:"+ref.PlanDigest {
		return empty, nil, errStage2aReservationAuthority
	}
	record := stage2aLocalTestQRootSpend{
		Schema:      "agent-bot-machine/stage2a-observed-body-local-test-q-root-spend/v1",
		QPlanSHA256: payload.PlanSHA256, ApprovalReference: ref,
		ApprovalEnvelopeSHA256: stage2aReservationSHA256(envelope),
		HostUUID:               observedHostUUID, InstallationID: q.InstallationID,
		InstalledPlanID: q.InstalledPlanID, InstalledPlanDigest: q.InstalledPlanDigest,
		SpentAt: now.UTC().Format(time.RFC3339Nano),
	}
	raw, err := marshalStage2aReservationJCS(record)
	if err != nil || len(raw) > 8192 {
		return empty, nil, errStage2aReservationAuthority
	}
	return record, raw, nil
}

// The owner-reviewed root installer calls this only after measuring the
// proposed install and exact Q plan. The Q envelope must already have been
// staged at its fixed root-owned path; no caller-selected path is accepted.
// A failed apply after this point leaves the Q approval spent.
func loadAndSpendStage2aLocalTestQRootApproval(ctx context.Context,
	q stage2aLocalTestQPlan, ref stage2aLocalTestQApprovalReference,
	ownerPlanSHA256, machineFingerprint, pairCommitment string,
	key ed25519.PublicKey, now time.Time) (stage2aLocalTestQRootSpend, error) {
	var empty stage2aLocalTestQRootSpend
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return empty, errStage2aReservationAuthority
	}
	path, err := stage2aLocalTestQRootEnvelopePath(ref)
	if err != nil {
		return empty, err
	}
	envelope, err := stage2aReadRootFile(path, stage2aV3EnvelopeLimit, 0400)
	if err != nil || observeStage2aQualificationHost(ctx, q.HostUUID) != nil {
		return empty, errStage2aReservationAuthority
	}
	record, raw, err := stage2aLocalTestQRootSpendRecord(envelope, key, q, ref,
		ownerPlanSHA256, machineFingerprint, pairCommitment, q.HostUUID, now)
	if err != nil {
		return empty, err
	}
	dir, err := openStage2aAdminDirectory(stage2aLocalTestQRootDir, 0)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	defer dir.Close()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Uid != 0 || st.Gid != 0 ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
		return empty, errStage2aReservationAuthority
	}
	lock, err := lockStage2aReservation(dir, 0, 0, q.InstallationID)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	name := ".stage2a-local-test-q-spent-" + ref.PlanID + ".json"
	if err := commitStage2aReservation(dir, name, raw); err != nil {
		return empty, err
	}
	return record, nil
}
