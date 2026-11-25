//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const (
	stage2aLocalTestQPurpose             = "stage2a-observed-body-local-test-qualification/v1"
	stage2aLocalTestQSchema              = "agent-bot-machine/stage2a-observed-body-local-test-q/v1"
	stage2aLocalTestInstallReceiptSchema = "agent-bot-machine/stage2a-observed-body-local-test-install-receipt/v1"
)

// This Q purpose is disjoint from schema-2 harness-qualification-run. A saved
// schema-2 driver plan can never authorize observed-body Provider access.
type stage2aLocalTestQPlan struct {
	Schema                  string `json:"schema"`
	Purpose                 string `json:"purpose"`
	HostUUID                string `json:"host_uuid"`
	InstallationID          string `json:"installation_id"`
	InstalledPlanID         string `json:"installed_plan_id"`
	InstalledPlanDigest     string `json:"installed_plan_digest"`
	OwnerPlanSHA256         string `json:"owner_plan_sha256"`
	SourceRevision          string `json:"source_revision"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
	DriverPlanSHA256        string `json:"driver_plan_sha256"`
	AKeyID                  string `json:"a_key_id"`
	ExpiresAt               string `json:"expires_at"`
}

type stage2aLocalTestQApprovalReference struct {
	PlanID         string `json:"plan_id"`
	PlanDigest     string `json:"plan_digest"`
	PairCommitment string `json:"pair_commitment"`
}

// Root produces this echo only after checking the distinct Q approval and
// remeasuring the installed lead member. It is not an HQ-supplied plan field.
type stage2aLocalTestInstallReceipt struct {
	Schema                 string                             `json:"schema"`
	OwnerPlanSHA256        string                             `json:"owner_plan_sha256"`
	InstalledPlanID        string                             `json:"installed_plan_id"`
	InstalledPlanDigest    string                             `json:"installed_plan_digest"`
	SourceRevision         string                             `json:"source_revision"`
	MemberSetSHA256        string                             `json:"member_set_sha256"`
	AdapterManifestSHA256  string                             `json:"adapter_manifest_sha256"`
	CommandSHA256          string                             `json:"command_sha256"`
	AdjacentCLISHA256      string                             `json:"adjacent_cli_sha256"`
	HeaderShapeSHA256      string                             `json:"header_shape_sha256"`
	AncillaryProfileSHA256 string                             `json:"ancillary_profile_sha256"`
	BodyProfile            string                             `json:"body_profile"`
	ClientKeySHA256        string                             `json:"client_key_sha256"`
	AKeyID                 string                             `json:"a_key_id"`
	InstallationID         string                             `json:"installation_id"`
	ExpiresAt              string                             `json:"expires_at"`
	QPlanDigest            string                             `json:"q_plan_digest"`
	QApprovalReference     stage2aLocalTestQApprovalReference `json:"q_approval_reference"`
}

type stage2aLocalTestMeasuredLead struct {
	AdapterManifestSHA256 string
	CommandSHA256         string
	AdjacentCLISHA256     string
}

func parseStage2aLocalTestQPlan(raw []byte) (stage2aLocalTestQPlan, string, error) {
	var q stage2aLocalTestQPlan
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &q) != nil || q.Schema != stage2aLocalTestQSchema ||
		q.Purpose != stage2aLocalTestQPurpose ||
		!qualificationPhysicalUUID.MatchString(q.HostUUID) ||
		!soulInstallationID.MatchString(q.InstallationID) ||
		!ValidApproval(q.InstalledPlanID, q.InstalledPlanDigest) ||
		!stage2aPrefixedDigest.MatchString(q.OwnerPlanSHA256) ||
		!qualificationRevision.MatchString(q.SourceRevision) ||
		!stage2aPrefixedDigest.MatchString(q.CandidateManifestSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.DriverPlanSHA256) ||
		!stage2aPrefixedDigest.MatchString(q.AKeyID) {
		return stage2aLocalTestQPlan{}, "", errStage2aReservationAuthority
	}
	if _, err := time.Parse(time.RFC3339Nano, q.ExpiresAt); err != nil {
		return stage2aLocalTestQPlan{}, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(q)
	if err != nil {
		return stage2aLocalTestQPlan{}, "", errStage2aReservationAuthority
	}
	return q, stage2aReservationSHA256(canonical), nil
}

func stage2aLocalTestInstallReceiptFor(p stage2aLocalTestOwnerPlan, ownerPlanSHA256 string,
	q stage2aLocalTestQPlan, qDigest string, approval stage2aLocalTestQApprovalReference,
	measured stage2aLocalTestMeasuredLead, installedPlanID, installedPlanDigest, installationID string,
	key ed25519.PublicKey) (stage2aLocalTestInstallReceipt, error) {
	var empty stage2aLocalTestInstallReceipt
	if len(key) != ed25519.PublicKeySize || !p.Enabled ||
		!stage2aPrefixedDigest.MatchString(ownerPlanSHA256) ||
		!stage2aPrefixedDigest.MatchString(qDigest) ||
		!soulDigest.MatchString(approval.PlanDigest) ||
		qDigest != "sha256:"+approval.PlanDigest ||
		!ValidApproval(approval.PlanID, approval.PlanDigest) ||
		!soulDigest.MatchString(approval.PairCommitment) ||
		q.Purpose != stage2aLocalTestQPurpose || q.Schema != stage2aLocalTestQSchema ||
		q.OwnerPlanSHA256 != ownerPlanSHA256 || q.SourceRevision != p.Revision ||
		q.InstalledPlanID != installedPlanID || q.InstalledPlanDigest != installedPlanDigest ||
		q.InstallationID != installationID ||
		q.AKeyID != stage2aReservationSHA256(key) ||
		!stage2aPrefixedDigest.MatchString(measured.AdapterManifestSHA256) ||
		!stage2aPrefixedDigest.MatchString(measured.CommandSHA256) ||
		!stage2aPrefixedDigest.MatchString(measured.AdjacentCLISHA256) {
		return empty, errStage2aReservationAuthority
	}
	ownerRaw, e0 := marshalStage2aReservationJCS(p)
	qRaw, eq := marshalStage2aReservationJCS(q)
	if e0 != nil || eq != nil || stage2aReservationSHA256(ownerRaw) != ownerPlanSHA256 ||
		stage2aReservationSHA256(qRaw) != qDigest {
		return empty, errStage2aReservationAuthority
	}
	qExpires, e1 := time.Parse(time.RFC3339Nano, q.ExpiresAt)
	pExpires, e2 := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if e1 != nil || e2 != nil || qExpires.After(pExpires) {
		return empty, errStage2aReservationAuthority
	}
	lead := p.Members[0]
	if measured.AdapterManifestSHA256 != lead.AdapterManifestSHA256 ||
		measured.CommandSHA256 != lead.CommandSHA256 ||
		measured.AdjacentCLISHA256 != lead.AdjacentCLISHA256 {
		return empty, errStage2aReservationAuthority
	}
	memberRaw, e3 := marshalStage2aReservationJCS(p.Members)
	headerRaw, e4 := marshalStage2aReservationJCS(p.HeaderShape)
	ancillaryRaw, e5 := marshalStage2aReservationJCS(p.AncillaryProfile)
	if e3 != nil || e4 != nil || e5 != nil {
		return empty, errStage2aReservationAuthority
	}
	return stage2aLocalTestInstallReceipt{
		Schema:          stage2aLocalTestInstallReceiptSchema,
		OwnerPlanSHA256: ownerPlanSHA256, InstalledPlanID: installedPlanID,
		InstalledPlanDigest: installedPlanDigest, SourceRevision: p.Revision,
		MemberSetSHA256:       stage2aReservationSHA256(memberRaw),
		AdapterManifestSHA256: measured.AdapterManifestSHA256,
		CommandSHA256:         measured.CommandSHA256, AdjacentCLISHA256: measured.AdjacentCLISHA256,
		HeaderShapeSHA256:      stage2aReservationSHA256(headerRaw),
		AncillaryProfileSHA256: stage2aReservationSHA256(ancillaryRaw),
		BodyProfile:            p.BodyProfile, ClientKeySHA256: p.ClientKeySHA256,
		AKeyID: q.AKeyID, InstallationID: installationID, ExpiresAt: q.ExpiresAt,
		QPlanDigest: qDigest, QApprovalReference: approval,
	}, nil
}

func parseStage2aLocalTestInstallReceipt(raw json.RawMessage) (stage2aLocalTestInstallReceipt, error) {
	var r stage2aLocalTestInstallReceipt
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &r) != nil || r.Schema != stage2aLocalTestInstallReceiptSchema {
		return stage2aLocalTestInstallReceipt{}, errStage2aReservationAuthority
	}
	return r, nil
}
