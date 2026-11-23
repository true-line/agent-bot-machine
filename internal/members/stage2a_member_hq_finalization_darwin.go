//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type stage2aMemberHQFinalizationRow struct {
	MemberID               string                               `json:"member_id"`
	MemberSelector         string                               `json:"member_selector"`
	MemberLaunchID         string                               `json:"member_launch_id"`
	RuntimeID              string                               `json:"runtime_id"`
	GrantSHA256            string                               `json:"grant_sha256"`
	BridgeArmReceiptSHA256 string                               `json:"bridge_arm_receipt_sha256"`
	LauncherProcess        stage2aMemberObservedLauncherProcess `json:"launcher_process"`
	ChildProcess           stage2aMemberObservedProcess         `json:"child_process"`
}

type stage2aMemberHQFinalizationRecord struct {
	Schema         string `json:"schema"`
	ProfileInForce string `json:"profile_in_force"`
	HostID         string `json:"host_id"`
	Stage2aStopRequest
	SoulID                         string                            `json:"soul_id"`
	AssignmentEnvelopeSHA256       string                            `json:"assignment_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string                            `json:"child_observation_envelope_sha256"`
	ReadyEnvelopeSHA256            string                            `json:"ready_envelope_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                            `json:"member_b_authority_envelope_sha256"`
	ProvisionalHQMappingSHA256     string                            `json:"provisional_hq_mapping_sha256"`
	BindReceiptSHA256              string                            `json:"bind_receipt_sha256"`
	Members                        [2]stage2aMemberHQFinalizationRow `json:"members"`
	CommittedAt                    string                            `json:"committed_at"`
}

type stage2aMemberHQFinalizationAckPayload struct {
	Contract                       string `json:"contract"`
	Kind                           string `json:"kind"`
	SchemaVersion                  int    `json:"schema_version"`
	ProfileInForce                 string `json:"profile_in_force"`
	HostID                         string `json:"host_id"`
	InstallationID                 string `json:"installation_id"`
	SoulID                         string `json:"soul_id"`
	StartID                        string `json:"start_id"`
	LaunchID                       string `json:"launch_id"`
	PlanID                         string `json:"plan_id"`
	PlanDigest                     string `json:"plan_digest"`
	HQEpoch                        string `json:"hq_epoch"`
	ReservationSHA256              string `json:"reservation_sha256"`
	HQFinalizationSHA256           string `json:"hq_finalization_sha256"`
	ReadyEnvelopeSHA256            string `json:"ready_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string `json:"child_observation_envelope_sha256"`
	IssuedAt                       string `json:"issued_at"`
}

// MemberHQFinalization accepts only a canonical H record already durably
// committed by paired H. A checks its own exact Ready/observation/assignment,
// both kernel children and all retained protected peers before acknowledging.
// The ack is not a substitute for H's own fsync/readback or B ingress proof.
func (s *Stage2aService) MemberHQFinalization(hqUID int, epoch string,
	q Stage2aMemberHQFinalizationRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.hello == nil || r.hello.aborted || r.protectedQ == nil ||
		r.twoMemberChildren == nil || len(r.memberChildGrants) != 2 ||
		len(r.memberHQFinalizationRaw) != 0 ||
		len(r.memberReadyEnvelope) == 0 || len(r.memberSetAssignmentEnvelope) == 0 ||
		len(r.memberChildObservationEnvelope) == 0 || len(r.memberBAuthorityEnvelope) == 0 ||
		len(r.provisionalHQMap) == 0 || r.bindReceiptSHA256 == "" {
		return reply, errStage2aReservationAuthority
	}
	raw, err := stage2aDecodeHQFinalizationRecord(q.FinalizationBase64URL,
		q.FinalizationSHA256)
	var h stage2aMemberHQFinalizationRecord
	if err != nil || stage2aDecodeExact(raw, &h) != nil ||
		h.Schema != "agent-bot-hq/stage2a-member-finalization/v1" ||
		h.ProfileInForce != "managed-protected" ||
		h.Stage2aStopRequest != q.Stage2aStopRequest ||
		h.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) ||
		h.ChildObservationEnvelopeSHA256 != stage2aReservationSHA256(r.memberChildObservationEnvelope) ||
		h.ReadyEnvelopeSHA256 != stage2aReservationSHA256(r.memberReadyEnvelope) ||
		h.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(r.memberBAuthorityEnvelope) ||
		h.ProvisionalHQMappingSHA256 != r.provisionalHQMapSHA256 ||
		h.BindReceiptSHA256 != r.bindReceiptSHA256 ||
		h.Members[0].MemberID >= h.Members[1].MemberID {
		return reply, errStage2aReservationAuthority
	}
	committedAt, committedErr := time.Parse(time.RFC3339Nano, h.CommittedAt)
	if committedErr != nil || committedAt.After(time.Now()) {
		return reply, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(h)
	if err != nil || !bytes.Equal(raw, canonical) {
		return reply, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	p, policyRaw, err := loadStage2aActiveExecutionPolicy(key, hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(policyRaw) != r.policyDigest ||
		p.Binding.ProfileInForce != "managed-protected" ||
		h.HostID != p.Binding.HostID || h.SoulID != p.Binding.SoulID ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.protectedQ.recheckMemberQ() != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	readyRaw, err := verifyStage2aStoredARecordV3(r.memberReadyEnvelope,
		Stage2aMemberReadyPurpose, 1, key)
	var ready stage2aMemberReadyPayload
	if err != nil || stage2aDecodeExact(readyRaw, &ready) != nil ||
		ready.Contract != "machine/v3" || ready.Kind != "stage2a-member-set-ready" ||
		ready.SchemaVersion != 1 || ready.ProfileInForce != "managed-protected" ||
		ready.HostID != p.Binding.HostID || ready.InstallationID != q.InstallationID ||
		ready.SoulID != h.SoulID || ready.StartID != q.StartID ||
		ready.HQEpoch != epoch || ready.ReservationSHA256 != r.digest ||
		ready.AssignmentEnvelopeSHA256 != h.AssignmentEnvelopeSHA256 ||
		ready.ChildObservationEnvelopeSHA256 != h.ChildObservationEnvelopeSHA256 ||
		ready.MemberBAuthorityEnvelopeSHA256 != h.MemberBAuthorityEnvelopeSHA256 ||
		ready.ProvisionalHQMappingSHA256 != h.ProvisionalHQMappingSHA256 {
		return reply, errStage2aReservationAuthority
	}
	readyExpiry, readyErr := time.Parse(time.RFC3339Nano, ready.ExpiresAt)
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if readyErr != nil || approvalErr != nil || !readyExpiry.Equal(r.memberReadyExpires) ||
		committedAt.After(readyExpiry) ||
		!time.Now().Before(readyExpiry) || !time.Now().Before(approvedUntil) {
		return reply, errStage2aReservationAuthority
	}
	observationRaw, err := verifyStage2aStoredARecordV3(r.memberChildObservationEnvelope,
		Stage2aMemberChildObservationPurpose, 1, key)
	var observation stage2aMemberChildObservationPayload
	if err != nil || stage2aDecodeExact(observationRaw, &observation) != nil ||
		observation.Contract != "machine/v3" ||
		observation.Kind != "stage2a-member-set-child-observation" ||
		observation.SchemaVersion != 1 ||
		observation.ProfileInForce != "managed-protected" ||
		observation.HostID != h.HostID ||
		observation.InstallationID != q.InstallationID ||
		observation.SoulID != h.SoulID || observation.StartID != q.StartID ||
		observation.HQEpoch != epoch || observation.ReservationSHA256 != r.digest ||
		observation.AssignmentEnvelopeSHA256 != h.AssignmentEnvelopeSHA256 ||
		observation.ProvisionalHQMappingSHA256 != h.ProvisionalHQMappingSHA256 {
		return reply, errStage2aReservationAuthority
	}
	assignmentRaw, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.Contract != "machine/v3" ||
		assignment.Kind != "stage2a-member-set-assignment" ||
		assignment.SchemaVersion != 1 ||
		assignment.ProfileInForce != "managed-protected" ||
		assignment.HostID != h.HostID || assignment.InstallationID != q.InstallationID ||
		assignment.SoulID != h.SoulID || assignment.StartID != q.StartID ||
		assignment.HQEpoch != epoch || assignment.ReservationSHA256 != r.digest ||
		assignment.PlanID != q.PlanID || assignment.PlanDigest != q.PlanDigest {
		return reply, errStage2aReservationAuthority
	}
	bAuthorityRaw, err := verifyStage2aStoredARecordV3(r.memberBAuthorityEnvelope,
		stage2aBMemberAuthorityPurpose, 1, key)
	var bAuthority stage2aBMemberAuthorityPayload
	if err != nil || stage2aDecodeExact(bAuthorityRaw, &bAuthority) != nil ||
		bAuthority.Contract != "machine/v3" ||
		bAuthority.Kind != "stage2a-b-member-authority" ||
		bAuthority.SchemaVersion != 1 ||
		bAuthority.ProfileInForce != "managed-protected" ||
		bAuthority.HostID != h.HostID || bAuthority.InstallationID != q.InstallationID ||
		bAuthority.SoulID != h.SoulID || bAuthority.StartID != q.StartID ||
		bAuthority.HQEpoch != epoch || bAuthority.ReservationSHA256 != r.digest ||
		bAuthority.PlanID != q.PlanID || bAuthority.PlanDigest != q.PlanDigest ||
		bAuthority.MemberSetAssignmentEnvelopeSHA256 != h.AssignmentEnvelopeSHA256 {
		return reply, errStage2aReservationAuthority
	}
	if stage2aReservationSHA256(r.provisionalHQMap) != r.provisionalHQMapSHA256 ||
		stage2aStrictJSON(r.provisionalHQMap) != nil {
		return reply, errStage2aReservationAuthority
	}
	for i, row := range h.Members {
		grant := r.memberChildGrants[row.MemberID]
		if row.MemberID != ready.Members[i].MemberID ||
			row.MemberID != assignment.Members[i].MemberID ||
			row.MemberID != bAuthority.Members[i].MemberID ||
			row.MemberID != observation.Members[i].MemberID ||
			row.MemberID != r.twoMemberChildren.Members[i].MemberID ||
			row.MemberSelector != ready.Members[i].MemberSelector ||
			row.MemberSelector != assignment.Members[i].MemberSelector ||
			row.MemberSelector != bAuthority.Members[i].MemberSelector ||
			row.MemberSelector != observation.Members[i].MemberSelector ||
			row.MemberSelector != grant.MemberSelector ||
			row.MemberLaunchID != ready.Members[i].LaunchID ||
			row.MemberLaunchID != assignment.Members[i].LaunchID ||
			row.MemberLaunchID != bAuthority.Members[i].LaunchID ||
			row.MemberLaunchID != observation.Members[i].LaunchID ||
			row.MemberLaunchID != grant.MemberLaunchID ||
			row.RuntimeID != ready.Members[i].RuntimeID ||
			row.RuntimeID != observation.Members[i].RuntimeID ||
			row.GrantSHA256 != observation.Members[i].GrantSHA256 ||
			row.GrantSHA256 != grant.GrantSHA256 ||
			row.BridgeArmReceiptSHA256 != ready.Members[i].BridgeArmReceiptSHA256 ||
			row.LauncherProcess != observation.Members[i].LauncherProcess ||
			row.ChildProcess != observation.Members[i].ChildProcess {
			return reply, errStage2aReservationAuthority
		}
	}
	checkChildren := func() error {
		return r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		})
	}
	if checkChildren() != nil {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	ack := stage2aMemberHQFinalizationAckPayload{Contract: "machine/v3",
		Kind: "stage2a-member-finalization-ack", SchemaVersion: 1,
		ProfileInForce: "managed-protected", HostID: p.Binding.HostID,
		InstallationID: q.InstallationID, SoulID: h.SoulID,
		StartID: q.StartID, LaunchID: q.LaunchID, PlanID: q.PlanID,
		PlanDigest: q.PlanDigest, HQEpoch: epoch, ReservationSHA256: r.digest,
		HQFinalizationSHA256:           q.FinalizationSHA256,
		ReadyEnvelopeSHA256:            h.ReadyEnvelopeSHA256,
		ChildObservationEnvelopeSHA256: h.ChildObservationEnvelopeSHA256,
		IssuedAt:                       now.UTC().Format(time.RFC3339Nano)}
	envelope, err := signStage2aEnvelope(ack, 1,
		Stage2aMemberHQFinalizationAckPurpose, key, s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 ||
		!time.Now().Before(readyExpiry) || !time.Now().Before(approvedUntil) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.protectedQ.recheckMemberQ() != nil || checkChildren() != nil {
		return reply, errStage2aReservationAuthority
	}
	r.memberHQFinalizationRaw = bytes.Clone(raw)
	r.memberHQFinalizationSHA256 = q.FinalizationSHA256
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}
