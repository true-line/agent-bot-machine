//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"time"
)

type stage2aMemberBridgeArm struct {
	MemberID                       string `json:"member_id"`
	MemberSelector                 string `json:"member_selector"`
	RuntimeID                      string `json:"runtime_id"`
	ChildObservationEnvelopeSHA256 string `json:"child_observation_envelope_sha256"`
	BridgeUID                      int    `json:"bridge_uid"`
	AdapterPID                     int    `json:"adapter_pid"`
	AdapterUID                     int    `json:"adapter_uid"`
	AdapterGID                     int    `json:"adapter_gid"`
	AdapterStartSeconds            int64  `json:"adapter_start_seconds"`
	AdapterStartMicros             int32  `json:"adapter_start_micros"`
	RelayPeerRule                  string `json:"relay_peer_rule"`
	RelayPeerState                 string `json:"relay_peer_state"`
	ProviderIngress                string `json:"provider_ingress"`
	State                          string `json:"state"`
	ArmedAt                        string `json:"armed_at"`
}

type stage2aMemberArmWireRequest struct {
	Kind                           string                       `json:"kind"`
	Selectors                      stage2aNativeMemberSelectors `json:"selectors"`
	MemberID                       string                       `json:"member_id"`
	MemberSelector                 string                       `json:"member_selector"`
	ObserveNonce                   string                       `json:"observe_nonce"`
	ArmNonce                       string                       `json:"arm_nonce"`
	ChildObservationEnvelopeSHA256 string                       `json:"child_observation_envelope_sha256"`
	BridgeArm                      stage2aMemberBridgeArm       `json:"bridge_arm"`
	BridgeArmReceiptSHA256         string                       `json:"bridge_arm_receipt_sha256"`
}

type stage2aMemberArmWireResult struct {
	Kind                   string `json:"kind"`
	MemberID               string `json:"member_id"`
	MemberSelector         string `json:"member_selector"`
	ArmNonce               string `json:"arm_nonce"`
	BridgeArmReceiptSHA256 string `json:"bridge_arm_receipt_sha256"`
	State                  string `json:"state"`
	ExpiresAt              string `json:"expires_at"`
}

type stage2aMemberReadyPayload struct {
	Contract                       string `json:"contract"`
	Kind                           string `json:"kind"`
	SchemaVersion                  int    `json:"schema_version"`
	ProfileInForce                 string `json:"profile_in_force"`
	HostID                         string `json:"host_id"`
	InstallationID                 string `json:"installation_id"`
	SoulID                         string `json:"soul_id"`
	StartID                        string `json:"start_id"`
	HQEpoch                        string `json:"hq_epoch"`
	ReservationSHA256              string `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256       string `json:"assignment_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string `json:"child_observation_envelope_sha256"`
	BAuthoritySHA256               string `json:"b_authority_sha256"`
	MemberBAuthorityEnvelopeSHA256 string `json:"member_b_authority_envelope_sha256"`
	ProvisionalHQMappingSHA256     string `json:"provisional_hq_mapping_sha256"`
	BridgeProcess                  struct {
		PID              int    `json:"pid"`
		UID              int    `json:"uid"`
		GID              int    `json:"gid"`
		StartSeconds     int64  `json:"start_seconds"`
		StartMicros      int32  `json:"start_micros"`
		ExecutableSHA256 string `json:"executable_sha256"`
	} `json:"bridge_process"`
	Members [2]struct {
		MemberID               string                 `json:"member_id"`
		LaunchID               string                 `json:"launch_id"`
		MemberSelector         string                 `json:"member_selector"`
		RuntimeID              string                 `json:"runtime_id"`
		BridgeArm              stage2aMemberBridgeArm `json:"bridge_arm"`
		BridgeArmReceiptSHA256 string                 `json:"bridge_arm_receipt_sha256"`
	} `json:"members"`
	ObservedAt string `json:"observed_at"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
}

func stage2aVerifyMemberArmExchange(pair Stage2aMemberArmExchange,
	selectors stage2aNativeMemberSelectors, memberID, memberSelector, runtimeID,
	observationSHA256 string, child soulKernelProcessSnapshot, bridgeUID, runnerUID,
	runnerGID int, observedAt, now time.Time) (stage2aMemberArmWireRequest, time.Time, error) {
	var request stage2aMemberArmWireRequest
	var result stage2aMemberArmWireResult
	if stage2aDecodeExact(pair.ArmRequest, &request) != nil ||
		stage2aDecodeExact(pair.ArmResult, &result) != nil ||
		request.Kind != "bridge.member.arm.v3.request" ||
		result.Kind != "bridge.member.arm.v3.result" ||
		request.Selectors != selectors || request.MemberID != memberID ||
		request.MemberSelector != memberSelector ||
		request.ChildObservationEnvelopeSHA256 != observationSHA256 ||
		!stage2aLowerHex64(request.ObserveNonce) || !stage2aLowerHex64(request.ArmNonce) ||
		result.MemberID != request.MemberID || result.MemberSelector != request.MemberSelector ||
		result.ArmNonce != request.ArmNonce ||
		result.BridgeArmReceiptSHA256 != request.BridgeArmReceiptSHA256 ||
		result.State != "recorded-pending-aggregate-ready" {
		return stage2aMemberArmWireRequest{}, time.Time{}, errStage2aReservationAuthority
	}
	arm := request.BridgeArm
	if arm.MemberID != memberID || arm.MemberSelector != memberSelector ||
		arm.RuntimeID != runtimeID ||
		arm.ChildObservationEnvelopeSHA256 != observationSHA256 ||
		arm.BridgeUID != bridgeUID || arm.AdapterPID != child.PID ||
		arm.AdapterUID != runnerUID || arm.AdapterGID != runnerGID ||
		arm.AdapterStartSeconds != child.StartSeconds ||
		arm.AdapterStartMicros != child.StartMicros ||
		arm.RelayPeerRule != "a-attested-live-direct-child-of-adapter-v1" ||
		arm.RelayPeerState != "unobserved" ||
		arm.ProviderIngress != "withheld-pending-per-peer-attestation" ||
		arm.State != "armed" {
		return stage2aMemberArmWireRequest{}, time.Time{}, errStage2aReservationAuthority
	}
	armRaw, err := marshalStage2aReservationJCS(arm)
	armed, armErr := time.Parse(time.RFC3339Nano, arm.ArmedAt)
	ackExpires, ackErr := time.Parse(time.RFC3339Nano, result.ExpiresAt)
	if err != nil || stage2aReservationSHA256(armRaw) != request.BridgeArmReceiptSHA256 ||
		armErr != nil || ackErr != nil || armed.After(now) || armed.Before(observedAt) ||
		armed.Before(time.Unix(0, 0)) || !now.Before(ackExpires) {
		return stage2aMemberArmWireRequest{}, time.Time{}, errStage2aReservationAuthority
	}
	return request, ackExpires, nil
}

// MemberReady only records H's two B-origin arm requests, paired with H's
// pending acknowledgments on the existing authenticated broker stream. A
// verifies every arm against its own observed children and signed B policy;
// the signed aggregate does not claim a future CLI peer or provider ingress.
func (s *Stage2aService) MemberReady(hqUID int, epoch string,
	q Stage2aMemberReadyRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize || len(q.Arms) != 2 {
		return reply, errStage2aReservationAuthority
	}
	r, p, reservationExpires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.memberReadyEnvelope) != 0 || len(r.memberChildObservationEnvelope) == 0 ||
		len(r.memberBAuthorityEnvelope) == 0 || r.twoMemberChildren == nil ||
		len(r.memberChildGrants) != 2 || r.hello == nil || r.hello.aborted || r.hello.finalized ||
		r.protectedQ.recheckMemberQ() != nil ||
		q.ChildObservationEnvelopeSHA256 != stage2aReservationSHA256(r.memberChildObservationEnvelope) ||
		q.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(r.memberBAuthorityEnvelope) ||
		!stage2aPrefixedDigest.MatchString(p.LaunchInputs.ComponentDigests["bridge"]) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	assignmentRaw, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.ReservationSHA256 != r.digest ||
		assignment.InstallationID != q.InstallationID || assignment.StartID != q.StartID ||
		assignment.HQEpoch != epoch || assignment.ProfileInForce != "managed-protected" ||
		p.Binding.ProfileInForce != assignment.ProfileInForce ||
		assignment.HostID != p.Binding.HostID || assignment.SoulID != p.Binding.SoulID {
		return reply, errStage2aReservationAuthority
	}
	observationRaw, err := verifyStage2aStoredARecordV3(r.memberChildObservationEnvelope,
		Stage2aMemberChildObservationPurpose, 1, key)
	var observation stage2aMemberChildObservationPayload
	if err != nil || stage2aDecodeExact(observationRaw, &observation) != nil ||
		observation.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) ||
		observation.ProvisionalHQMappingSHA256 != r.provisionalHQMapSHA256 ||
		observation.ReservationSHA256 != r.digest || observation.ProfileInForce != assignment.ProfileInForce ||
		observation.HostID != assignment.HostID || observation.SoulID != assignment.SoulID ||
		!reflect.DeepEqual([]byte(observation.ProvisionalHQMapping), r.provisionalHQMap) {
		return reply, errStage2aReservationAuthority
	}
	bRaw, err := verifyStage2aStoredARecordV3(r.memberBAuthorityEnvelope,
		stage2aBMemberAuthorityPurpose, 1, key)
	var bAuthority stage2aBMemberAuthorityPayload
	if err != nil || stage2aDecodeExact(bRaw, &bAuthority) != nil ||
		bAuthority.ReservationSHA256 != r.digest ||
		bAuthority.MemberSetAssignmentEnvelopeSHA256 != observation.AssignmentEnvelopeSHA256 ||
		bAuthority.ProfileInForce != "managed-protected" ||
		bAuthority.HostID != assignment.HostID || bAuthority.SoulID != assignment.SoulID ||
		bAuthority.InstallationID != assignment.InstallationID ||
		bAuthority.StartID != assignment.StartID || bAuthority.HQEpoch != assignment.HQEpoch ||
		bAuthority.PlanID != assignment.PlanID || bAuthority.PlanDigest != assignment.PlanDigest ||
		bAuthority.OwnerPlanMemberSetSHA256 != assignment.OwnerPlanMemberSetSHA256 ||
		bAuthority.BAuthority != assignment.BAuthority ||
		bAuthority.HQUID != hqUID || bAuthority.RunnerUID != p.Runner.UID {
		return reply, errStage2aReservationAuthority
	}
	bridgeRaw, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil || !reflect.DeepEqual([]byte(bAuthority.Bridge), bridgeRaw) {
		return reply, errStage2aReservationAuthority
	}
	selectorBytes, err := marshalStage2aReservationJCS([]string{
		assignment.Members[0].MemberSelector, assignment.Members[1].MemberSelector})
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	expectedSelectors := stage2aNativeMemberSelectors{InstallationID: q.InstallationID,
		StartID: q.StartID, PlanID: assignment.PlanID, PlanDigest: assignment.PlanDigest,
		ReservationDigest:        r.digest,
		AssignmentEnvelopeSHA256: stage2aReservationSHA256(r.memberSetAssignmentEnvelope),
		AuthorityEnvelopeSHA256:  stage2aReservationSHA256(r.memberBAuthorityEnvelope),
		MemberSelectorsSHA256:    stage2aReservationSHA256(selectorBytes)}
	now := time.Now()
	mapExpires, mapErr := time.Parse(time.RFC3339Nano, observation.ExpiresAt)
	observedAt, observedErr := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	bExpires, bErr := time.Parse(time.RFC3339Nano, bAuthority.ExpiresAt)
	if mapErr != nil || observedErr != nil || bErr != nil ||
		!now.Before(mapExpires) || !now.Before(bExpires) ||
		!now.Before(r.memberSetAssignmentExpires) ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	ready := stage2aMemberReadyPayload{Contract: "machine/v3", Kind: "stage2a-member-set-ready",
		SchemaVersion: 1, ProfileInForce: "managed-protected", HostID: p.Binding.HostID,
		InstallationID: q.InstallationID, SoulID: p.Binding.SoulID,
		StartID: q.StartID, HQEpoch: epoch, ReservationSHA256: r.digest,
		AssignmentEnvelopeSHA256:       stage2aReservationSHA256(r.memberSetAssignmentEnvelope),
		ChildObservationEnvelopeSHA256: q.ChildObservationEnvelopeSHA256,
		BAuthoritySHA256:               assignment.BAuthority.EnvelopeSHA256,
		MemberBAuthorityEnvelopeSHA256: q.MemberBAuthorityEnvelopeSHA256,
		ProvisionalHQMappingSHA256:     observation.ProvisionalHQMappingSHA256,
		ObservedAt:                     now.UTC().Format(time.RFC3339Nano),
		IssuedAt:                       now.UTC().Format(time.RFC3339Nano)}
	ready.BridgeProcess.PID = r.bridgeProcess.PID
	ready.BridgeProcess.UID = int(r.bridgeProcess.EffectiveUID)
	ready.BridgeProcess.GID = int(r.bridgeProcess.PrimaryGroupGID)
	ready.BridgeProcess.StartSeconds = r.bridgeProcess.StartSeconds
	ready.BridgeProcess.StartMicros = r.bridgeProcess.StartMicros
	ready.BridgeProcess.ExecutableSHA256 = p.LaunchInputs.ComponentDigests["bridge"]
	until := minStage2aTime(now.Add(5*time.Second), reservationExpires)
	until = minStage2aTime(until, r.memberSetAssignmentExpires)
	until = minStage2aTime(until, r.memberChildObservationExpires)
	until = minStage2aTime(until, bExpires)
	seenObserve, seenArm := map[string]bool{}, map[string]bool{}
	for i, pair := range q.Arms {
		if observation.Members[i].MemberID != assignment.Members[i].MemberID ||
			observation.Members[i].MemberSelector != assignment.Members[i].MemberSelector ||
			observation.Members[i].LaunchID != assignment.Members[i].LaunchID ||
			observation.Members[i].LauncherProcess != stage2aMemberLauncherIdentity(r.twoMemberChildren.Members[i].Launcher) ||
			observation.Members[i].ChildProcess != stage2aMemberProcessIdentity(r.twoMemberChildren.Members[i].Child,
				r.twoMemberChildren.Members[i].CommandSHA256) ||
			observation.Members[i].GrantSHA256 != r.memberChildGrants[assignment.Members[i].MemberID].GrantSHA256 {
			return reply, errStage2aReservationAuthority
		}
		request, ackExpires, err := stage2aVerifyMemberArmExchange(pair, expectedSelectors,
			assignment.Members[i].MemberID, assignment.Members[i].MemberSelector,
			observation.Members[i].RuntimeID, q.ChildObservationEnvelopeSHA256,
			r.twoMemberChildren.Members[i].Child, p.Bridge.UID, p.Runner.UID, p.Runner.GID,
			observedAt, now)
		if err != nil || seenObserve[request.ObserveNonce] || seenArm[request.ArmNonce] ||
			!now.Before(r.memberChildGrants[assignment.Members[i].MemberID].ExpiresAt) {
			return reply, errStage2aReservationAuthority
		}
		seenObserve[request.ObserveNonce], seenArm[request.ArmNonce] = true, true
		arm := request.BridgeArm
		until = minStage2aTime(until, ackExpires)
		until = minStage2aTime(until, r.memberChildGrants[request.MemberID].ExpiresAt)
		ready.Members[i].MemberID = request.MemberID
		ready.Members[i].LaunchID = assignment.Members[i].LaunchID
		ready.Members[i].MemberSelector = request.MemberSelector
		ready.Members[i].RuntimeID = arm.RuntimeID
		ready.Members[i].BridgeArm = arm
		ready.Members[i].BridgeArmReceiptSHA256 = request.BridgeArmReceiptSHA256
	}
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	until = minStage2aTime(until, approvedUntil)
	if approvalErr != nil || !until.After(now) ||
		r.protectedQ.recheckMemberQ() != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	ready.ExpiresAt = until.UTC().Format(time.RFC3339Nano)
	envelope, err := signStage2aEnvelope(ready, 1, Stage2aMemberReadyPurpose, key, s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 16<<10 || !time.Now().Before(until) ||
		r.protectedQ.recheckMemberQ() != nil ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.memberReadyEnvelope, r.memberReadyExpires = envelope, until
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}
