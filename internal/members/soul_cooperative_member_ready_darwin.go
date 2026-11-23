//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

type soulCooperativeReadyPayloadV3 struct {
	Contract                       string                           `json:"contract"`
	Kind                           string                           `json:"kind"`
	SchemaVersion                  int                              `json:"schema_version"`
	ProfileInForce                 string                           `json:"profile_in_force"`
	HostID                         string                           `json:"host_id"`
	InstallationID                 string                           `json:"installation_id"`
	StartID                        string                           `json:"start_id"`
	HQEpoch                        string                           `json:"hq_epoch"`
	ReservationSHA256              string                           `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256       string                           `json:"assignment_envelope_sha256"`
	ChildObservationEnvelopeSHA256 string                           `json:"child_observation_envelope_sha256"`
	ProvisionalHQMappingSHA256     string                           `json:"provisional_hq_mapping_sha256"`
	MemberBAuthorityEnvelopeSHA256 string                           `json:"member_b_authority_envelope_sha256"`
	BridgeObservedSHA256           string                           `json:"bridge_observed_sha256"`
	Members                        [2]stage2aCooperativeReadyMember `json:"members"`
	IssuedAt                       string                           `json:"issued_at"`
	ExpiresAt                      string                           `json:"expires_at"`
}

// CooperativeMemberReady is the only aggregate A grant for the two stock
// children. B's two same-bound arm requests remain pending until this exact
// A signature is delivered; no future CLI peer is authorized here.
func (s *Stage2aService) CooperativeMemberReady(hqUID int, epoch string,
	q SoulCooperativeMemberReadyRequestV3,
	paired func(string, func() error) error) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if paired == nil || len(s.key) != ed25519.PrivateKeySize || q.HQEpoch != epoch ||
		len(q.Arms) != 2 {
		return reply, errSoulCooperativeAuthority
	}
	live := s.cooperativeActive[q.ReservationSHA256]
	if live == nil || !live.attached || len(live.memberReadyEnvelope) != 0 ||
		len(live.childObservationEnvelope) == 0 || len(live.childGrants) != 2 ||
		len(live.provisionalHQMap) == 0 || len(live.memberBAuthorityEnvelope) == 0 ||
		q.ChildObservationEnvelopeSHA256 != stage2aReservationSHA256(live.childObservationEnvelope) ||
		q.MemberBAuthorityEnvelopeSHA256 != stage2aReservationSHA256(live.memberBAuthorityEnvelope) ||
		q.BridgeObservedSHA256 != stage2aReservationSHA256(live.bridgeObservedEnvelope) ||
		live.installed.Policy.HQUID != hqUID || live.request.InstallationID != q.InstallationID ||
		live.request.StartID != q.StartID || live.request.LaunchID != q.LaunchID ||
		live.request.PlanDigest != q.PlanDigest || live.request.HQEpoch != epoch {
		return reply, errSoulCooperativeAuthority
	}
	var ran bool
	err := paired(live.installed.PairCommitment, func() error {
		if ran {
			return errSoulCooperativeAuthority
		}
		ran = true
		pub := s.key.Public().(ed25519.PublicKey)
		installed, r, err := loadSoulCooperativeInstalledV3(pub, hqUID, epoch, q.InstallationID)
		if err != nil || !bytes.Equal(installed.RootReceipt, live.installed.RootReceipt) ||
			stage2aRecheckVerifiedDomainV3(r) != nil ||
			stage2aRecheckVerifiedDomainV3(live.h) != nil ||
			!cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		paths, err := cooperativeLaunchPaths(q.InstallationID)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		pid, err := observeSoulCooperativeLaunchdPID(paths, q.InstallationID)
		if err != nil || pid != live.dispatcherPID {
			return errSoulCooperativeAuthority
		}
		dispatcher, e1 := observeSoulKernelProcess(live.dispatcherPID)
		runner, e2 := observeSoulKernelProcess(live.runnerPID)
		if e1 != nil || e2 != nil || !sameSoulKernelProcess(live.dispatcher, dispatcher) ||
			!sameSoulKernelProcess(live.runner, runner) ||
			!cooperativeProcessPair(installed.Policy, dispatcher, runner) {
			return errSoulCooperativeAuthority
		}
		assignmentRaw, err := verifyStage2aStoredARecordV3(live.memberEnvelope,
			stage2aMemberSetAssignmentPurpose, 1, pub)
		var assignment soulCooperativeMemberSetAssignmentV3
		observationRaw, obsErr := verifyStage2aStoredARecordV3(live.childObservationEnvelope,
			Stage2aMemberChildObservationPurpose, 1, pub)
		var observation stage2aMemberChildObservationPayload
		if err != nil || obsErr != nil ||
			stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
			stage2aDecodeExact(observationRaw, &observation) != nil ||
			assignment.ProfileInForce != "managed-cooperative" ||
			observation.ProfileInForce != "managed-cooperative" ||
			assignment.ReservationSHA256 != live.digest ||
			observation.ReservationSHA256 != live.digest ||
			observation.AssignmentEnvelopeSHA256 != live.memberSHA ||
			observation.ProvisionalHQMappingSHA256 != live.provisionalHQMapSHA256 ||
			!bytes.Equal(observation.ProvisionalHQMapping, live.provisionalHQMap) {
			return errSoulCooperativeAuthority
		}
		mapQ := Stage2aMemberProvisionalMapRequest{Stage2aStopRequest: q.Stage2aStopRequest,
			ProvisionalHQMappingBase64URL: base64.RawURLEncoding.EncodeToString(live.provisionalHQMap),
			ProvisionalHQMappingSHA256:    live.provisionalHQMapSHA256}
		_, mapping, err := decodeSoulCooperativeProvisionalMap(mapQ)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		selectorsRaw, err := marshalStage2aReservationJCS([]string{
			assignment.Members[0].MemberSelector, assignment.Members[1].MemberSelector})
		if err != nil {
			return errSoulCooperativeAuthority
		}
		selectors := stage2aNativeMemberSelectors{
			InstallationID: assignment.InstallationID, StartID: assignment.StartID,
			PlanID: assignment.PlanID, PlanDigest: assignment.PlanDigest,
			ReservationDigest: live.digest, AssignmentEnvelopeSHA256: live.memberSHA,
			AuthorityEnvelopeSHA256: q.MemberBAuthorityEnvelopeSHA256,
			MemberSelectorsSHA256:   stage2aReservationSHA256(selectorsRaw)}
		now := time.Now().UTC()
		observedAt, e3 := time.Parse(time.RFC3339Nano, observation.ObservedAt)
		obsExpires, e4 := time.Parse(time.RFC3339Nano, observation.ExpiresAt)
		mapExpires, e5 := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
		assignmentExpires, e6 := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
		if e3 != nil || e4 != nil || e5 != nil || e6 != nil ||
			!now.Before(obsExpires) || !now.Before(mapExpires) ||
			!now.Before(assignmentExpires) {
			return errSoulCooperativeAuthority
		}
		ready := soulCooperativeReadyPayloadV3{Contract: "machine/v3",
			Kind: "soul-cooperative-member-ready", SchemaVersion: 3,
			ProfileInForce: "managed-cooperative", HostID: installed.Policy.HostID,
			InstallationID: q.InstallationID, StartID: q.StartID, HQEpoch: epoch,
			ReservationSHA256: live.digest, AssignmentEnvelopeSHA256: live.memberSHA,
			ChildObservationEnvelopeSHA256: q.ChildObservationEnvelopeSHA256,
			ProvisionalHQMappingSHA256:     live.provisionalHQMapSHA256,
			MemberBAuthorityEnvelopeSHA256: q.MemberBAuthorityEnvelopeSHA256,
			BridgeObservedSHA256:           q.BridgeObservedSHA256,
			IssuedAt:                       now.Format(time.RFC3339Nano)}
		seenObserve, seenArm := make(map[string]bool), make(map[string]bool)
		until := minStage2aTime(now.Add(20*time.Second), obsExpires)
		until = minStage2aTime(until, mapExpires)
		until = minStage2aTime(until, assignmentExpires)
		for i, exchange := range q.Arms {
			member := assignment.Members[i]
			state := live.childGrants[member.MemberID]
			if state == nil || state.childPID <= 1 || state.hObservationSHA == "" ||
				state.memberLaunchID != member.LaunchID ||
				state.memberSelector != member.MemberSelector ||
				observation.Members[i].GrantSHA256 != state.grantSHA ||
				observation.Members[i].ChildProcess.PID != state.childPID ||
				mapping.Members[i].MemberID != member.MemberID ||
				mapping.Members[i].MemberSelector != member.MemberSelector {
				return errSoulCooperativeAuthority
			}
			launcher, err := observeStage2aRoleProcess(state.launcherPID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, childErr := observeStage2aChildProcess(state.childPID, state.launcherPID,
				installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if err != nil || childErr != nil ||
				!sameSoulKernelProcess(state.launcher, launcher) ||
				!sameSoulKernelProcess(state.child, child) ||
				observation.Members[i].LauncherProcess != stage2aMemberLauncherIdentity(launcher) ||
				observation.Members[i].ChildProcess != stage2aMemberProcessIdentity(child,
					member.CommandSHA256) {
				return errSoulCooperativeAuthority
			}
			armSHA, ackExpires, err := verifySoulCooperativeArmExchangeV3(exchange,
				selectors, member.MemberID, member.MemberSelector, mapping.Members[i].RuntimeID,
				q.ChildObservationEnvelopeSHA256, child, installed.Policy.Bridge.UID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, observedAt, now)
			if err != nil || !now.Before(ackExpires) {
				return errSoulCooperativeAuthority
			}
			var request soulCooperativeArmWireRequestV3
			if stage2aDecodeExact(exchange.ArmRequest, &request) != nil ||
				seenObserve[request.ObserveNonce] || seenArm[request.ArmNonce] {
				return errSoulCooperativeAuthority
			}
			seenObserve[request.ObserveNonce] = true
			seenArm[request.ArmNonce] = true
			until = minStage2aTime(until, ackExpires)
			ready.Members[i] = stage2aCooperativeReadyMember{
				MemberID: member.MemberID, MemberLaunchID: member.LaunchID,
				MemberSelector: member.MemberSelector, GrantSHA256: state.grantSHA,
				LauncherProcess:    stage2aMemberLauncherIdentity(launcher),
				ChildProcess:       stage2aMemberProcessIdentity(child, member.CommandSHA256),
				HObservationSHA256: state.hObservationSHA, BArmReceiptSHA256: armSHA}
		}
		if !until.After(now) {
			return errSoulCooperativeAuthority
		}
		ready.ExpiresAt = until.Format(time.RFC3339Nano)
		store := installed.claimStore()
		dir, err := store.open()
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer dir.Close()
		lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
		if err != nil {
			return errSoulCooperativeAuthority
		}
		defer lock.Close()
		name := ".cooperative-member-ready-" + soulStartClaimName(q.InstallationID, q.StartID)
		if store.checkDirectory(dir) != nil ||
			cooperativeActiveClaimMatches(dir, store, q.InstallationID, q.StartID) != nil ||
			requireUnspentStage2aReservation(dir, name) != nil ||
			spendStage2aAdminName(dir, name, store.uid, store.gid) != nil {
			return errSoulCooperativeAuthority
		}
		envelope, err := signStage2aEnvelope(ready, 3,
			stage2aCooperativeReadyPurpose, pub, s.sign)
		if err != nil || len(envelope) == 0 || len(envelope) > 16<<10 ||
			!time.Now().Before(until) || !cooperativeObservedBStillLive(live, installed) {
			return errSoulCooperativeAuthority
		}
		for i := range ready.Members {
			state := live.childGrants[ready.Members[i].MemberID]
			launcher, e1 := observeStage2aRoleProcess(state.launcherPID,
				installed.Policy.Runner.UID, installed.Policy.Runner.GID, "child")
			child, e2 := observeStage2aChildProcess(state.childPID, state.launcherPID,
				installed.Policy.Runner, *installed.Policy.LaunchInputs)
			if e1 != nil || e2 != nil || !sameSoulKernelProcess(state.launcher, launcher) ||
				!sameSoulKernelProcess(state.child, child) {
				return errSoulCooperativeAuthority
			}
		}
		live.memberReadyEnvelope = envelope
		live.memberReadyExpires = until
		reply = Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
			SHA256: stage2aReservationSHA256(envelope)}
		return nil
	})
	if err != nil || !ran || reply.SHA256 == "" {
		return Stage2aHelloReply{}, errSoulCooperativeAuthority
	}
	return reply, nil
}
