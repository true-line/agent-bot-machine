//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"
)

type stage2aMemberObservedProcess struct {
	PID              int    `json:"pid"`
	UID              int    `json:"uid"`
	GID              int    `json:"gid"`
	ParentPID        int    `json:"parent_pid"`
	ProcessGroupID   int    `json:"process_group_id"`
	StartSeconds     int64  `json:"start_seconds"`
	StartMicros      int32  `json:"start_micros"`
	ExecutableSHA256 string `json:"executable_sha256"`
}

type stage2aMemberObservedLauncherProcess struct {
	PID          int   `json:"pid"`
	UID          int   `json:"uid"`
	GID          int   `json:"gid"`
	StartSeconds int64 `json:"start_seconds"`
	StartMicros  int32 `json:"start_micros"`
}

type stage2aMemberChildObservationPayload struct {
	Contract                   string          `json:"contract"`
	Kind                       string          `json:"kind"`
	SchemaVersion              int             `json:"schema_version"`
	ProfileInForce             string          `json:"profile_in_force"`
	HostID                     string          `json:"host_id"`
	InstallationID             string          `json:"installation_id"`
	SoulID                     string          `json:"soul_id"`
	StartID                    string          `json:"start_id"`
	HQEpoch                    string          `json:"hq_epoch"`
	ReservationSHA256          string          `json:"reservation_sha256"`
	AssignmentEnvelopeSHA256   string          `json:"assignment_envelope_sha256"`
	ProvisionalHQMappingSHA256 string          `json:"provisional_hq_mapping_sha256"`
	ProvisionalHQMapping       json.RawMessage `json:"provisional_hq_mapping"`
	Members                    [2]struct {
		MemberID        string                               `json:"member_id"`
		LaunchID        string                               `json:"launch_id"`
		MemberSelector  string                               `json:"member_selector"`
		RuntimeID       string                               `json:"runtime_id"`
		GrantSHA256     string                               `json:"grant_sha256"`
		LauncherProcess stage2aMemberObservedLauncherProcess `json:"launcher_process"`
		ChildProcess    stage2aMemberObservedProcess         `json:"child_process"`
	} `json:"members"`
	ObservedAt string `json:"observed_at"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
}

func stage2aMemberProcessIdentity(p soulKernelProcessSnapshot, executableSHA256 string) stage2aMemberObservedProcess {
	return stage2aMemberObservedProcess{PID: p.PID, UID: int(p.EffectiveUID), GID: int(p.PrimaryGroupGID),
		ParentPID: p.ParentPID, ProcessGroupID: p.ProcessGroupID,
		StartSeconds: p.StartSeconds, StartMicros: p.StartMicros,
		ExecutableSHA256: executableSHA256}
}

func stage2aMemberLauncherIdentity(p soulKernelProcessSnapshot) stage2aMemberObservedLauncherProcess {
	return stage2aMemberObservedLauncherProcess{PID: p.PID, UID: int(p.EffectiveUID),
		GID: int(p.PrimaryGroupGID), StartSeconds: p.StartSeconds, StartMicros: p.StartMicros}
}

// A signs only after independently sampling both exact granted launcher and
// sandboxed ACP child process pairs twice. H's map remains provisional and
// this observation does not assert that B has armed either relay rule.
func (s *Stage2aService) MemberChildObserve(hqUID int, epoch string,
	q Stage2aMemberChildObservationRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize ||
		len(q.Members) != 2 ||
		q.Members[0].MemberID >= q.Members[1].MemberID {
		return reply, errStage2aReservationAuthority
	}
	r, p, reservationExpires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		len(r.memberSetAssignmentEnvelope) == 0 || len(r.provisionalHQMap) == 0 ||
		r.provisionalHQMapSHA256 != stage2aReservationSHA256(r.provisionalHQMap) ||
		len(r.memberChildGrants) != 2 || len(p.MemberBridgeQualifications) != 2 ||
		r.memberChildObservationEnvelope != nil || r.twoMemberChildren != nil ||
		r.hello == nil || r.hello.aborted || r.hello.finalized ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	var mapping Stage2aProvisionalMemberMap
	if stage2aDecodeExact(r.provisionalHQMap, &mapping) != nil || len(mapping.Members) != 2 ||
		mapping.AssignmentEnvelopeSHA256 != stage2aReservationSHA256(r.memberSetAssignmentEnvelope) ||
		mapping.RuntimeState != "provisional" || mapping.ACPAuthority != "withheld" {
		return reply, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	assignmentRaw, err := verifyStage2aStoredARecordV3(r.memberSetAssignmentEnvelope,
		stage2aMemberSetAssignmentPurpose, 1, key)
	var assignment stage2aMemberSetAssignmentPayload
	if err != nil || stage2aDecodeExact(assignmentRaw, &assignment) != nil ||
		assignment.ReservationSHA256 != r.digest || assignment.InstallationID != q.InstallationID ||
		assignment.StartID != q.StartID || assignment.HQEpoch != epoch ||
		assignment.PlanID != q.PlanID || assignment.PlanDigest != q.PlanDigest ||
		assignment.ProfileInForce != "managed-protected" || assignment.HostID != p.Binding.HostID ||
		assignment.SoulID != p.Binding.SoulID {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	mapExpires, mapErr := time.Parse(time.RFC3339Nano, mapping.ExpiresAt)
	if mapErr != nil || !now.Before(mapExpires) || !now.Before(r.memberSetAssignmentExpires) {
		return reply, errStage2aReservationExpired
	}
	candidates := make([]stage2aMemberChildCandidate, 2)
	for i, member := range q.Members {
		grant := r.memberChildGrants[member.MemberID]
		if member.MemberID != assignment.Members[i].MemberID ||
			member.MemberID != mapping.Members[i].MemberID ||
			member.MemberLaunchID != assignment.Members[i].LaunchID ||
			member.MemberSelector != assignment.Members[i].MemberSelector ||
			member.MemberSelector != mapping.Members[i].MemberSelector ||
			member.MemberSelector != stage2aMemberSelector(r.digest, member.MemberID, member.MemberLaunchID) ||
			member.MemberID != grant.MemberID || member.MemberLaunchID != grant.MemberLaunchID ||
			member.MemberSelector != grant.MemberSelector || member.GrantSHA256 != grant.GrantSHA256 ||
			member.ChildLauncherPID != grant.Launcher.PID || member.ChildPID <= 1 ||
			!now.Before(grant.ExpiresAt) ||
			grant.ChildPID != 0 || len(grant.Receipt) != 0 {
			return reply, errStage2aReservationAuthority
		}
		candidates[i] = stage2aMemberChildCandidate{MemberID: member.MemberID,
			LauncherPID: member.ChildLauncherPID, ChildPID: member.ChildPID,
			GrantedLauncher: grant.Launcher}
	}
	if err := r.observeTwoMemberChildren(p, candidates); err != nil || r.twoMemberChildren == nil {
		return reply, errStage2aReservationAuthority
	}
	approvedUntil, approvalErr := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	until := minStage2aTime(now.Add(15*time.Second), approvedUntil)
	until = minStage2aTime(until, reservationExpires)
	until = minStage2aTime(until, mapExpires)
	until = minStage2aTime(until, r.memberSetAssignmentExpires)
	for _, member := range q.Members {
		until = minStage2aTime(until, r.memberChildGrants[member.MemberID].ExpiresAt)
	}
	if approvalErr != nil || !until.After(now) ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	payload := stage2aMemberChildObservationPayload{Contract: "machine/v3",
		Kind: "stage2a-member-set-child-observation", SchemaVersion: 1,
		ProfileInForce: "managed-protected", HostID: p.Binding.HostID,
		InstallationID: q.InstallationID, SoulID: p.Binding.SoulID,
		StartID: q.StartID, HQEpoch: epoch, ReservationSHA256: r.digest,
		AssignmentEnvelopeSHA256:   stage2aReservationSHA256(r.memberSetAssignmentEnvelope),
		ProvisionalHQMappingSHA256: r.provisionalHQMapSHA256,
		ProvisionalHQMapping:       bytes.Clone(r.provisionalHQMap),
		ObservedAt:                 now.UTC().Format(time.RFC3339Nano),
		IssuedAt:                   now.UTC().Format(time.RFC3339Nano), ExpiresAt: until.UTC().Format(time.RFC3339Nano)}
	for i, observed := range r.twoMemberChildren.Members {
		payload.Members[i].MemberID = assignment.Members[i].MemberID
		payload.Members[i].LaunchID = assignment.Members[i].LaunchID
		payload.Members[i].MemberSelector = assignment.Members[i].MemberSelector
		payload.Members[i].RuntimeID = mapping.Members[i].RuntimeID
		payload.Members[i].GrantSHA256 = q.Members[i].GrantSHA256
		payload.Members[i].LauncherProcess = stage2aMemberLauncherIdentity(observed.Launcher)
		payload.Members[i].ChildProcess = stage2aMemberProcessIdentity(observed.Child,
			observed.CommandSHA256)
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aMemberChildObservationPurpose,
		key, s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 16<<10 ||
		!time.Now().Before(until) || stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		r.twoMemberChildren.recheck(func(pid int) (soulKernelProcessSnapshot, error) {
			return observeStage2aRoleProcess(pid, p.Runner.UID, p.Runner.GID, "child")
		}, func(pid, parent int) (soulKernelProcessSnapshot, error) {
			return observeStage2aChildProcess(pid, parent, p.Runner, p.LaunchInputs)
		}) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.memberChildObservationEnvelope = envelope
	r.memberChildObservationExpires = until
	for i, member := range q.Members {
		grant := r.memberChildGrants[member.MemberID]
		grant.ChildPID = member.ChildPID
		grant.Child = r.twoMemberChildren.Members[i].Child
		r.memberChildGrants[member.MemberID] = grant
	}
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}
