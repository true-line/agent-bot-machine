//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"time"
)

type stage2aHelloState struct {
	startEnvelope        []byte
	finalizationEnvelope []byte
	peerProcess          soulKernelProcessSnapshot
	helloSHA256          string
	requestID            string
	members              []string
	aborted              bool
	finalized            bool
}

type Stage2aHelloStartPayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	HostID                   string                  `json:"host_id"`
	SoulID                   string                  `json:"soul_id"`
	DefinitionDigest         string                  `json:"definition_digest"`
	DefinitionMeasurement    string                  `json:"definition_measurement"`
	LaunchInputMeasurement   string                  `json:"launch_input_measurement"`
	ProfileInForce           string                  `json:"profile_in_force"`
	PeerUID                  int                     `json:"peer_uid"`
	PeerPID                  int                     `json:"peer_pid"`
	PeerProcess              Stage2aLiveRoleIdentity `json:"peer_process"`
	PeerParentPID            int                     `json:"peer_parent_pid"`
	PeerProcessGroupID       int                     `json:"peer_process_group_id"`
	Runner                   Stage2aLiveRoleIdentity `json:"runner"`
	Bridge                   Stage2aLiveRoleIdentity `json:"bridge"`
	BrokerBindReceiptSHA256  string                  `json:"broker_bind_receipt_sha256"`
	BridgeFinalizationSHA256 string                  `json:"bridge_finalization_sha256"`
	HelloPayloadSHA256       string                  `json:"hello_payload_sha256"`
	HelloRequestID           string                  `json:"hello_request_id"`
	RequestedMemberIDs       []string                `json:"requested_member_ids"`
	IssuedAt                 string                  `json:"issued_at"`
}

type Stage2aHelloFinalizationPayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	StartEnvelopeSHA256 string               `json:"start_envelope_sha256"`
	Expected            Stage2aHelloExpected `json:"expected"`
	FinalizedAt         string               `json:"finalized_at"`
}

type Stage2aPeerRolePayload struct {
	Schema string `json:"schema"`
	Stage2aStopRequest
	Role                    string                  `json:"role"`
	PeerUID                 int                     `json:"peer_uid"`
	PeerPID                 int                     `json:"peer_pid"`
	PeerProcess             Stage2aLiveRoleIdentity `json:"peer_process"`
	PeerParentPID           int                     `json:"peer_parent_pid"`
	PeerProcessGroupID      int                     `json:"peer_process_group_id"`
	Runner                  Stage2aLiveRoleIdentity `json:"runner"`
	Bridge                  Stage2aLiveRoleIdentity `json:"bridge"`
	DefinitionMeasurement   string                  `json:"definition_measurement"`
	LaunchInputMeasurement  string                  `json:"launch_input_measurement"`
	ProfileInForce          string                  `json:"profile_in_force"`
	HelloFinalizationSHA256 string                  `json:"hello_finalization_sha256,omitempty"`
	ChildStartReceiptSHA256 string                  `json:"child_start_receipt_sha256,omitempty"`
	IssuedAtMS              int64                   `json:"issued_at_ms"`
	ExpiresAtMS             int64                   `json:"expires_at_ms"`
}

// PeerRole is called by the paired HQ listener immediately after accept. A
// observes either the exact R Node child or the separately granted child Go
// wrapper; sharing R's UID is never enough to classify the socket.
func (s *Stage2aService) PeerRole(hqUID int, epoch string, q Stage2aPeerRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		q.PeerPID <= 1 || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.hello != nil && r.hello.aborted {
		return reply, errStage2aReservationAuthority
	}
	p, raw, err := loadStage2aInstalledPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, q.InstallationID)
	if err != nil || stage2aReservationSHA256(raw) != r.policyDigest ||
		q.PeerUID != p.Runner.UID || p.Binding.ProfileInForce != "managed-protected" ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil {
		return reply, errStage2aReservationAuthority
	}
	role := "runner"
	peer, err := observeStage2aHelloRunnerPeer(q.PeerPID, r, p)
	if err != nil {
		role = "child"
		if r.hello == nil || !r.hello.finalized || len(r.hello.finalizationEnvelope) == 0 ||
			r.childLauncherPID != q.PeerPID || r.childPID <= 1 || len(r.childReceiptEnvelope) == 0 ||
			checkStage2aGrantedRoleProcess(q.PeerPID, p.Runner.UID, p.Runner.GID, "child", r.childLauncherProcess) != nil ||
			checkStage2aChildProcess(r.childPID, q.PeerPID, p.Runner, p.LaunchInputs, r.childProcess) != nil {
			return reply, errStage2aReservationAuthority
		}
		peer = r.childLauncherProcess
	} else if r.hello != nil && r.hello.peerProcess.PID > 1 &&
		!sameSoulKernelProcess(peer, r.hello.peerProcess) {
		return reply, errStage2aReservationAuthority
	}
	now := time.Now()
	approvedUntil, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	expires := minStage2aTime(now.Add(stage2aLiveLease), approvedUntil)
	if err != nil || !expires.After(now) {
		return reply, errStage2aReservationAuthority
	}
	payload := Stage2aPeerRolePayload{
		Schema: "agent-bot-machine/stage2a-peer-role/v1", Stage2aStopRequest: q.Stage2aStopRequest,
		Role: role, PeerUID: q.PeerUID, PeerPID: q.PeerPID,
		PeerProcess: stage2aLiveRoleIdentity(peer), PeerParentPID: peer.ParentPID,
		PeerProcessGroupID: peer.ProcessGroupID,
		Runner:             stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		DefinitionMeasurement:  p.Binding.DefinitionMeasurement,
		LaunchInputMeasurement: p.Binding.LaunchInputMeasurement,
		ProfileInForce:         p.Binding.ProfileInForce,
		IssuedAtMS:             now.UnixMilli(), ExpiresAtMS: expires.UnixMilli(),
	}
	if role == "child" {
		payload.HelloFinalizationSHA256 = stage2aReservationSHA256(r.hello.finalizationEnvelope)
		payload.ChildStartReceiptSHA256 = stage2aReservationSHA256(r.childReceiptEnvelope)
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aPeerRolePurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 || !time.Now().Before(expires) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil {
		return reply, errStage2aReservationAuthority
	}
	if role == "runner" && checkStage2aHelloRunnerPeer(q.PeerPID, r, p, peer) != nil ||
		role == "child" && (checkStage2aGrantedRoleProcess(q.PeerPID, p.Runner.UID, p.Runner.GID, "child", peer) != nil ||
			checkStage2aChildProcess(r.childPID, q.PeerPID, p.Runner, p.LaunchInputs, r.childProcess) != nil) {
		return reply, errStage2aReservationAuthority
	}
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}

func observeStage2aHelloRunnerPeer(pid int, r *stage2aLiveReservation,
	p stage2aInstalledPolicy) (soulKernelProcessSnapshot, error) {
	if r == nil || pid <= 1 || pid == r.runnerPID || p.Node == "" ||
		len(p.LaunchInputs.Argv) == 0 || p.LaunchInputs.Argv[0] != p.Node ||
		p.LaunchInputs.SelectedCommand != p.Node ||
		!stage2aRuntimeFile(p.Binding.Snapshots.LaunchInputs.RootPath, p.Node,
			"bin/node", p.LaunchInputs.Files, true) ||
		!stage2aRuntimeFile(p.Binding.Snapshots.LaunchInputs.RootPath, p.Entry,
			"bin/agent-bot-souls.mjs", p.LaunchInputs.Files, false) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	if r.request.StartID != r.payload.Assignment.StartID ||
		r.request.InstallationID != p.Binding.InstallationID {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	argv, _, err := stage2aRunnerArgvForStart(p.LaunchInputs, p.Node, p.Entry,
		p.Binding.Snapshots.Definition.RootPath, p.Binding.ProfileInForce,
		p.Runner, p.Bridge, p.HQUID, r.request.StartID)
	if err != nil {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(pid, p.Node, argv)
	if err != nil || !stage2aRunnerPeerKernelMatches(observed.Kernel,
		r.runnerPID, p.Runner.UID, p.Runner.GID) {
		return soulKernelProcessSnapshot{}, errStage2aReservationAuthority
	}
	return observed.Kernel, nil
}

func stage2aRunnerPeerKernelMatches(peer soulKernelProcessSnapshot, wrapperPID, uid, gid int) bool {
	return peer.PID > 1 && peer.PID != wrapperPID && peer.ParentPID == wrapperPID &&
		peer.ProcessGroupID == peer.PID && peer.StartSeconds > 0 &&
		peer.RealUID == uint32(uid) && peer.EffectiveUID == uint32(uid) &&
		peer.SavedUID == uint32(uid) && peer.RealGID == uint32(gid) &&
		peer.PrimaryGroupGID == uint32(gid) && peer.SavedGID == uint32(gid)
}

func checkStage2aHelloRunnerPeer(pid int, r *stage2aLiveReservation,
	p stage2aInstalledPolicy, expected soulKernelProcessSnapshot) error {
	observed, err := observeStage2aHelloRunnerPeer(pid, r, p)
	if err != nil || !sameSoulKernelProcess(observed, expected) {
		return errStage2aReservationAuthority
	}
	return nil
}

// HelloStart turns HQ's kernel-observed admission peer and exact canonical
// Hello into a signed, one-use A binding. The paired H request is trusted only
// as a statement of what its listener observed; A reobserves R and B.
func (s *Stage2aService) HelloStart(hqUID int, epoch string, q Stage2aHelloStartRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		len(s.key) != ed25519.PrivateKeySize || q.PeerUID <= 0 || q.PeerPID <= 1 {
		return reply, errStage2aReservationAuthority
	}
	helloBytes, err := stage2aHelloBytes(q)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	var hello stage2aHelloClaim
	if json.Unmarshal(helloBytes, &hello) != nil || hello.Contract != "hq/v1" ||
		!stage2aBindingID.MatchString(hello.RequestID) ||
		hello.RequestedProfile != "managed-protected" ||
		len(hello.RequestedRoles) == 0 || len(hello.RequestedRoles) > 32 {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.hello != nil || q.PeerUID != p.Runner.UID ||
		q.BrokerBindReceiptSHA256 != r.bindReceiptSHA256 ||
		hello.SoulID != p.Binding.SoulID || hello.InstallationID != q.InstallationID ||
		hello.DefinitionDigest != p.Binding.ClaimedDefinitionDigest ||
		p.Binding.ProfileInForce != "managed-protected" {
		return reply, errStage2aReservationAuthority
	}
	if stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil {
		return reply, errStage2aReservationAuthority
	}
	peer, err := observeStage2aHelloRunnerPeer(q.PeerPID, r, p)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	members := make([]string, 0, len(hello.RequestedRoles))
	for _, role := range hello.RequestedRoles {
		if !stage2aBindingID.MatchString(role.MemberID) || slices.Contains(members, role.MemberID) {
			return reply, errStage2aReservationAuthority
		}
		members = append(members, role.MemberID)
	}
	slices.Sort(members)
	b := p.Binding
	payload := Stage2aHelloStartPayload{
		Schema: "agent-bot-machine/stage2a-hello-start/v1", Stage2aStopRequest: q.Stage2aStopRequest,
		HostID: b.HostID, SoulID: b.SoulID, DefinitionDigest: b.ClaimedDefinitionDigest,
		DefinitionMeasurement: b.DefinitionMeasurement, LaunchInputMeasurement: b.LaunchInputMeasurement,
		ProfileInForce: b.ProfileInForce, PeerUID: q.PeerUID, PeerPID: q.PeerPID,
		PeerProcess: stage2aLiveRoleIdentity(peer), PeerParentPID: peer.ParentPID,
		PeerProcessGroupID: peer.ProcessGroupID,
		Runner:             stage2aLiveRoleIdentity(r.runnerProcess), Bridge: stage2aLiveRoleIdentity(r.bridgeProcess),
		BrokerBindReceiptSHA256:  r.bindReceiptSHA256,
		BridgeFinalizationSHA256: stage2aReservationSHA256(r.finalizationEnvelope),
		HelloPayloadSHA256:       q.HelloPayloadSHA256, HelloRequestID: hello.RequestID,
		RequestedMemberIDs: members, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aHelloStartPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 || !time.Now().Before(expires) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(q.PeerPID, r, p, peer) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.hello = &stage2aHelloState{startEnvelope: envelope, helloSHA256: q.HelloPayloadSHA256,
		requestID: hello.RequestID, members: members, peerProcess: peer}
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}

// HelloFinalize signs HQ's exact pending admission result once. The lock makes
// AbortHello terminal against a late finalization on this Machine process.
func (s *Stage2aService) HelloFinalize(hqUID int, epoch string, q Stage2aHelloFinalizeRequest) (Stage2aHelloReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aHelloReply
	if !validStage2aStopRequest(q.Stage2aStopRequest) || q.HQEpoch != epoch ||
		!validStage2aHelloExpected(q.Expected) || len(s.key) != ed25519.PrivateKeySize {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.hello == nil || r.hello.aborted || r.hello.finalized ||
		stage2aReservationSHA256(r.hello.startEnvelope) != q.StartEnvelopeSHA256 ||
		!stage2aHelloExpectedMatches(q, r, p) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	payload := Stage2aHelloFinalizationPayload{
		Schema: "agent-bot-machine/stage2a-hello-finalization/v1", Stage2aStopRequest: q.Stage2aStopRequest,
		StartEnvelopeSHA256: q.StartEnvelopeSHA256, Expected: q.Expected,
		FinalizedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	envelope, err := signStage2aEnvelope(payload, 1, Stage2aHelloFinalizationPurpose,
		s.key.Public().(ed25519.PublicKey), s.sign)
	if err != nil || len(envelope) == 0 || len(envelope) > 8192 || !time.Now().Before(expires) ||
		stage2aHelloCheckLive(r, p, q.Stage2aStopRequest) != nil ||
		checkStage2aHelloRunnerPeer(r.hello.peerProcess.PID, r, p, r.hello.peerProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	r.hello.finalized = true
	r.hello.finalizationEnvelope = envelope
	return Stage2aHelloReply{EnvelopeBase64URL: base64.RawURLEncoding.EncodeToString(envelope),
		SHA256: stage2aReservationSHA256(envelope)}, nil
}

func stage2aHelloExpectedMatches(q Stage2aHelloFinalizeRequest, r *stage2aLiveReservation, p stage2aInstalledPolicy) bool {
	e := q.Expected
	b := p.Binding
	if e.ReservationSHA256 != q.ReservationSHA256 || e.StartID != q.StartID ||
		e.LaunchID != q.LaunchID || e.HQEpoch != q.HQEpoch || e.InstallationID != q.InstallationID ||
		e.SoulID != b.SoulID || e.DefinitionDigest != b.ClaimedDefinitionDigest ||
		e.DefinitionMeasurement != b.DefinitionMeasurement ||
		e.LaunchInputMeasurement != b.LaunchInputMeasurement ||
		e.HelloPayloadSHA256 != r.hello.helloSHA256 ||
		e.HQBrokerBindReceiptSHA256 != r.bindReceiptSHA256 ||
		len(e.AdmittedRuntimes) != len(r.hello.members) {
		return false
	}
	seenRuntimes := make(map[string]bool, len(e.AdmittedRuntimes))
	for i, admitted := range e.AdmittedRuntimes {
		if admitted.MemberID != r.hello.members[i] || seenRuntimes[admitted.RuntimeID] {
			return false
		}
		seenRuntimes[admitted.RuntimeID] = true
	}
	return true
}

// This check deliberately repeats the installed and durable evidence checks
// under the same service lock immediately before each signature is returned.
func stage2aHelloCheckLive(r *stage2aLiveReservation, p stage2aInstalledPolicy, q Stage2aStopRequest) error {
	if r == nil || r.runnerPID <= 1 || r.bridgePID <= 1 || len(r.finalizationEnvelope) == 0 ||
		r.bindReceiptSHA256 == "" ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID, "runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID, "bridge", r.bridgeProcess) != nil {
		return errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return err
	}
	defer lock.Close()
	if store.checkDirectory(dir) != nil || snapshots.check() != nil || p.verifyRunnerGroup() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+soulStartClaimName(q.InstallationID, q.StartID), store.uid, store.gid) != nil {
		return errStage2aReservationAuthority
	}
	definition, err := observeStage2aAdminSnapshot(snapshots, filepath.Base(p.Binding.Snapshots.Definition.RootPath),
		p.Binding.Snapshots.Definition, p.Definition)
	if err != nil || definition != p.Binding.DefinitionMeasurement ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil {
		return errStage2aReservationAuthority
	}
	name := ".stage2a-b-final-" + soulStartClaimName(q.InstallationID, q.StartID) + ".json"
	if stage2aCheckFinalizationFile(dir, name, store.uid, store.gid, r.finalizationEnvelope) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}

// AbortHello denies later finalization and renewal even if HQ's pending
// transaction failed. A restart also loses this in-memory grant and refuses.
func (s *Stage2aService) AbortHello(hqUID int, epoch string, q Stage2aStopRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.active[q.ReservationSHA256]
	if !validStage2aStopRequest(q) || q.HQEpoch != epoch ||
		!stage2aMatchesStopSelectors(r, q, hqUID) {
		return errStage2aReservationAuthority
	}
	if r.hello == nil {
		r.hello = &stage2aHelloState{aborted: true}
	} else {
		r.hello.aborted = true
	}
	return nil
}
