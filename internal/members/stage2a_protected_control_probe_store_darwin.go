//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"
)

// StoreProtectedControlProbe retains one exact raw control artifact under A.
// The paired HQ transport carries bytes but does not attest to the probe OS
// facts. This method never signs a gate result or qualifies a host.
func (s *Stage2aService) StoreProtectedControlProbe(hqUID int, epoch string,
	q Stage2aProtectedControlProbeUpload) (Stage2aProtectedControlProbeReceipt, error) {
	var reply Stage2aProtectedControlProbeReceipt
	if s == nil || len(s.key) != ed25519.PrivateKeySize ||
		!validStage2aStopRequest(q.Stage2aStopRequest) || epoch != q.HQEpoch ||
		!stage2aPrefixedDigest.MatchString(q.ChildReceiptSHA256) {
		return reply, errStage2aReservationAuthority
	}
	artifact, err := base64.RawURLEncoding.Strict().DecodeString(q.ArtifactBase64URL)
	if err != nil || len(artifact) == 0 || len(artifact) > stage2aProtectedControlProbeLimit ||
		base64.RawURLEncoding.EncodeToString(artifact) != q.ArtifactBase64URL ||
		stage2aStrictJSON(artifact) != nil {
		return reply, errStage2aReservationAuthority
	}
	var evidence stage2aProtectedControlProbeEvidence
	if stage2aDecodeExact(artifact, &evidence) != nil ||
		evidence.Schema != stage2aProtectedControlProbeSchema ||
		evidence.Kind != "negative-control" || evidence.Phase != "pre-acp" ||
		!evidence.ControlOnly || evidence.ChildReceiptSHA256 != q.ChildReceiptSHA256 ||
		evidence.ReservationSHA256 != q.ReservationSHA256 ||
		evidence.ProfileSHA256 != "sha256:"+harnessSHA(soulChildProfile) ||
		evidence.Result.Schema != stage2aProtectedControlProbeSchema ||
		evidence.Result.Kind != "negative-control" ||
		evidence.Result.PID != evidence.Probe.PID ||
		evidence.Result.DirectIPv4 != "EPERM" && evidence.Result.DirectIPv4 != "EACCES" ||
		evidence.Result.DirectIPv6 != "EPERM" && evidence.Result.DirectIPv6 != "EACCES" ||
		evidence.Result.AssignedRelay != "connected" ||
		evidence.Result.SiblingSocket != "EPERM" && evidence.Result.SiblingSocket != "EACCES" ||
		evidence.Result.SiblingToken != "EPERM" && evidence.Result.SiblingToken != "EACCES" {
		return reply, errStage2aReservationAuthority
	}
	captured, err := time.Parse(time.RFC3339Nano, evidence.Result.CapturedAt)
	if err != nil || captured.After(time.Now()) {
		return reply, errStage2aReservationAuthority
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.active[q.ReservationSHA256]
	if !stage2aMatchesStopSelectors(r, q.Stage2aStopRequest, hqUID) ||
		r.runModeV3 != stage2aCandidateRunV3 || r.childPID <= 1 ||
		len(r.childReceiptEnvelope) == 0 ||
		q.ChildReceiptSHA256 != stage2aReservationSHA256(r.childReceiptEnvelope) ||
		len(r.finalizationEnvelope) == 0 || r.hello == nil || r.hello.aborted ||
		!r.hello.finalized || len(r.hello.finalizationEnvelope) == 0 {
		return reply, errStage2aReservationAuthority
	}
	p, rawPolicy, err := loadStage2aActiveExecutionPolicy(s.key.Public().(ed25519.PublicKey), hqUID, epoch, r)
	if err != nil || stage2aReservationSHA256(rawPolicy) != r.policyDigest ||
		p.Binding.ProfileInForce != "managed-protected" ||
		evidence.Spec.ProviderModel != p.BridgeQualification.Model ||
		evidence.Spec.ProviderRequestSHA256 != p.BridgeQualification.RequestSHA256 ||
		!stage2aProtectedControlProbeSpecMatches(evidence.Spec, r.payload.Assignment.SoulStartAssignment,
			p.LaunchInputs.ComponentDigests["test_provider"]) ||
		checkStage2aGrantedRoleProcess(r.runnerPID, p.Runner.UID, p.Runner.GID,
			"runner", r.runnerProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.bridgePID, p.Bridge.UID, p.Bridge.GID,
			"bridge", r.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(r.childLauncherPID, p.Runner.UID, p.Runner.GID,
			"child", r.childLauncherProcess) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner,
			p.LaunchInputs, r.childProcess) != nil ||
		stage2aRecheckExecutionCode(r, p) != nil {
		return reply, errStage2aReservationAuthority
	}
	childPayload, err := verifyStage2aStoredARecordV3(r.childReceiptEnvelope,
		Stage2aChildStartPurpose, 1, s.key.Public().(ed25519.PublicKey))
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	var signed struct {
		ProtectedControlProbe *Stage2aProtectedControlProbeSpec `json:"protected_control_probe"`
		StartedAtMS           int64                             `json:"started_at_ms"`
		ExpiresAtMS           int64                             `json:"expires_at_ms"`
	}
	if json.Unmarshal(childPayload, &signed) != nil || signed.ProtectedControlProbe == nil ||
		!reflect.DeepEqual(*signed.ProtectedControlProbe, evidence.Spec) ||
		captured.Before(time.UnixMilli(signed.StartedAtMS)) ||
		!captured.Before(time.UnixMilli(signed.ExpiresAtMS)) ||
		!time.Now().Before(time.UnixMilli(signed.ExpiresAtMS)) ||
		!reflect.DeepEqual(evidence.Runner, stage2aLiveRoleIdentity(r.runnerProcess)) ||
		!reflect.DeepEqual(evidence.Bridge, stage2aLiveRoleIdentity(r.bridgeProcess)) ||
		!reflect.DeepEqual(evidence.Launcher, stage2aProtectedProbeIdentity(r.childLauncherProcess)) ||
		!reflect.DeepEqual(evidence.Child, stage2aProtectedProbeIdentity(r.childProcess)) ||
		evidence.Probe.PID <= 1 || evidence.Probe.PID == r.childPID ||
		evidence.Probe.ParentPID != r.childLauncherPID ||
		evidence.Probe.GroupPID != r.childLauncherProcess.ProcessGroupID ||
		evidence.Probe.RealUID != uint32(p.Runner.UID) ||
		evidence.Probe.EffectiveUID != uint32(p.Runner.UID) ||
		evidence.Probe.SavedUID != uint32(p.Runner.UID) ||
		evidence.Probe.RealGID != uint32(p.Runner.GID) ||
		evidence.Probe.PrimaryGID != uint32(p.Runner.GID) ||
		evidence.Probe.SavedGID != uint32(p.Runner.GID) ||
		len(evidence.Probe.Groups) != 1 || evidence.Probe.Groups[0] != uint32(p.Runner.GID) ||
		evidence.Result.UID != p.Runner.UID {
		return reply, errStage2aReservationAuthority
	}
	if r.protectedQ == nil {
		return reply, errStage2aReservationAuthority
	}
	currentPeerSpec, err := s.stage2aProtectedPeerSpec(hqUID, epoch, r, p,
		r.protectedQ.install.Review)
	if err != nil || !reflect.DeepEqual(currentPeerSpec, signed.ProtectedControlProbe) {
		return reply, errStage2aReservationAuthority
	}
	store, snapshots := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, errStage2aReservationAuthority
	}
	defer lock.Close()
	slot := soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil || snapshots.check() != nil ||
		p.verifyRunnerGroup() != nil ||
		stage2aCheckSpentClaim(dir, stage2aActiveClaimName(q.InstallationID), store.uid, store.gid) != nil ||
		stage2aCheckSpentClaim(dir, ".stage2a-b-bind-"+slot, store.uid, store.gid) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-child-ready-"+slot+".json",
			store.uid, store.gid, r.childReceiptEnvelope, 8192) != nil ||
		stage2aExactAdminRecord(dir, ".stage2a-b-final-"+slot+".json",
			store.uid, store.gid, r.finalizationEnvelope, 64<<10) != nil ||
		observeInstalledStage2aLaunchInputs(snapshots, p.Binding, p.LaunchInputs) != nil ||
		stage2aCheckRuntimeSnapshot(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files) != nil ||
		checkStage2aChildProcess(r.childPID, r.childLauncherPID, p.Runner,
			p.LaunchInputs, r.childProcess) != nil {
		return reply, errStage2aReservationAuthority
	}
	name := ".stage2a-control-probe-" + slot + ".json"
	if commitStage2aReservation(dir, name, artifact) != nil {
		return reply, errStage2aReservationAuthority
	}
	return Stage2aProtectedControlProbeReceipt{
		ArtifactSHA256: stage2aReservationSHA256(artifact), Kind: "stored-control-only"}, nil
}
