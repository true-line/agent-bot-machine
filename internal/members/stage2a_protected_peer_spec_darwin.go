//go:build darwin

package members

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The reviewed Q installation names one other installed Soul. A binds that
// name to exactly one currently live B2 reservation, never to an HQ supplied
// path, UID, or stale sibling fixture. Call with Stage2aService.mu held.
func (s *Stage2aService) stage2aProtectedPeerSpec(hqUID int, epoch string,
	self *stage2aLiveReservation, policy stage2aInstalledPolicy,
	review stage2aQualificationQReview) (*Stage2aProtectedControlProbeSpec, error) {
	if s == nil || !review.DriverLive || !review.valid() ||
		policy.Binding.ProfileInForce != "managed-protected" ||
		self == nil || self.protectedQ == nil || self.protectedQ.checkLive() != nil ||
		self.payload.Assignment.InstallationID != review.InstallationID {
		return nil, errStage2aReservationAuthority
	}
	var peer *stage2aLiveReservation
	for _, candidate := range s.active {
		if candidate != nil && candidate.payload.Assignment.InstallationID == review.ControlPeerInstallationID &&
			candidate.request.HQEpoch == epoch && candidate.payload.Assignment.HQUID == hqUID {
			if peer != nil {
				return nil, errStage2aReservationAuthority
			}
			peer = candidate
		}
	}
	if peer == nil || peer == self || peer.digest == self.digest ||
		peer.runModeV3 != stage2aCandidateRunV3 || peer.bridgePID <= 1 ||
		peer.runnerPID <= 1 || peer.childPID <= 1 || peer.liveSequence == 0 ||
		len(peer.finalizationEnvelope) == 0 || len(peer.childReceiptEnvelope) == 0 ||
		peer.hello == nil || peer.hello.aborted || !peer.hello.finalized {
		return nil, errStage2aReservationAuthority
	}
	peer, peerPolicy, _, err := s.current(hqUID, epoch, peer.digest)
	if err != nil || peerPolicy.Binding.ProfileInForce != "managed-protected" ||
		peerPolicy.Binding.HostID != policy.Binding.HostID ||
		peerPolicy.Bridge.UID == policy.Bridge.UID ||
		peerPolicy.Runner.UID == policy.Runner.UID ||
		peerPolicy.Bridge.UID == policy.Runner.UID ||
		peerPolicy.Runner.UID == policy.Bridge.UID ||
		checkStage2aGrantedRoleProcess(peer.bridgePID, peerPolicy.Bridge.UID,
			peerPolicy.Bridge.GID, "bridge", peer.bridgeProcess) != nil ||
		checkStage2aGrantedRoleProcess(peer.runnerPID, peerPolicy.Runner.UID,
			peerPolicy.Runner.GID, "runner", peer.runnerProcess) != nil ||
		checkStage2aChildProcess(peer.childPID, peer.childLauncherPID,
			peerPolicy.Runner, peerPolicy.LaunchInputs, peer.childProcess) != nil ||
		stage2aRecheckExecutionCode(peer, peerPolicy) != nil {
		return nil, errStage2aReservationAuthority
	}
	peerStart := peer.payload.Assignment.SoulStartAssignment
	endpoints, err := DeriveSoulBridgeEndpoints(peerPolicy.Runner, peerPolicy.Bridge, hqUID, peerStart.StartID)
	if err != nil || peerStart.Relay.SocketPath != endpoints.Relay.SocketPath ||
		stage2aCheckProtectedPeerProof(peerStart) != nil {
		return nil, errStage2aReservationAuthority
	}
	proofDir, proofName := stage2aBridgeProofPath(peerStart)
	selfStart := self.payload.Assignment.SoulStartAssignment
	spec := &Stage2aProtectedControlProbeSpec{
		Schema:         stage2aProtectedControlProbeSchema,
		InstallationID: selfStart.InstallationID, StartID: selfStart.StartID,
		LaunchID: selfStart.LaunchID, PlanDigest: selfStart.PlanDigest,
		HQEpoch:              selfStart.HQEpoch,
		ProviderConfigSHA256: policy.LaunchInputs.ComponentDigests["test_provider"],
		ProviderPort: stage2aProtectedProviderPortV1(selfStart.HQEpoch,
			selfStart.InstallationID, selfStart.StartID),
		ProviderModel:         policy.BridgeQualification.Model,
		ProviderRequestSHA256: policy.BridgeQualification.RequestSHA256,
		SiblingInstallationID: peerStart.InstallationID,
		SiblingStartID:        peerStart.StartID,
		SiblingBridgeUID:      peerPolicy.Bridge.UID,
		SiblingTokenPath:      filepath.Join(proofDir, proofName),
		SiblingRelaySocket:    endpoints.Relay.SocketPath,
	}
	if !stage2aProtectedControlProbeSpecMatches(*spec, selfStart,
		policy.LaunchInputs.ComponentDigests["test_provider"]) {
		return nil, errStage2aReservationAuthority
	}
	return spec, nil
}

// Inspect the real A-published B-only proof node without reading its key.
func stage2aCheckProtectedPeerProof(start SoulStartAssignment) error {
	if start.MachineUID != os.Getuid() || start.MachineUID != os.Geteuid() ||
		start.BridgeGID <= 0 {
		return errStage2aReservationAuthority
	}
	directory, name := stage2aBridgeProofPath(start)
	dir, err := openStage2aAdminDirectory(directory, uint32(start.MachineUID))
	if err != nil {
		return errStage2aReservationAuthority
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil ||
		parent.Mode != unix.S_IFDIR|02710 ||
		parent.Uid != uint32(start.MachineUID) ||
		parent.Gid != uint32(start.BridgeGID) {
		return errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errStage2aReservationAuthority
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var node unix.Stat_t
	if unix.Fstat(fd, &node) != nil || node.Mode != unix.S_IFREG|0440 ||
		node.Nlink != 1 || node.Uid != uint32(start.MachineUID) ||
		node.Gid != uint32(start.BridgeGID) || node.Size != 32 ||
		checkDarwinACLs([]string{filepath.Join(directory, name)}) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}
