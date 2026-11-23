//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os/user"
	"strconv"
)

// A alone begins a candidate qualification from the retained root-installed
// Q plan. The paired HQ supplies start selectors, never the saved plan,
// approval, adapter bytes or pair guard. The one-use approval is spent before
// Reserve sends a signed grant to the offline worker.
func (s *Stage2aService) beginInstalledCandidateV3(hqUID int, epoch string, selector Stage2aReserveRequest,
	checkPair func(string, string, string, func() error) error) error {
	if s == nil || checkPair == nil || len(s.key) != ed25519.PrivateKeySize ||
		hqUID < 300 || hqUID > 399 || selector.HQEpoch != epoch {
		return errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	runtime, err := stage2aLoadInstalledRuntimeV3(key, hqUID, epoch, selector.InstallationID)
	if err != nil {
		return errStage2aReservationAuthority
	}
	install, err := loadStage2aQualificationQInstall()
	if err != nil || !stage2aCandidateInstallMatchesRuntimeV3(install, runtime) {
		return errStage2aReservationAuthority
	}
	saved, approval, owner, state, err := loadStage2aCandidatePlanSourceV3(install, fmt.Sprintf("%x", sha256.Sum256(key)))
	if err != nil {
		return errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	if err != nil {
		return errStage2aReservationAuthority
	}
	guard := func(a Approval, run func() error) error {
		if a != approval || run == nil {
			return errStage2aReservationAuthority
		}
		return checkPair(state, account.Username, approval.PairCommitment, run)
	}
	request := stage2aReservationRequest{start: SoulRunRequest{
		PlanDigest: selector.PlanDigest, InstallationID: selector.InstallationID,
		StartID: selector.StartID, HQEpoch: selector.HQEpoch,
	}, launchID: selector.LaunchID}
	base, err := loadStage2aReservationEvidenceV3(request, runtime, key, stage2aReservationAdapterV3{}, nil)
	if err != nil {
		return errStage2aReservationAuthority
	}
	return s.beginStage2aCandidateRunV3(hqUID, selector, saved, approval, owner, state, base,
		guard, stage2aCandidateDesignatedHostCheckV3(install), stage2aCandidateInstalledQCheckV3(install))
}
