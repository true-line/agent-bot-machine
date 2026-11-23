//go:build darwin

package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os/user"
	"strconv"
	"time"
)

// The first protected qualification uses the root-installed Q plan and its
// spent owner approval. There is deliberately no ordinary qualified fallback:
// a released adapter qualification needs its own authenticated loader.
func loadStage2aCandidateWorkerAuthorityV3(runtime stage2aInstalledRuntimeV3, key ed25519.PublicKey,
	checkPair func(string, string, string, func() error) error) (stage2aReservationWorkerAuthorityV3, error) {
	var empty stage2aReservationWorkerAuthorityV3
	if checkPair == nil || len(key) != ed25519.PublicKeySize || runtime.Policy.RuntimeV3 == nil {
		return empty, errStage2aReservationAuthority
	}
	install, err := loadStage2aQualificationQInstall()
	p := runtime.Policy
	if err != nil || !stage2aCandidateInstallMatchesRuntimeV3(install, runtime) {
		return empty, errStage2aReservationAuthority
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(key))
	saved, approval, owner, state, err := loadStage2aCandidatePlanSourceV3(install, fingerprint)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	if err != nil || checkPair(state, account.Username, approval.PairCommitment, nil) != nil {
		return empty, errStage2aReservationAuthority
	}
	store, _ := p.stores()
	hostCheck := stage2aCandidateDesignatedHostCheckV3(install)
	qCheck := stage2aCandidateInstalledQCheckV3(install)
	return stage2aReservationWorkerAuthorityV3{
		mode: stage2aCandidateRunV3, store: store,
		loadCandidate: func(req stage2aReservationRequest) (stage2aQualificationCandidateAuthorityV3, error) {
			var noAuthority stage2aQualificationCandidateAuthorityV3
			if checkPair(state, account.Username, approval.PairCommitment, nil) != nil {
				return noAuthority, errStage2aReservationAuthority
			}
			base, err := loadStage2aReservationEvidenceV3(req, runtime, key, stage2aReservationAdapterV3{}, nil)
			if err != nil {
				return noAuthority, err
			}
			a, sealedR, err := stage2aPrepareCandidateAuthorityV3(saved, approval, owner, state,
				p.HQUID, base, hostCheck, qCheck)
			if err != nil || stage2aRecheckVerifiedDomainV3(sealedR) != nil {
				return noAuthority, errStage2aReservationAuthority
			}
			if _, err := stage2aCandidateAttemptV3(a, time.Now()); err != nil {
				return noAuthority, errStage2aReservationAuthority
			}
			return a, nil
		},
	}, nil
}
