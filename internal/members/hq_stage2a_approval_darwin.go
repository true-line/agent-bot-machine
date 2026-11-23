package members

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// The offline installer rechecks the persisted paired-owner approval and the
// root claim receipt. An approved source digest is authoritative only for the
// exact complete saved plan, including limits and the release manifest hashes.
func checkHQStage2aPairedApproval(saved Saved, rec launchRecord, a Approval, key ed25519.PublicKey,
	daemonDir, owner string, pairing upgradePairGuard, claimed bool) error {
	s := rec.Service.Stage2a
	if s == nil || !hqStage2aIsOfflineAdmin(*s) || pairing == nil || len(key) != ed25519.PublicKeySize ||
		a.MachineFingerprint != fmt.Sprintf("%x", sha256.Sum256(key)) || !digestPattern.MatchString(a.PairCommitment) ||
		!matchesReviewedHQPlist(rec, owner, launchControlV2) {
		return errStage2aReservationAuthority
	}
	if err := checkHQStage2aApprovedRecord(saved, rec, a, owner); err != nil {
		return err
	}
	return checkHQStage2aStoredApproval(*s, a, daemonDir, owner, pairing, claimed)
}

func checkHQStage2aStoredApproval(s hqStage2aService, a Approval, daemonDir, owner string,
	pairing upgradePairGuard, claimed bool) error {
	if !ValidApproval(a.PlanID, a.PlanDigest) || a.Purpose != UpgradePurpose || pairing == nil ||
		!digestPattern.MatchString(a.MachineFingerprint) || !digestPattern.MatchString(a.PairCommitment) {
		return errStage2aReservationAuthority
	}
	stored, why := loadApproval(OSHost{}, daemonDir, s.MachineAccount, a.PlanID, PlatformDarwin, time.Now())
	if why != "" || stored != a {
		return errStage2aReservationAuthority
	}
	if err := pairing(a, nil); err != nil {
		return err
	}
	if claimed {
		receipt, err := currentUpgradeReceipt(a, owner)
		if err != nil || receipt.Result != "started" {
			return errStage2aReservationAuthority
		}
	}
	return nil
}

func checkHQStage2aApprovedRecord(saved Saved, rec launchRecord, a Approval, owner string) error {
	if saved.UpgradeFrom == nil || saved.HQService == nil || saved.HQService.Stage2a == nil ||
		!reflect.DeepEqual(*saved.HQService, rec.Service) || a.Purpose != UpgradePurpose ||
		!ValidApproval(a.PlanID, a.PlanDigest) || a.PlanID != saved.PlanID || a.PlanDigest != saved.PlanDigest {
		return errStage2aReservationAuthority
	}
	plan := saved.Plan
	if plan.Version != PlanVersion || plan.HQAccount != DarwinHQAccount || plan.Dir != DarwinDir ||
		len(plan.Members) != 0 || len(plan.Steps) != 2 {
		return errStage2aReservationAuthority
	}
	step := plan.Steps[1]
	var reviewed launchUpgrade
	if step.Kind != KindService || step.Target != launchLabel || step.Action != upgradeAction || step.Owner != owner ||
		json.Unmarshal([]byte(step.Content), &reviewed) != nil || !reflect.DeepEqual(reviewed.Next, rec) ||
		reviewed.Previous.Service.Stage2a != nil || reviewed.Previous.Stage2a != nil {
		return errStage2aReservationAuthority
	}
	digest, err := plan.Digest()
	priorDigest, priorErr := saved.UpgradeFrom.Plan.Digest()
	if err != nil || digest != a.PlanDigest || priorErr != nil || priorDigest != reviewed.PreviousDigest ||
		reviewed.PreviousID != saved.UpgradeFrom.ID || !ValidApproval(reviewed.PreviousID, priorDigest) {
		return errStage2aReservationAuthority
	}
	return nil
}
