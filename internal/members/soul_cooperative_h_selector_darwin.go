//go:build darwin

package members

import (
	"crypto/ed25519"
	"encoding/json"
)

func (s *Stage2aService) CooperativeInstalledHSelectorV3(hqUID int, epoch,
	installationID string) (SoulCooperativeHSelectorV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var selector SoulCooperativeHSelectorV3
	if len(s.key) != ed25519.PrivateKeySize {
		return selector, errSoulCooperativeAuthority
	}
	installed, r, err := loadSoulCooperativeInstalledV3(
		s.key.Public().(ed25519.PublicKey), hqUID, epoch, installationID)
	if err != nil || stage2aRecheckVerifiedDomainV3(r) != nil {
		return selector, errSoulCooperativeAuthority
	}
	return cooperativeHSelectorFromInstalled(installed)
}

func cooperativeHSelectorFromInstalled(installed soulCooperativeInstalledV3) (
	SoulCooperativeHSelectorV3, error) {
	var selector SoulCooperativeHSelectorV3
	var receipt Receipt
	if json.Unmarshal(installed.RootReceipt, &receipt) != nil ||
		!ValidApproval(receipt.PlanID, receipt.PlanDigest) || receipt.Owner == "" {
		return selector, errSoulCooperativeAuthority
	}
	p := installed.Policy
	if p.HOwnerPlanDigest == "" || p.HQInstallationID == "" ||
		p.HOwnerPlanDigest == "sha256:"+receipt.PlanDigest {
		return selector, errSoulCooperativeAuthority
	}
	return SoulCooperativeHSelectorV3{HOwnerPlanDigest: p.HOwnerPlanDigest,
		HQInstallationID: p.HQInstallationID, CooperativePlanID: receipt.PlanID,
		CooperativePlanDigest: receipt.PlanDigest, Owner: receipt.Owner}, nil
}
