//go:build !darwin

package members

import "errors"

func inspectUpgradeJob(HQService, string) (bool, string, error) {
	return false, "", errors.New("HQ service upgrade requires macOS")
}

func activateUpgrade(Step, Approval, upgradePairGuard) error {
	return errors.New("HQ service upgrade requires macOS")
}

func resumeServiceUpgrade(Saved, string, upgradePairGuard) (bool, error) { return false, nil }
func currentUpgradeReceipt(Approval, string) (Receipt, error) {
	return Receipt{}, errors.New("HQ upgrade requires macOS")
}

func claimUpgradeReceipt(string, []byte) error { return errors.New("HQ upgrade requires macOS") }
