//go:build !darwin

package members

import "errors"

var errHarnessPlatform = errors.New("reviewed harness launch grants require macOS")

func planHarnessRequest(string, string, Host) (*HarnessPolicyRecord, error) {
	return nil, errHarnessPlatform
}
func inspectHarnessLaunch(HarnessPolicyRecord) error        { return errHarnessPlatform }
func matchingInstalledHarness(string, Host) (string, error) { return "", errHarnessPlatform }

func applyHarnessGrant(Saved, Approval, string, string, upgradePairGuard) error {
	return errHarnessPlatform
}

func finishAbsentHarnessRetirement(Saved, string, string, upgradePairGuard) (string, error) {
	return "", nil
}

func completedHarnessInstall(Saved, string, string, upgradePairGuard) (bool, error) {
	return false, errHarnessPlatform
}
