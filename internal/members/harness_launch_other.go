//go:build !darwin

package members

import "errors"

var errHarnessPlatform = errors.New("reviewed harness launch grants require macOS")

func planHarnessRequest(string, string, Host) (*HarnessPolicyRecord, error) {
	return nil, errHarnessPlatform
}
func inspectHarnessLaunch(HarnessPolicyRecord) error        { return errHarnessPlatform }
func matchingInstalledHarness(string, Host) (string, error) { return "", errHarnessPlatform }
