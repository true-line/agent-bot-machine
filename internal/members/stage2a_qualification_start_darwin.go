//go:build darwin

package members

import (
	"errors"
	"os"
)

// A reports only the one start ID pinned in the current owner-reviewed Q
// install. An occupied invalid Q descriptor refuses rather than silently
// restoring HQ's ordinary random start selection.
func stage2aQualificationPreparedStart(installationID, installedPlanDigest string) (string, error) {
	info, err := os.Lstat(stage2aQualificationQConfig)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return "", errStage2aReservationAuthority
	}
	install, err := loadStage2aQualificationQInstall()
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	if install.Review.InstallationID != installationID || !install.Review.DriverLive {
		return "", nil
	}
	if install.Review.InstalledPlanDigest != installedPlanDigest ||
		!soulStartID.MatchString(install.Review.QualificationStartID) {
		return "", errStage2aReservationAuthority
	}
	return install.Review.QualificationStartID, nil
}
