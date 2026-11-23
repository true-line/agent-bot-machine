package members

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
)

type stage2aQualificationQReview struct {
	Owner                     string            `json:"owner"`
	PlanID                    string            `json:"plan_id"`
	PlanDigest                string            `json:"plan_digest"`
	HostUUID                  string            `json:"host_uuid"`
	HostID                    string            `json:"host_id"`
	InstallationID            string            `json:"installation_id"`
	QualificationStartID      string            `json:"qualification_start_id,omitempty"`
	ControlPeerInstallationID string            `json:"control_peer_installation_id,omitempty"`
	InstalledPlanDigest       string            `json:"installed_plan_digest"`
	TestPlan                  qualificationFile `json:"test_plan"`
	Provider                  qualificationFile `json:"provider"`
	DriverBaselineOnly        bool              `json:"driver_baseline_only,omitempty"`
	DriverLive                bool              `json:"driver_live,omitempty"`
}

var stage2aQualificationUUID = regexp.MustCompile(`^[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}$`)

func (r stage2aQualificationQReview) valid() bool {
	return r.Owner != "" && ValidApproval(r.PlanID, r.PlanDigest) &&
		stage2aQualificationUUID.MatchString(r.HostUUID) && stage2aQualificationPrintable(r.HostID, 128) &&
		soulInstallationID.MatchString(r.InstallationID) && digestPattern.MatchString(r.InstalledPlanDigest) &&
		stage2aAbsolutePath(r.TestPlan.Path) && stage2aAbsolutePath(r.Provider.Path) &&
		qualificationDigest.MatchString(r.TestPlan.SHA256) && qualificationDigest.MatchString(r.Provider.SHA256) &&
		!(r.DriverBaselineOnly && r.DriverLive) &&
		(!r.DriverLive || soulStartID.MatchString(r.QualificationStartID)) &&
		(r.DriverLive || r.QualificationStartID == "") &&
		(!r.DriverLive || soulInstallationID.MatchString(r.ControlPeerInstallationID) &&
			r.ControlPeerInstallationID != r.InstallationID) &&
		(r.DriverLive || r.ControlPeerInstallationID == "")
}

func observeStage2aQualificationHost(ctx context.Context, expected string) error {
	cmd := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil || len(out) > 128<<10 {
		return errQualificationAdmissionUnavailable
	}
	key := "\"IOPlatformUUID\" = \"" + expected + "\""
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == key {
			count++
		}
	}
	if count != 1 {
		return errQualificationAdmissionUnavailable
	}
	return nil
}
