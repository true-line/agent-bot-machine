//go:build darwin

package members

import (
	"strings"
	"testing"
)

func TestStage2aLiveQReviewPinsOneStart(t *testing.T) {
	review := stage2aQualificationQReview{
		Owner: "machine-admin", PlanID: "plan-20261122T141516Z-abcd",
		PlanDigest: strings.Repeat("a", 64),
		HostUUID:   "A0000000-0000-0000-0000-000000000001", HostID: "disposable-test-only",
		InstallationID: "inst_0000000000000001", InstalledPlanDigest: strings.Repeat("b", 64),
		TestPlan: qualificationFile{Path: "/private/tmp/test-plan", SHA256: strings.Repeat("c", 64)},
		Provider: qualificationFile{Path: "/private/tmp/provider", SHA256: strings.Repeat("d", 64)},
	}
	if !review.valid() {
		t.Fatal("ordinary review should be valid")
	}
	review.QualificationStartID = "st_000000000000000000000001"
	if review.valid() {
		t.Fatal("unreviewed start ID accepted without live driver")
	}
	review.DriverLive = true
	review.ControlPeerInstallationID = "inst_0000000000000002"
	if !review.valid() {
		t.Fatal("live driver with reviewed start ID should be valid")
	}
	review.QualificationStartID = "st_bad"
	if review.valid() {
		t.Fatal("malformed live start ID accepted")
	}
	review.QualificationStartID = ""
	if review.valid() {
		t.Fatal("live driver accepted without pinned start ID")
	}
	review.QualificationStartID = "st_000000000000000000000001"
	review.ControlPeerInstallationID = review.InstallationID
	if review.valid() {
		t.Fatal("live driver accepted its own installation as control peer")
	}
}
