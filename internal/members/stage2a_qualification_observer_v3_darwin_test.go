package members

import "testing"

func TestQualificationAssignmentUsesHQUIDNotHQGID(t *testing.T) {
	install := stage2aQualificationQInstall{
		AdminUID: 501, HQUID: 309, HQGID: 621, RunnerGID: 622, BridgeGID: 623,
		Review: stage2aQualificationQReview{InstalledPlanDigest: "plan-digest"},
	}
	assignment := stage2aReservationAssignmentV3{stage2aReservationAssignment: stage2aReservationAssignment{
		SoulStartAssignment: SoulStartAssignment{
			MachineUID: 501, HQUID: 309, RunnerGID: 622, BridgeGID: 623,
			PlanDigest: "plan-digest", StartID: "start-1",
		},
	}}
	if !stage2aQualificationAssignmentMatchesQInstall(assignment, install, "start-1") {
		t.Fatal("matching HQ UID must pass when its GID differs")
	}
	assignment.HQUID = install.HQGID
	if stage2aQualificationAssignmentMatchesQInstall(assignment, install, "start-1") {
		t.Fatal("matching HQ GID must not substitute for HQ UID")
	}
}
