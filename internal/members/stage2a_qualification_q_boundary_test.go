//go:build darwin

package members

import "testing"

func TestStage2aQualificationQGroupsRejectDriftAndProtectedRoles(t *testing.T) {
	known := []int{12, 61, 100, 701}
	if !validStage2aQualificationQGroups(450, known, 20, 309, 331, 333) ||
		!exactStage2aQualificationQGroups([]int{450, 12, 61, 701, 100}, 450, known) {
		t.Fatal("exact measured stock groups refused")
	}
	if validStage2aQualificationQGroups(450, known, 20, 309, 331, 701) ||
		validStage2aQualificationQGroups(450, []int{12, 61, 80}, 20, 309, 331, 333) ||
		exactStage2aQualificationQGroups([]int{450, 12, 61, 701, 100, 333}, 450, known) ||
		exactStage2aQualificationQGroups([]int{450, 12, 61, 701}, 450, known) {
		t.Fatal("unreviewed or protected role group vector accepted")
	}
}

func TestStage2aQualificationQSocketFitsDarwinAddress(t *testing.T) {
	const darwinSUNPathSize = 104
	if len(stage2aQualificationQSessionPath) >= darwinSUNPathSize {
		t.Fatal("qualification socket exceeds Darwin Unix address size")
	}
}
