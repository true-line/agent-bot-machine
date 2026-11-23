package members

// These fixed locations and account names are candidates for owner review.
// This definition alone never publishes a sudo rule or provisions a role.
const (
	stage2aQualificationQAccount = "_abm-qual-q"
	stage2aQualificationQCommand = "stage2a-qualification-observe"
	stage2aQualificationQRule    = "/private/etc/sudoers.d/agent-bot-stage2a-qualification-q"
	stage2aQualificationQHome    = "/private/var/db/managed-machine/qualification-q"
	stage2aQualificationQSocket  = "/private/var/db/managed-machine/q"
)

// Each explicitly reviewed supplemental group must identify a stock macOS
// group. Q still has no access to another role's group or general filesystem.
func validStage2aQualificationQGroups(primary int, supplemental []int, protectedRoles ...int) bool {
	checked := map[int]bool{primary: true}
	for _, gid := range supplemental {
		switch gid {
		case 12, 61, 100, 701:
		default:
			return false
		}
		if checked[gid] {
			return false
		}
		checked[gid] = true
	}
	for _, gid := range protectedRoles {
		if gid <= 0 || checked[gid] {
			return false
		}
	}
	return true
}

func exactStage2aQualificationQGroups(observed []int, primary int, reviewed []int) bool {
	// Some kernels omit the primary group from getgroups; accept that
	// difference only. Its real/effective/saved IDs are checked separately.
	want := make(map[int]bool, len(reviewed))
	for _, gid := range reviewed {
		want[gid] = true
	}
	for _, gid := range observed {
		if gid == primary {
			continue
		}
		if !want[gid] {
			return false
		}
		delete(want, gid)
	}
	return len(want) == 0
}
