//go:build !darwin && !linux

package daemon

func readMembersPlans(home, option, id string) ([]byte, error) {
	return nil, errMembersPlans
}
