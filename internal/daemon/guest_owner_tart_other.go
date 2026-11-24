//go:build !darwin

package daemon

func readAdminGuestChallenge(string, Caller) ([]byte, error) {
	return nil, errGuestOwnerPermit
}
