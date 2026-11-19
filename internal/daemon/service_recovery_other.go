//go:build !darwin

package daemon

func currentRecoveryPlan(home, owner, id, digest string, uid int) (string, error) {
	return "", errRecoveryPlan
}
