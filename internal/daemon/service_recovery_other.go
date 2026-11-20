//go:build !darwin

package daemon

func currentPairedServicePlan(verb, home, owner, id, digest string, uid int) (string, error) {
	return "", errRecoveryPlan
}
