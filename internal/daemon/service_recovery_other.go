//go:build !darwin

package daemon

func currentPairedServicePlan(verb, home, owner, id, digest string, uid int) (string, error) {
	return "", errRecoveryPlan
}

func CheckHQUpgradePair(string, string, string, func() error) error { return errRecoveryPlan }
