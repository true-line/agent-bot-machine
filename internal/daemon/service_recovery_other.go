//go:build !darwin

package daemon

import "crypto/ed25519"

func currentPairedServicePlan(verb, home, owner, id, digest string, uid int, machine ed25519.PublicKey) (string, error) {
	return "", errRecoveryPlan
}

func CheckHQUpgradePair(string, string, string, func() error) error { return errRecoveryPlan }
