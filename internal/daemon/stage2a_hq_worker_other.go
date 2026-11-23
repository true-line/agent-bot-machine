//go:build !darwin

package daemon

import "crypto/ed25519"

func ReadStage2aHQWorkerKey(string, string, func(string) error) (ed25519.PrivateKey, string, error) {
	return nil, "", errChannelIdentity
}
