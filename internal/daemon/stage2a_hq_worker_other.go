//go:build !darwin

package daemon

import "crypto/ed25519"

func ReadStage2aReservationWorkerKey(int, string, string) (ed25519.PrivateKey, func() error, error) {
	return nil, nil, errHQDevice
}

func ReadStage2aHQWorkerKey(string, string, func(string) error) (ed25519.PrivateKey, string, error) {
	return nil, "", errChannelIdentity
}
