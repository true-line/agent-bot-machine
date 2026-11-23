//go:build !darwin

package daemon

import "crypto/ed25519"

func stage2aHandler(ed25519.PrivateKey, string, string) func(Request) Response { return nil }

func stage2aServiceHandlers(ed25519.PrivateKey, string, string) (func(Request) Response, cooperativeRecoveryApply) {
	return nil, nil
}
