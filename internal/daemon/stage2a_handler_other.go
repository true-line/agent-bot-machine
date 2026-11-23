//go:build !darwin

package daemon

import "crypto/ed25519"

func stage2aHandler(ed25519.PrivateKey) func(Request) Response { return nil }
