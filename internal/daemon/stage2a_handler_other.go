//go:build !darwin

package daemon

import "crypto/ed25519"

func stage2aHandler(ed25519.PrivateKey, *stage2aT02KeydMonitor) func(Request) Response { return nil }
