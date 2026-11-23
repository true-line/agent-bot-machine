//go:build !darwin

package members

import "crypto/ed25519"

func RunStage2aReservationWorkerV3(
	func(int, string, string) (ed25519.PrivateKey, func() error, error),
	func(string, string, string, func() error) error) int {
	return 78
}
