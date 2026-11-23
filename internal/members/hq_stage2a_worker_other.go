//go:build !darwin

package members

import (
	"crypto/ed25519"
	"errors"
)

func RunStage2aHQEvidence(func(string, string, func(string) error) (ed25519.PrivateKey, string, error), func(string, string, string, func() error) error) int {
	return 78
}

func prepareHQStage2aApply(Saved, Approval, string, string, upgradePairGuard) (func(Step) error, error) {
	return nil, errors.New(hqStage2aCutoverRefusal)
}
