//go:build !darwin

package members

import "errors"

func RunStage2aQualificationOwnerDriver() error {
	return errors.New("Stage 2a owner driver requires macOS")
}
