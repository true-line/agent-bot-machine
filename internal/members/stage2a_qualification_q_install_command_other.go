//go:build !darwin

package members

import "errors"

func RunStage2aQualificationQInstall(ApplyDeps, []string) error {
	return errors.New("qualification observer installation requires Darwin")
}

func RunStage2aQualificationQRemove(ApplyDeps, []string) error {
	return errors.New("qualification observer removal requires Darwin")
}
