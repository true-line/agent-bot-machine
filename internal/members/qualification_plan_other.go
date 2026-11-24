//go:build !darwin

package members

import "errors"

func verifyQualificationExecutable(string, string) error {
	return errors.New("qualification executable verification is supported only on Darwin")
}

func verifyQualificationPendingQSource(qualificationFile) error {
	return errors.New("pending Q source verification is supported only on Darwin")
}
