//go:build !darwin

package members

import "errors"

func verifyQualificationExecutable(string, string) error {
	return errors.New("qualification executable verification is supported only on Darwin")
}
