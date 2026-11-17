//go:build !linux

package members

import "errors"

func checkHQFileCapabilities(string) error {
	return errors.New("HQ service installation requires Linux")
}
