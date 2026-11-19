//go:build !darwin

package daemon

import "context"

// Requires a platform-reviewed local custody provider and authenticated HQ role.
func runDeviceKeyd(context.Context, string, deviceDelegation) ([]byte, error) {
	return nil, errHQDevice
}
