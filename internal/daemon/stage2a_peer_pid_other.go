//go:build !darwin

package daemon

import (
	"errors"
	"net"
)

func stage2aPeerPID(net.Conn) (int, error) {
	return 0, errors.New("Stage 2a measured HQ peer requires Darwin")
}
