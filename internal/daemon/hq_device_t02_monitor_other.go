//go:build !darwin

package daemon

import "context"

type stage2aT02KeydMonitor struct{}

func newStage2aT02KeydMonitor() *stage2aT02KeydMonitor { return &stage2aT02KeydMonitor{} }

func (*stage2aT02KeydMonitor) provider(ctx context.Context, home string, d deviceDelegation) ([]byte, error) {
	return runDeviceKeyd(ctx, home, d)
}
