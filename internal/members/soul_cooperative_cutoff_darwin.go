//go:build darwin

package members

import "golang.org/x/sys/unix"

// A releases a cooperative slot only after both fixed guest roles are idle.
func soulCooperativeGuestRolesIdle(p SoulCooperativeLaunchPolicy) bool {
	if p.Bridge == nil {
		return false
	}
	return requireIdleHarnessRoles([]HarnessAdapter{
		{Account: p.Runner.Account, UID: p.Runner.UID},
		{Account: p.Bridge.Account, UID: p.Bridge.UID},
	}, unix.SysctlKinfoProcSlice) == nil
}

func soulCooperativeGuestEndpointsAbsent(p SoulCooperativeLaunchPolicy, startID string) bool {
	if p.Bridge == nil || startID != p.ReviewedStartID {
		return false
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, startID)
	return err == nil && soulCooperativeLeafAbsent(ends.Admission.SocketPath) &&
		soulCooperativeLeafAbsent(ends.Broker.SocketPath) &&
		soulCooperativeLeafAbsent(ends.Member.SocketPath) &&
		soulCooperativeLeafAbsent(ends.Relay.SocketPath)
}
