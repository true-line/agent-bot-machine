//go:build darwin

package members

import "slices"

func cooperativeReviewedAdmission(p SoulCooperativeLaunchPolicy) (SoulCooperativeEndpoint, error) {
	if p.Bridge == nil || p.LaunchInputs == nil || !soulStartID.MatchString(p.ReviewedStartID) {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID)
	if err != nil || !slices.Contains(p.LaunchInputs.Argv, ends.Admission.SocketPath) {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return soulCooperativeEndpointFromSoul(ends.Admission, p.Runner.UID), nil
}

func cooperativeBrokerEndpoint(p SoulCooperativeLaunchPolicy) (SoulCooperativeEndpoint, error) {
	if p.Bridge == nil || !soulStartID.MatchString(p.ReviewedStartID) {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID)
	if err != nil {
		return SoulCooperativeEndpoint{}, errSoulCooperativeAuthority
	}
	return soulCooperativeEndpointFromSoul(ends.Broker, p.Bridge.UID), nil
}

func soulCooperativeEndpointFromSoul(e SoulEndpoint, peer int) SoulCooperativeEndpoint {
	return SoulCooperativeEndpoint{Directory: e.Directory, SocketPath: e.SocketPath,
		OwnerUID: e.OwnerUID, GroupGID: e.GroupGID, DirMode: int(e.DirMode),
		SocketMode: int(e.SocketMode), PeerUID: peer}
}
