package members

import "testing"

func TestSoulBridgeEndpointsUseOnlyReviewedPrincipalsAndPerStartPaths(t *testing.T) {
	runners, bridges := runnerFixture(), bridgeFixture()
	first, err := DeriveSoulBridgeEndpoints(runners[0], bridges[0], 309, "st_0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveSoulBridgeEndpoints(runners[0], bridges[0], 309, "st_0123456789abcdef01234568")
	if err != nil {
		t.Fatal(err)
	}
	other, err := DeriveSoulBridgeEndpoints(runners[1], bridges[1], 309, "st_0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	if first.Member.SocketPath == second.Member.SocketPath || first.Member.SocketPath == other.Member.SocketPath ||
		first.Relay.SocketPath == second.Relay.SocketPath || first.Relay.SocketPath == other.Relay.SocketPath ||
		first.Admission.SocketPath == second.Admission.SocketPath || first.Admission.SocketPath == other.Admission.SocketPath {
		t.Fatal("per-start endpoint collision")
	}
	if first.Broker.OwnerUID != 309 || first.Broker.GroupGID != bridges[0].GID || first.Broker.PeerUID != bridges[0].UID ||
		first.Member.OwnerUID != runners[0].UID || first.Member.GroupGID != bridges[0].GID || first.Member.PeerUID != bridges[0].UID ||
		first.Relay.OwnerUID != bridges[0].UID || first.Relay.GroupGID != runners[0].GID || first.Relay.PeerUID != runners[0].UID ||
		first.Admission.OwnerUID != 309 || first.Admission.GroupGID != runners[0].GID || first.Admission.PeerUID != runners[0].UID {
		t.Fatal("endpoint crossed a reviewed account boundary")
	}
	for _, channel := range []SoulEndpoint{first.Broker, first.Member, first.Relay, first.Admission} {
		if channel.DirMode != 02750 || channel.SocketMode != 0660 || len(channel.SocketPath) > 103 {
			t.Fatalf("unusable Unix endpoint: %+v", channel)
		}
	}
	if _, err := DeriveSoulBridgeEndpoints(runners[0], bridges[1], 309, "st_0123456789abcdef01234567"); err == nil {
		t.Fatal("accepted sibling bridge")
	}
	if _, err := DeriveSoulBridgeEndpoints(runners[0], bridges[0], 309, "st_invalid"); err == nil {
		t.Fatal("accepted unreviewed start")
	}
}
