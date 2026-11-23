//go:build darwin

package members

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCooperativeBridgeSignedWireMatchesContracts85(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-cooperative-bridge-signed.v3.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString("md_slh0rlGaEmhWfslcpMB7g1Z1yFL5fexfxrYCl25o")
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := verifySoulCooperativePurposeV3(bytes.TrimSpace(raw), key,
		soulCooperativeBridgeAssignmentPurposeV3)
	if err != nil {
		t.Fatalf("Contracts #85 signed B wire refused: %v", err)
	}
	var assignment soulCooperativeBridgeAssignmentPayloadV3
	if err := json.Unmarshal(payload, &assignment); err != nil {
		t.Fatal(err)
	}
	bridge, err := marshalStage2aReservationJCS(assignment.Bridge)
	if err != nil || assignment.BridgeLaunchSHA256 != stage2aReservationSHA256(bridge) ||
		assignment.Contract != "machine/v3" || assignment.Kind != "soul-cooperative-bridge-assignment" ||
		assignment.SchemaVersion != 3 || assignment.ReservationSHA256 == "" {
		t.Fatal("Contracts #85 signed B selectors or bridge digest changed")
	}
}

func TestCooperativeBridgeLaunchUsesContracts85Digest(t *testing.T) {
	raw, err := os.ReadFile("testdata/stage2a-cooperative-bridge-launch.v3.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var bridge soulCooperativeBLaunchV3
	if err := json.Unmarshal(raw, &bridge); err != nil {
		t.Fatal(err)
	}
	canonical, err := marshalStage2aReservationJCS(bridge)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:fab50fc3f566ea3e09e15b91090cb5d5c7ec5975054839509112cc710f579689"
	if got := stage2aReservationSHA256(canonical); got != want {
		t.Fatalf("Contracts #85 bridge launch digest: %s", got)
	}
	bridge.Argv[2] += "-other"
	changed, err := marshalStage2aReservationJCS(bridge)
	if err != nil || stage2aReservationSHA256(changed) == want {
		t.Fatal("changed broker socket retained bridge launch digest")
	}
}

func TestCooperativeBIntentBindsRetainedParentIdentities(t *testing.T) {
	p, _, _, _, _ := cooperativeTwoMemberPolicyFixture(t)
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID)
	if err != nil {
		t.Fatal(err)
	}
	parent := func(path, inode string) stage2aInstalledDirectory {
		return stage2aInstalledDirectory{Path: path, Device: 1, Inode: inode,
			BirthSeconds: 1795356936, BirthNanoseconds: 0}
	}
	parents := soulCooperativeBParentsV3{Broker: parent(ends.Broker.Directory, "2001"),
		Member: parent(ends.Member.Directory, "2002"), Relay: parent(ends.Relay.Directory, "2003")}
	bridge, endpoint, digest, err := soulCooperativeBLaunchIntentV3(p, p.ReviewedStartID, parents)
	if err != nil || !stage2aPrefixedDigest.MatchString(digest) ||
		bridge.Account != p.Bridge.Account || bridge.ExecutablePath != SoulBridgeBinary ||
		endpoint.Broker.ExpectedPeerUID != p.Bridge.UID ||
		endpoint.Member.ExpectedPeerUID != p.Bridge.UID ||
		endpoint.Relay.ExpectedPeerUID != p.Runner.UID ||
		endpoint.Member.ParentInode != "2002" || endpoint.Relay.ParentBirthtimeNS != "1795356936000000000" {
		t.Fatalf("reviewed B intent mismatch: %v", err)
	}
	parents.Member.Inode = "0"
	if _, _, _, err := soulCooperativeBLaunchIntentV3(p, p.ReviewedStartID, parents); err == nil {
		t.Fatal("invalid retained member parent was accepted")
	}
	if _, _, _, err := soulCooperativeBLaunchIntentV3(p, "st_"+strings.Repeat("0", 24),
		soulCooperativeBParentsV3{Broker: parent(ends.Broker.Directory, "2001"),
			Member: parent(ends.Member.Directory, "2002"), Relay: parent(ends.Relay.Directory, "2003")}); err == nil {
		t.Fatal("unreviewed start selected B endpoints")
	}
}
