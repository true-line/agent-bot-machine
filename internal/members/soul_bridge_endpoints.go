package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
)

// SoulEndpoint describes a per-start Unix socket directory that Machine must
// provision and recheck before HQ admits either process. PeerUIDs is
// the exact kernel peer set; member protocol authority still depends on the
// authenticated start and purpose. Directory and socket modes are exact.
type SoulEndpoint struct {
	Directory  string
	SocketPath string
	OwnerUID   int
	GroupGID   int
	PeerUIDs   []int
	DirMode    uint32
	SocketMode uint32
}

// SoulBridgeEndpoints binds one start to four different channels. Only the
// bridge receives the HQ broker endpoint; the vendor client receives Member
// and Relay. Admission is used by the runner's control process before vendor
// confinement, never as a third vendor-client outbound path.
type SoulBridgeEndpoints struct {
	Broker    SoulEndpoint
	Member    SoulEndpoint
	Relay     SoulEndpoint
	Admission SoulEndpoint
}

// SoulMemberLaunchAssignment is the exact member_endpoint fragment Souls
// accepts in an HQ launch reply. Machine signs this assignment with the
// start; HQ may not invent a directory or omit either allowed peer.
type SoulMemberLaunchAssignment struct {
	MemberSocket   string `json:"member_socket"`
	MemberEndpoint struct {
		Directory  string `json:"directory"`
		OwnerUID   int    `json:"owner_uid"`
		GroupGID   int    `json:"group_gid"`
		DirMode    uint32 `json:"dir_mode"`
		SocketMode uint32 `json:"socket_mode"`
		PeerUIDs   []int  `json:"peer_uids"`
	} `json:"member_endpoint"`
}

func (e SoulBridgeEndpoints) MemberLaunchAssignment() SoulMemberLaunchAssignment {
	var assignment SoulMemberLaunchAssignment
	assignment.MemberSocket = e.Member.SocketPath
	assignment.MemberEndpoint.Directory = e.Member.Directory
	assignment.MemberEndpoint.OwnerUID = e.Member.OwnerUID
	assignment.MemberEndpoint.GroupGID = e.Member.GroupGID
	assignment.MemberEndpoint.DirMode = e.Member.DirMode
	assignment.MemberEndpoint.SocketMode = e.Member.SocketMode
	assignment.MemberEndpoint.PeerUIDs = append([]int(nil), e.Member.PeerUIDs...)
	return assignment
}

func soulEndpointInstallationSlot(installationID string) string {
	sum := sha256.Sum256([]byte("agent-bot-soul-endpoint-installation/v1\x00" + installationID))
	return fmt.Sprintf("%x", sum[:10])
}

func soulEndpointStartSlot(installationID, startID string) string {
	sum := sha256.Sum256([]byte("agent-bot-soul-endpoint-start/v1\x00" + installationID + "\x00" + startID))
	return fmt.Sprintf("%x", sum[:10])
}

// DeriveSoulBridgeEndpoints accepts identity, not caller-chosen paths. Machine
// provisions the cross-owned installation directories during paired review;
// the socket basename is start-specific. No runtime target-user launcher needs
// root or membership in another role's private group to create a parent.
// Machine must reject an occupied socket name and enforce one live start per
// installation. The short names fit Darwin's 103-byte Unix socket limit.
func DeriveSoulBridgeEndpoints(r SoulRunner, b SoulBridge, hqUID int, startID string) (SoulBridgeEndpoints, error) {
	invalid := errors.New("invalid protected Soul endpoint assignment")
	if !soulStartID.MatchString(startID) || ValidateSoulBridges([]SoulRunner{r}, []SoulBridge{b}, hqUID, nil) != nil {
		return SoulBridgeEndpoints{}, invalid
	}
	installationSlot := soulEndpointInstallationSlot(r.InstallationID)
	startSocket := soulEndpointStartSlot(r.InstallationID, startID) + ".sock"
	endpoint := func(root string, owner, group int, peers ...int) SoulEndpoint {
		dir := path.Join(launchRuntimeDir, root, installationSlot)
		return SoulEndpoint{Directory: dir, SocketPath: path.Join(dir, startSocket),
			OwnerUID: owner, GroupGID: group, PeerUIDs: peers, DirMode: 02750, SocketMode: 0660}
	}
	brokerDir := path.Join(DarwinBrokerDir, b.Account)
	result := SoulBridgeEndpoints{
		Broker: SoulEndpoint{Directory: brokerDir, SocketPath: path.Join(brokerDir, "broker.sock"),
			OwnerUID: hqUID, GroupGID: b.GID, PeerUIDs: []int{b.UID}, DirMode: 02750, SocketMode: 0660},
		Member:    endpoint("m", r.UID, b.GID, r.UID, b.UID),
		Relay:     endpoint("s", b.UID, r.GID, r.UID),
		Admission: endpoint("r", hqUID, r.GID, r.UID),
	}
	for _, channel := range []SoulEndpoint{result.Broker, result.Member, result.Relay, result.Admission} {
		if len(channel.SocketPath) > 103 {
			return SoulBridgeEndpoints{}, invalid
		}
	}
	return result, nil
}
