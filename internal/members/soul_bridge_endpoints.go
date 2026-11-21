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

// DeriveSoulBridgeEndpoints accepts identity, not caller-chosen paths. The
// 96-bit per-start directory names fit Darwin's 103-byte Unix socket limit;
// Machine must still create them exclusively and refuse an occupied name.
func DeriveSoulBridgeEndpoints(r SoulRunner, b SoulBridge, hqUID int, startID string) (SoulBridgeEndpoints, error) {
	invalid := errors.New("invalid protected Soul endpoint assignment")
	if !soulStartID.MatchString(startID) || ValidateSoulBridges([]SoulRunner{r}, []SoulBridge{b}, hqUID, nil) != nil {
		return SoulBridgeEndpoints{}, invalid
	}
	sum := sha256.Sum256([]byte("agent-bot-soul-start/v1\x00" + r.InstallationID + "\x00" + startID))
	slot := fmt.Sprintf("%x", sum[:12])
	endpoint := func(root, name string, owner, group int, peers ...int) SoulEndpoint {
		dir := path.Join(launchRuntimeDir, root, slot)
		return SoulEndpoint{Directory: dir, SocketPath: path.Join(dir, name),
			OwnerUID: owner, GroupGID: group, PeerUIDs: peers, DirMode: 02750, SocketMode: 0660}
	}
	brokerDir := path.Join(DarwinBrokerDir, b.Account)
	result := SoulBridgeEndpoints{
		Broker: SoulEndpoint{Directory: brokerDir, SocketPath: path.Join(brokerDir, "broker.sock"),
			OwnerUID: hqUID, GroupGID: b.GID, PeerUIDs: []int{b.UID}, DirMode: 02750, SocketMode: 0660},
		Member:    endpoint("m", "member.sock", r.UID, b.GID, r.UID, b.UID),
		Relay:     endpoint("s", "http.sock", b.UID, r.GID, r.UID),
		Admission: endpoint("r", "admission.sock", hqUID, r.GID, r.UID),
	}
	for _, channel := range []SoulEndpoint{result.Broker, result.Member, result.Relay, result.Admission} {
		if len(channel.SocketPath) > 103 {
			return SoulBridgeEndpoints{}, invalid
		}
	}
	return result, nil
}
