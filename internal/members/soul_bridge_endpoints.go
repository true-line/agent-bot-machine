package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
)

// SoulEndpoint describes a per-start Unix socket directory that Machine must
// provision and recheck before HQ admits either process. PeerUID is the only
// kernel peer admitted by the listener; directory and socket modes are exact.
type SoulEndpoint struct {
	Directory  string
	SocketPath string
	OwnerUID   int
	GroupGID   int
	PeerUID    int
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
	endpoint := func(root, name string, owner, group, peer int) SoulEndpoint {
		dir := path.Join(launchRuntimeDir, root, slot)
		return SoulEndpoint{Directory: dir, SocketPath: path.Join(dir, name),
			OwnerUID: owner, GroupGID: group, PeerUID: peer, DirMode: 02750, SocketMode: 0660}
	}
	brokerDir := path.Join(DarwinBrokerDir, b.Account)
	result := SoulBridgeEndpoints{
		Broker: SoulEndpoint{Directory: brokerDir, SocketPath: path.Join(brokerDir, "broker.sock"),
			OwnerUID: hqUID, GroupGID: b.GID, PeerUID: b.UID, DirMode: 02750, SocketMode: 0660},
		Member:    endpoint("m", "member.sock", r.UID, b.GID, b.UID),
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
