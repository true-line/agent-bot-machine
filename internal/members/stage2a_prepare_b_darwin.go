//go:build darwin

package members

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"time"
)

type stage2aNativeIdentity struct {
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
}
type stage2aNativeEndpoint struct {
	Path   string                `json:"path"`
	Parent stage2aNativeIdentity `json:"parent"`
	Socket stage2aNativeIdentity `json:"socket"`
}
type stage2aNativeSelectors struct {
	Installation string `json:"installation_id"`
	Start        string `json:"start_id"`
	Launch       string `json:"launch_id"`
	Plan         string `json:"plan_id"`
	PlanDigest   string `json:"plan_digest"`
	Reservation  string `json:"reservation_digest"`
}
type stage2aNativeAssignment struct {
	Version         string                 `json:"version"`
	Selectors       stage2aNativeSelectors `json:"selectors"`
	Epoch           string                 `json:"hq_epoch"`
	BridgeUID       uint32                 `json:"bridge_uid"`
	HQUID           uint32                 `json:"hq_uid"`
	RunnerUID       uint32                 `json:"runner_uid"`
	Expires         time.Time              `json:"expires_at"`
	Broker          stage2aNativeEndpoint  `json:"broker"`
	Relay           stage2aNativeEndpoint  `json:"relay"`
	Model           string                 `json:"model"`
	RequestDigest   string                 `json:"request_sha256"`
	HeadersDigest   string                 `json:"headers_sha256"`
	ClientKeyDigest string                 `json:"client_key_sha256"`
	HTTPHost        string                 `json:"http_host"`
	MessagesQuery   string                 `json:"messages_query"`
}

func stage2aNativeClaim(c Stage2aKernelNodeClaim) (stage2aNativeIdentity, error) {
	var out stage2aNativeIdentity
	if !validStage2aKernelClaim(c) {
		return out, errStage2aReservationAuthority
	}
	device, err := strconv.ParseUint(c.Device, 10, 64)
	inode, inodeErr := strconv.ParseUint(c.Inode, 10, 64)
	if err != nil || inodeErr != nil {
		return out, errStage2aReservationAuthority
	}
	return stage2aNativeIdentity{c.UID, c.GID, device, inode, c.Mode}, nil
}

// HQ attests its private broker inode after listen. A binds that claim to its
// installed selectors and one-use reservation. Native B independently reopens
// the exact inode and checks the kernel HQ peer before accepting the broker.
func (s *Stage2aService) PrepareB(hqUID int, epoch string, q Stage2aPrepareBRequest) (Stage2aPrepareBReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply Stage2aPrepareBReply
	if !validStage2aPrepareBSelector(q) || q.HQEpoch != epoch {
		return reply, errStage2aReservationAuthority
	}
	r, p, expires, err := s.current(hqUID, epoch, q.ReservationSHA256)
	if err != nil || len(r.bridgeAssignment) != 0 {
		return reply, errStage2aReservationAuthority
	}
	a := r.payload.Assignment
	if a.InstallationID != q.InstallationID || a.StartID != q.StartID || a.LaunchID != q.LaunchID ||
		a.PlanID != q.PlanID || a.PlanDigest != q.PlanDigest || a.HQEpoch != q.HQEpoch {
		return reply, errStage2aReservationAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, q.StartID)
	if err != nil || q.Broker.Path != ends.Broker.SocketPath || filepath.Dir(q.Broker.Path) != ends.Broker.Directory ||
		q.Broker.Parent.UID != uint32(p.HQUID) || q.Broker.Parent.GID != uint32(p.Bridge.GID) ||
		q.Broker.Parent.Mode != 02750 || q.Broker.Socket.UID != uint32(p.HQUID) ||
		q.Broker.Socket.GID != uint32(p.Bridge.GID) || q.Broker.Socket.Mode != 0660 {
		return reply, errStage2aReservationAuthority
	}
	parent, err := stage2aNativeClaim(q.Broker.Parent)
	if err != nil {
		return reply, err
	}
	socket, err := stage2aNativeClaim(q.Broker.Socket)
	if err != nil {
		return reply, err
	}
	relayInode, err := strconv.ParseUint(p.RelayParent.Inode, 10, 64)
	if err != nil || relayInode == 0 || p.RelayParent.Path != ends.Relay.Directory ||
		p.RelayParent.Device <= 0 {
		return reply, errStage2aReservationAuthority
	}
	assignment := stage2aNativeAssignment{
		Version:   "stage2a-b-assignment/v2",
		Selectors: stage2aNativeSelectors{q.InstallationID, q.StartID, q.LaunchID, q.PlanID, q.PlanDigest, q.ReservationSHA256},
		Epoch:     epoch, BridgeUID: uint32(p.Bridge.UID), HQUID: uint32(p.HQUID), RunnerUID: uint32(p.Runner.UID), Expires: expires,
		Broker: stage2aNativeEndpoint{q.Broker.Path, parent, socket},
		Relay: stage2aNativeEndpoint{ends.Relay.SocketPath,
			stage2aNativeIdentity{uint32(p.Bridge.UID), uint32(p.Runner.GID), uint64(uint32(p.RelayParent.Device)), relayInode, 02750},
			stage2aNativeIdentity{uint32(p.Bridge.UID), uint32(p.Runner.GID), 0, 0, 0660}},
		Model: p.BridgeQualification.Model, RequestDigest: p.BridgeQualification.RequestSHA256,
		HeadersDigest: p.BridgeQualification.HeadersSHA256, ClientKeyDigest: p.BridgeQualification.ClientKeySHA256,
		HTTPHost: p.BridgeQualification.HTTPHost, MessagesQuery: p.BridgeQualification.MessagesQuery,
	}
	raw, err := json.Marshal(assignment)
	if err != nil || len(raw) == 0 || len(raw) > stage2aBridgeMaxAssignment || stage2aStrictJSON(raw) != nil {
		return reply, errStage2aReservationAuthority
	}
	// Durable prepare claim prevents replacing the H-attested socket identity
	// within this reservation. Restart loses the in-memory assignment and the
	// active installation fence remains spent, so no replay can relaunch B.
	store, _ := p.stores()
	dir, err := store.open()
	if err != nil {
		return reply, err
	}
	defer dir.Close()
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return reply, err
	}
	defer lock.Close()
	name := ".stage2a-b-prepare-" + soulStartClaimName(q.InstallationID, q.StartID)
	if store.checkDirectory(dir) != nil || requireUnspentStage2aReservation(dir, name) != nil ||
		!time.Now().Before(expires) {
		return reply, errStage2aReservationAuthority
	}
	if err := spendStage2aAdminName(dir, name, store.uid, store.gid); err != nil {
		return reply, err
	}
	r.bridgeAssignment = raw
	sum := sha256.Sum256(raw)
	return Stage2aPrepareBReply{AssignmentSHA256: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

var _ = errors.New
