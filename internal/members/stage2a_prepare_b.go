package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Device and inode are strings on HQ's signed request so JavaScript cannot
// round a 64-bit kernel identity. Machine emits exact uint64 JSON numbers only
// inside the B assignment that the native Go relay independently reopens.
type Stage2aKernelNodeClaim struct {
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Device string `json:"device"`
	Inode  string `json:"inode"`
	Mode   uint32 `json:"mode"`
}
type Stage2aBrokerClaim struct {
	Path   string                 `json:"path"`
	Parent Stage2aKernelNodeClaim `json:"parent"`
	Socket Stage2aKernelNodeClaim `json:"socket"`
}
type Stage2aPrepareBRequest struct {
	ReservationSHA256 string             `json:"reservation_sha256"`
	InstallationID    string             `json:"installation_id"`
	StartID           string             `json:"start_id"`
	LaunchID          string             `json:"launch_id"`
	PlanID            string             `json:"plan_id"`
	PlanDigest        string             `json:"plan_digest"`
	HQEpoch           string             `json:"hq_epoch"`
	Broker            Stage2aBrokerClaim `json:"broker"`
}
type Stage2aPrepareBReply struct {
	AssignmentSHA256 string `json:"assignment_sha256"`
}

func ParseStage2aPrepareBRequest(raw []byte) (Stage2aPrepareBRequest, error) {
	var q Stage2aPrepareBRequest
	if len(raw) == 0 || len(raw) > 4096 || stage2aStrictJSON(raw) != nil {
		return q, errors.New("invalid Stage 2a B preparation")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || !validStage2aPrepareBSelector(q) {
		return Stage2aPrepareBRequest{}, errors.New("invalid Stage 2a B preparation")
	}
	return q, nil
}

func validStage2aPrepareBSelector(q Stage2aPrepareBRequest) bool {
	return strings.HasPrefix(q.ReservationSHA256, "sha256:") && stage2aLowerHex64(strings.TrimPrefix(q.ReservationSHA256, "sha256:")) &&
		soulInstallationID.MatchString(q.InstallationID) && soulStartID.MatchString(q.StartID) &&
		soulLaunchID.MatchString(q.LaunchID) && ValidApproval(q.PlanID, q.PlanDigest) &&
		soulHQEpoch.MatchString(q.HQEpoch) && stage2aAbsolutePath(q.Broker.Path) &&
		len(q.Broker.Path) <= 103 && validStage2aKernelClaim(q.Broker.Parent) &&
		validStage2aKernelClaim(q.Broker.Socket)
}

func validStage2aKernelClaim(c Stage2aKernelNodeClaim) bool {
	if !stage2aDecimal.MatchString(c.Device) || !stage2aDecimal.MatchString(c.Inode) {
		return false
	}
	device, err := strconv.ParseUint(c.Device, 10, 64)
	inode, inodeErr := strconv.ParseUint(c.Inode, 10, 64)
	return err == nil && inodeErr == nil && device > 0 && inode > 0
}
