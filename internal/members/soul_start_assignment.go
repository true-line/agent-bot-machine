package members

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"
)

// SoulStartAssignment is a prepared, nonauthorizing body for a future signed
// Machine response. HQ must verify that response against its enrolled Machine
// key and a live installed rule. This value alone cannot permit a launch.
// There are no B-only tokens, broker bindings or caller-selected paths here.
type SoulStartAssignment struct {
	Schema         string            `json:"schema"`
	InstallationID string            `json:"installation_id"`
	SoulID         string            `json:"soul_id"`
	StartID        string            `json:"start_id"`
	LaunchID       string            `json:"launch_id"`
	PlanID         string            `json:"plan_id"`
	PlanDigest     string            `json:"plan_digest"` // installed bare 64-hex digest
	HQEpoch        string            `json:"hq_epoch"`
	ExpiresAt      string            `json:"expires_at"`
	RunnerAccount  string            `json:"runner_account"`
	RunnerUID      int               `json:"runner_uid"`
	RunnerGID      int               `json:"runner_gid"`
	BridgeAccount  string            `json:"bridge_account"`
	BridgeUID      int               `json:"bridge_uid"`
	BridgeGID      int               `json:"bridge_gid"`
	HQUID          int               `json:"hq_uid"`
	MachineUID     int               `json:"machine_uid"`
	PackageRoot    string            `json:"package_root"`
	PackageSHA256  string            `json:"package_sha256"`
	Broker         SoulStartEndpoint `json:"broker"`
	Member         SoulStartEndpoint `json:"member"`
	Relay          SoulStartEndpoint `json:"relay"`
	Admission      SoulStartEndpoint `json:"admission"`
}

type SoulStartEndpoint struct {
	Directory  string `json:"directory"`
	SocketPath string `json:"socket_path"`
	OwnerUID   int    `json:"owner_uid"`
	GroupGID   int    `json:"group_gid"`
	DirMode    uint32 `json:"dir_mode"`
	SocketMode uint32 `json:"socket_mode"`
	PeerUIDs   []int  `json:"peer_uids"`
}

func startEndpoint(e SoulEndpoint) SoulStartEndpoint {
	return SoulStartEndpoint{Directory: e.Directory, SocketPath: e.SocketPath,
		OwnerUID: e.OwnerUID, GroupGID: e.GroupGID, DirMode: e.DirMode,
		SocketMode: e.SocketMode, PeerUIDs: append([]int(nil), e.PeerUIDs...)}
}

var soulLaunchID = regexp.MustCompile(`^ln_[0-9a-f]{24}$`)

// PrepareSoulStartAssignment binds a pre-Hello start to the two reviewed
// principals and Machine-derived endpoint names. HQ mints runtime_id only
// after the runner's Hello, so it cannot appear in this prestart body.
// PackageSHA256 is copied from a proposed review field, not measured from a
// canonical .soul artifact.
// The caller must first load the installed plan and verify its root receipt,
// accepted owner policy and live roles; the eventual
// reservation operation must additionally consume this start durably before
// returning a Machine-signed response. No such operation exists yet.
func PrepareSoulStartAssignment(r SoulRunner, b SoulBridge, hqUID, machineUID int,
	planID, planDigest, startID, launchID, hqEpoch string,
	now, expires time.Time) (SoulStartAssignment, error) {
	invalid := errors.New("invalid protected Soul start assignment")
	if !ValidApproval(planID, planDigest) || !soulStartID.MatchString(startID) ||
		!soulLaunchID.MatchString(launchID) ||
		!soulHQEpoch.MatchString(hqEpoch) || machineUID <= 399 ||
		machineUID == hqUID || machineUID == r.UID || machineUID == b.UID ||
		now.IsZero() || expires.IsZero() || !expires.After(now) || expires.Sub(now) > 30*time.Second {
		return SoulStartAssignment{}, invalid
	}
	endpoints, err := DeriveSoulBridgeEndpoints(r, b, hqUID, startID)
	if err != nil {
		return SoulStartAssignment{}, invalid
	}
	return SoulStartAssignment{
		Schema: "agent-bot-machine/soul-start-assignment/v2", InstallationID: r.InstallationID,
		SoulID: r.SoulID, StartID: startID, LaunchID: launchID,
		PlanID: planID, PlanDigest: planDigest, HQEpoch: hqEpoch,
		ExpiresAt:     expires.UTC().Format(time.RFC3339Nano),
		RunnerAccount: r.Account, RunnerUID: r.UID, RunnerGID: r.GID,
		BridgeAccount: b.Account, BridgeUID: b.UID, BridgeGID: b.GID,
		HQUID: hqUID, MachineUID: machineUID,
		PackageRoot: r.PackageRoot, PackageSHA256: r.PackageSHA256,
		Broker: startEndpoint(endpoints.Broker), Member: startEndpoint(endpoints.Member),
		Relay: startEndpoint(endpoints.Relay), Admission: startEndpoint(endpoints.Admission),
	}, nil
}

// SoulReportPlanDigest converts an assignment's bare plan digest to the
// sha256-prefixed host-report form only when it matches the installed plan.
// The caller must load these canonical bytes from the installed plan and
// verify its root receipt before using this value in a signer.
func SoulReportPlanDigest(assignment SoulStartAssignment, installedID string, installedCanonical []byte) (string, error) {
	installedDigest := fmt.Sprintf("%x", sha256.Sum256(installedCanonical))
	if assignment.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		len(installedCanonical) == 0 ||
		!ValidApproval(assignment.PlanID, assignment.PlanDigest) ||
		!ValidApproval(installedID, installedDigest) ||
		assignment.PlanID != installedID || assignment.PlanDigest != installedDigest {
		return "", errors.New("Soul report plan digest does not match the installed plan")
	}
	return "sha256:" + installedDigest, nil
}

// CheckSoulStartAssignment re-derives every assignment field from the
// installed canonical plan and reviewed roles at the point of use. The caller
// must separately verify the root installation receipt, live HQ start,
// Machine signature, one-use claim, and current endpoint state. This check
// cannot grant launch authority by itself.
func CheckSoulStartAssignment(assignment SoulStartAssignment, installedID string, installedCanonical []byte,
	runner SoulRunner, bridge SoulBridge, hqUID, machineUID int,
	live SoulRunRequest, launchID string, now time.Time) error {
	invalid := errors.New("Soul start assignment differs from installed authority")
	if !live.valid() || live.InstallationID != runner.InstallationID ||
		live.PlanDigest != assignment.PlanDigest {
		return invalid
	}
	if _, err := SoulReportPlanDigest(assignment, installedID, installedCanonical); err != nil {
		return invalid
	}
	expires, err := time.Parse(time.RFC3339Nano, assignment.ExpiresAt)
	if err != nil {
		return invalid
	}
	want, err := PrepareSoulStartAssignment(runner, bridge, hqUID, machineUID,
		installedID, live.PlanDigest, live.StartID, launchID,
		live.HQEpoch, now, expires)
	if err != nil || !reflect.DeepEqual(assignment, want) {
		return invalid
	}
	return nil
}
