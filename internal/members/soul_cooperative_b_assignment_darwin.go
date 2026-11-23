//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const soulCooperativeBridgeAssignmentPurposeV3 = "agent-bot/soul-cooperative-bridge-assignment/v3"

// The parent identities are captured and retained by A's installed record.
// Neither H's start request nor R's FD3 frame may supply these fields.
type soulCooperativeBParentsV3 struct {
	Broker stage2aInstalledDirectory
	Member stage2aInstalledDirectory
	Relay  stage2aInstalledDirectory
}

type soulCooperativeBEndpointV3 struct {
	Directory         string `json:"directory"`
	SocketPath        string `json:"socket_path"`
	OwnerUID          int    `json:"owner_uid"`
	GroupGID          int    `json:"group_gid"`
	DirMode           uint32 `json:"dir_mode"`
	SocketMode        uint32 `json:"socket_mode"`
	ExpectedPeerUID   int    `json:"expected_peer_uid"`
	ParentDevice      string `json:"parent_device"`
	ParentInode       string `json:"parent_inode"`
	ParentBirthtimeNS string `json:"parent_birthtime_ns"`
}

type soulCooperativeBLaunchV3 struct {
	Account              string   `json:"account"`
	UID                  int      `json:"uid"`
	GID                  int      `json:"gid"`
	StateRoot            string   `json:"state_root"`
	StateRootMode        string   `json:"state_root_mode"`
	ExecutablePath       string   `json:"executable_path"`
	ExecutableSHA256     string   `json:"executable_sha256"`
	SandboxProfilePath   string   `json:"sandbox_profile_path"`
	SandboxProfileSHA256 string   `json:"sandbox_profile_sha256"`
	Argv                 []string `json:"argv"`
}

type soulCooperativeBEndpointsV3 struct {
	Broker soulCooperativeBEndpointV3 `json:"broker"`
	Member soulCooperativeBEndpointV3 `json:"member"`
	Relay  soulCooperativeBEndpointV3 `json:"relay"`
}

type soulCooperativeBridgeAssignmentPayloadV3 struct {
	Contract           string                      `json:"contract"`
	Kind               string                      `json:"kind"`
	SchemaVersion      int                         `json:"schema_version"`
	HostID             string                      `json:"host_id"`
	InstallationID     string                      `json:"installation_id"`
	StartID            string                      `json:"start_id"`
	LaunchID           string                      `json:"launch_id"`
	PlanID             string                      `json:"plan_id"`
	PlanDigest         string                      `json:"plan_digest"`
	HQEpoch            string                      `json:"hq_epoch"`
	ExpiresAt          string                      `json:"expires_at"`
	ReservationSHA256  string                      `json:"reservation_sha256"`
	BridgeLaunchSHA256 string                      `json:"bridge_launch_sha256"`
	Bridge             soulCooperativeBLaunchV3    `json:"bridge"`
	Endpoints          soulCooperativeBEndpointsV3 `json:"endpoints"`
}

type soulCooperativeBReservationViewV3 struct {
	Contract           string `json:"contract"`
	Kind               string `json:"kind"`
	SchemaVersion      int    `json:"schema_version"`
	HostID             string `json:"host_id"`
	IssuedAt           string `json:"issued_at"`
	ExpiresAt          string `json:"expires_at"`
	BridgeLaunchSHA256 string `json:"bridge_launch_sha256"`
	AdapterTransport   string `json:"adapter_transport"`
	Assignment         struct {
		InstallationID     string `json:"installation_id"`
		SoulID             string `json:"soul_id"`
		StartID            string `json:"start_id"`
		LaunchID           string `json:"launch_id"`
		PlanID             string `json:"plan_id"`
		PlanDigest         string `json:"plan_digest"`
		HQEpoch            string `json:"hq_epoch"`
		RunnerUID          int    `json:"runner_uid"`
		RunnerGID          int    `json:"runner_gid"`
		HQUID              int    `json:"hq_uid"`
		MachineUID         int    `json:"machine_uid"`
		RuntimeRoot        string `json:"runtime_root"`
		PackageRoot        string `json:"package_root"`
		LaunchInputsRoot   string `json:"launch_inputs_root"`
		StateRoot          string `json:"state_root"`
		NodePath           string `json:"node_path"`
		EntryPath          string `json:"entry_path"`
		PackageSHA256      string `json:"package_sha256"`
		SoulArtifactSHA256 string `json:"soul_artifact_sha256"`
	} `json:"assignment"`
	Endpoints struct {
		Member soulCooperativeBEndpointV3 `json:"member"`
		Relay  soulCooperativeBEndpointV3 `json:"relay"`
	} `json:"endpoints"`
	MeasurementBinding struct {
		Stage2aMeasurementBinding
		HDescriptorDigest string                      `json:"h_service_descriptor_digest"`
		RInventory        stage2aDomainInventoryRefV3 `json:"r_inventory"`
	} `json:"measurement_binding"`
}

func soulCooperativeBEndpointFromRetainedV3(want SoulEndpoint, peer int,
	retained stage2aInstalledDirectory) (soulCooperativeBEndpointV3, error) {
	var empty soulCooperativeBEndpointV3
	if retained.Path != want.Directory || retained.Device <= 0 || retained.Inode == "" ||
		retained.BirthSeconds <= 0 || retained.BirthNanoseconds < 0 ||
		retained.BirthNanoseconds >= 1_000_000_000 ||
		want.DirMode != 02750 || want.SocketMode != 0660 || peer <= 0 ||
		!stage2aAbsolutePath(want.SocketPath) || filepath.Dir(want.SocketPath) != retained.Path {
		return empty, errSoulCooperativeAuthority
	}
	inode, err := strconv.ParseUint(retained.Inode, 10, 64)
	if err != nil || inode == 0 || strconv.FormatUint(inode, 10) != retained.Inode ||
		retained.BirthSeconds > (1<<63-1-retained.BirthNanoseconds)/1_000_000_000 {
		return empty, errSoulCooperativeAuthority
	}
	birth := retained.BirthSeconds*1_000_000_000 + retained.BirthNanoseconds
	return soulCooperativeBEndpointV3{Directory: want.Directory, SocketPath: want.SocketPath,
		OwnerUID: want.OwnerUID, GroupGID: want.GroupGID, DirMode: want.DirMode,
		SocketMode: want.SocketMode, ExpectedPeerUID: peer,
		ParentDevice: strconv.FormatUint(uint64(uint32(retained.Device)), 10),
		ParentInode:  retained.Inode, ParentBirthtimeNS: strconv.FormatInt(birth, 10)}, nil
}

func soulCooperativeBLaunchIntentV3(p SoulCooperativeLaunchPolicy, startID string,
	parents soulCooperativeBParentsV3) (soulCooperativeBLaunchV3, soulCooperativeBEndpointsV3, string, error) {
	var empty soulCooperativeBLaunchV3
	var emptyEndpoints soulCooperativeBEndpointsV3
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 || p.validate() != nil ||
		p.Bridge == nil || p.BridgeExecutable == nil || startID != p.ReviewedStartID {
		return empty, emptyEndpoints, "", errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, startID)
	if err != nil {
		return empty, emptyEndpoints, "", errSoulCooperativeAuthority
	}
	broker, e1 := soulCooperativeBEndpointFromRetainedV3(ends.Broker, p.Bridge.UID, parents.Broker)
	member, e2 := soulCooperativeBEndpointFromRetainedV3(ends.Member, p.Bridge.UID, parents.Member)
	relay, e3 := soulCooperativeBEndpointFromRetainedV3(ends.Relay, p.Runner.UID, parents.Relay)
	if e1 != nil || e2 != nil || e3 != nil {
		return empty, emptyEndpoints, "", errSoulCooperativeAuthority
	}
	endpoints := soulCooperativeBEndpointsV3{Broker: broker, Member: member, Relay: relay}
	argv := []string{"/usr/bin/sandbox-exec", "-D", "BROKER_SOCKET=" + broker.SocketPath,
		"-D", "MEMBER_SOCKET=" + member.SocketPath, "-D", "RELAY_SOCKET=" + relay.SocketPath,
		"-f", SoulBridgeSandbox, SoulBridgeBinary,
		"--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"}
	bridge := soulCooperativeBLaunchV3{Account: p.Bridge.Account, UID: p.Bridge.UID, GID: p.Bridge.GID,
		StateRoot: path.Join(darwinSoulBridgeHome(p.Bridge.Account), "state"), StateRootMode: "0700",
		ExecutablePath: SoulBridgeBinary, ExecutableSHA256: "sha256:" + p.BridgeExecutable.SHA256,
		SandboxProfilePath: SoulBridgeSandbox, SandboxProfileSHA256: "sha256:" + harnessSHA(soulBridgeProfile),
		Argv: argv}
	canonical, err := marshalStage2aReservationJCS(bridge)
	if err != nil {
		return empty, emptyEndpoints, "", errSoulCooperativeAuthority
	}
	return bridge, endpoints, stage2aReservationSHA256(canonical), nil
}

// A's paired caller passes only a record reconstructed from its installed
// store. This signer reopens the root receipt and fixed pin, rechecks the
// retained H/R/B parent identities, and accepts only A's own signed v3
// reservation. The pair and installation locks are held by the caller.
func signSoulCooperativeBridgeAssignmentV3(in SoulCooperativeInstalledAuthority,
	reservationEnvelope []byte, parents soulCooperativeBParentsV3, now time.Time,
	key ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, string, error) {
	p := in.Policy
	if p.Schema != soulCooperativeTwoMemberInstallSchemaV3 || !in.matchesInstalledRecord() ||
		p.validate() != nil || len(key) != ed25519.PublicKeySize || sign == nil ||
		os.Getuid() != p.MachineUID || os.Geteuid() != p.MachineUID ||
		os.Getgid() != p.MachineGID || os.Getegid() != p.MachineGID ||
		base64.RawURLEncoding.EncodeToString(key) != p.MachinePublicKey {
		return nil, "", errSoulCooperativeAuthority
	}
	pin, err := stage2aReadRootFile(SoulAuthorityPin, ed25519.PublicKeySize, 0444)
	if err != nil || !bytes.Equal(pin, key) {
		return nil, "", errSoulCooperativeAuthority
	}
	root, err := stage2aReadRootFile(ReceiptPath(in.PlanID), 256<<10, 0644)
	if err != nil || !bytes.Equal(root, in.RootReceipt) {
		return nil, "", errSoulCooperativeAuthority
	}
	for _, parent := range []struct {
		identity     stage2aInstalledDirectory
		owner, group int
	}{{parents.Broker, p.HQUID, p.Bridge.GID},
		{parents.Member, p.Runner.UID, p.Bridge.GID},
		{parents.Relay, p.Bridge.UID, p.Runner.GID}} {
		if !soulCooperativeRecheckBParentV3(parent.identity, parent.owner, parent.group) {
			return nil, "", errSoulCooperativeAuthority
		}
	}
	reservationRaw, reservationSHA, err := verifySoulCooperativeEnvelopeV3(reservationEnvelope, key)
	if err != nil {
		return nil, "", errSoulCooperativeAuthority
	}
	var reservation soulCooperativeBReservationViewV3
	runtimeRoot := path.Dir(path.Dir(p.NodePath))
	inputsRoot := cooperativeReviewedInputsRoot(p.Runner.InstallationID)
	if json.Unmarshal(reservationRaw, &reservation) != nil ||
		reservation.Contract != "machine/v3" || reservation.Kind != "soul-cooperative-reservation" ||
		reservation.SchemaVersion != 3 || reservation.AdapterTransport != "brokered-b" ||
		reservation.HostID != p.HostID || reservation.Assignment.InstallationID != p.Runner.InstallationID ||
		reservation.Assignment.SoulID != p.Runner.SoulID || reservation.Assignment.StartID != p.ReviewedStartID ||
		!soulLaunchID.MatchString(reservation.Assignment.LaunchID) ||
		reservation.Assignment.PlanID != in.PlanID || reservation.Assignment.PlanDigest != in.PlanDigest ||
		reservation.Assignment.HQEpoch != p.HQEpoch || reservation.Assignment.RunnerUID != p.Runner.UID ||
		reservation.Assignment.RunnerGID != p.Runner.GID ||
		reservation.Assignment.HQUID != p.HQUID || reservation.Assignment.MachineUID != p.MachineUID ||
		reservation.Assignment.RuntimeRoot != runtimeRoot ||
		reservation.Assignment.PackageRoot != p.Runner.PackageRoot ||
		reservation.Assignment.LaunchInputsRoot != inputsRoot ||
		reservation.Assignment.StateRoot != path.Join("/private/var", "agent-bot-soul-runner-"+p.Runner.Account, "state") ||
		reservation.Assignment.NodePath != p.NodePath ||
		reservation.Assignment.EntryPath != path.Join(runtimeRoot, p.Entry) ||
		reservation.Assignment.PackageSHA256 != p.Runner.PackageSHA256 ||
		reservation.Assignment.SoulArtifactSHA256 != p.ArtifactSHA256 ||
		reservation.MeasurementBinding.ProfileInForce != "managed-cooperative" ||
		reservation.MeasurementBinding.HostID != p.HostID ||
		reservation.MeasurementBinding.InstallationID != p.Runner.InstallationID ||
		reservation.MeasurementBinding.SoulID != p.Runner.SoulID ||
		reservation.MeasurementBinding.StartID != p.ReviewedStartID ||
		reservation.MeasurementBinding.LaunchID != reservation.Assignment.LaunchID ||
		reservation.MeasurementBinding.PlanID != in.PlanID ||
		reservation.MeasurementBinding.SoulArtifactSHA256 != p.ArtifactSHA256 ||
		reservation.MeasurementBinding.ClaimedDefinitionDigest != "sha256:"+p.DefinitionSHA256 ||
		reservation.MeasurementBinding.HDescriptorDigest != in.ObservedHDescriptorSHA256 ||
		reservation.MeasurementBinding.RInventory.InventoryDigest != in.ObservedRInventorySHA256 ||
		!stage2aPrefixedDigest.MatchString(in.ObservedHDescriptorSHA256) ||
		!stage2aPrefixedDigest.MatchString(in.ObservedRInventorySHA256) ||
		reservation.MeasurementBinding.DefinitionMeasurement != p.DefinitionMeasurement ||
		reservation.MeasurementBinding.LaunchInputMeasurement != p.LaunchInputMeasurement ||
		reservation.MeasurementBinding.InstalledPlanDigest != in.PlanDigest ||
		reservation.MeasurementBinding.HQEpoch != p.HQEpoch ||
		reservation.MeasurementBinding.Snapshots.Definition.RootPath != p.Runner.PackageRoot ||
		reservation.MeasurementBinding.Snapshots.LaunchInputs.RootPath != inputsRoot ||
		reservation.MeasurementBinding.RInventory.Snapshot.Path != runtimeRoot {
		return nil, "", errSoulCooperativeAuthority
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, reservation.IssuedAt)
	expires, err := time.Parse(time.RFC3339Nano, reservation.ExpiresAt)
	if issueErr != nil || err != nil || issued.After(now) || !now.Before(expires) ||
		expires.Sub(issued) <= 0 || expires.Sub(issued) > 30*time.Second {
		return nil, "", errSoulCooperativeAuthority
	}
	bridge, endpoints, digest, err := soulCooperativeBLaunchIntentV3(p, reservation.Assignment.StartID, parents)
	if err != nil || digest != reservation.BridgeLaunchSHA256 ||
		!reflect.DeepEqual(reservation.Endpoints.Member, endpoints.Member) ||
		!reflect.DeepEqual(reservation.Endpoints.Relay, endpoints.Relay) {
		return nil, "", errSoulCooperativeAuthority
	}
	payload := soulCooperativeBridgeAssignmentPayloadV3{Contract: "machine/v3",
		Kind: "soul-cooperative-bridge-assignment", SchemaVersion: 3, HostID: p.HostID,
		InstallationID: p.Runner.InstallationID, StartID: reservation.Assignment.StartID,
		LaunchID: reservation.Assignment.LaunchID, PlanID: in.PlanID, PlanDigest: in.PlanDigest,
		HQEpoch: p.HQEpoch, ExpiresAt: reservation.ExpiresAt,
		ReservationSHA256: reservationSHA, BridgeLaunchSHA256: digest,
		Bridge: bridge, Endpoints: endpoints}
	envelope, err := signStage2aEnvelope(payload, 3, soulCooperativeBridgeAssignmentPurposeV3, key, sign)
	if err != nil || !time.Now().Before(expires) {
		return nil, "", errSoulCooperativeAuthority
	}
	return envelope, stage2aReservationSHA256(envelope), nil
}

func soulCooperativeRecheckBParentV3(parent stage2aInstalledDirectory, owner, group int) bool {
	if parent.Path == "" || parent.Device <= 0 || parent.Inode == "" ||
		parent.BirthSeconds <= 0 || parent.BirthNanoseconds < 0 {
		return false
	}
	dir, err := openStage2aAdminDirectory(filepath.Dir(parent.Path), uint32(os.Getuid()))
	if err != nil {
		return false
	}
	defer dir.Close()
	var st unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), filepath.Base(parent.Path), &st, unix.AT_SYMLINK_NOFOLLOW) == nil &&
		st.Mode == unix.S_IFDIR|02750 && st.Uid == uint32(owner) && st.Gid == uint32(group) && st.Dev == parent.Device &&
		fmt.Sprint(st.Ino) == parent.Inode && st.Btim.Sec == parent.BirthSeconds &&
		st.Btim.Nsec == parent.BirthNanoseconds && checkDarwinACLs([]string{parent.Path}) == nil
}
