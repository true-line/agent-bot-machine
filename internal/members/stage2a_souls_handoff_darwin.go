package members

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aSoulsStartLimit = 64 << 10

type stage2aSoulsProtectedStart struct {
	Schema                       string                    `json:"schema"`
	ReservationEnvelopeBase64URL string                    `json:"reservation_envelope_base64url"`
	ReservationSHA256            string                    `json:"reservation_sha256"`
	MachinePinPath               string                    `json:"machine_pin_path"`
	LaunchInputRecords           Stage2aLaunchInputRecords `json:"launch_input_records"`
	StateRoot                    string                    `json:"state_root"`
}

func verifyStage2aRunnerReservation(run Stage2aRunnerExec, in Stage2aRoleInvocation,
	pub ed25519.PublicKey, now time.Time) (stage2aDomainInventoryRefV3, error) {
	var empty stage2aDomainInventoryRefV3
	invalid := errors.New("Soul runner reservation differs from Machine's signed start")
	raw, err := decodeStage2aRoleBase64(run.ReservationEnvelopeBase64URL, stage2aV3EnvelopeLimit)
	if err != nil {
		return empty, invalid
	}
	guard, err := verifyStage2aReservationModeV3(stage2aReservationRunModeV3(run.ReservationRunModeV3), raw,
		run.ReservationSHA256, run.ReservationV3, pub, now)
	if err != nil {
		return empty, invalid
	}
	start := guard.assignment.SoulStartAssignment
	binding := guard.binding
	mode := stage2aReservationRunModeV3(run.ReservationRunModeV3)
	ordinary := start.Schema == stage2aAssignmentSchemaV3 && binding.Contract == "machine/v3" && binding.SchemaVersion == 3
	localTest := mode == stage2aLocalTestRunV1 && start.Schema == stage2aLocalTestAssignmentSchemaV1 &&
		binding.Contract == "machine/local-test-v1" && binding.SchemaVersion == 1
	if !ordinary && !localTest {
		return empty, invalid
	}
	start.Schema = in.Start.Schema
	binding.Contract, binding.SchemaVersion = in.Binding.Contract, in.Binding.SchemaVersion
	r := guard.r
	if !((guard.payload.Contract == "machine/v3" && guard.payload.SchemaVersion == 3) ||
		(guard.payload.Contract == "machine/local-test-v1" && guard.payload.SchemaVersion == 1 &&
			stage2aReservationRunModeV3(run.ReservationRunModeV3) == stage2aLocalTestRunV1)) ||
		!reflect.DeepEqual(start, in.Start) || !reflect.DeepEqual(binding, in.Binding) ||
		start.InstallationID != in.Request.InstallationID || start.StartID != in.Request.StartID ||
		start.HQEpoch != in.Request.HQEpoch || start.PlanDigest != in.Request.PlanDigest ||
		start.RunnerUID != os.Getuid() || start.RunnerUID != os.Geteuid() || start.RunnerGID != os.Getegid() ||
		guard.assignment.SoulArtifactSHA256 == "" || binding.SoulArtifactSHA256 != string(guard.assignment.SoulArtifactSHA256) ||
		!stage2aPrefixedDigest.MatchString(guard.assignment.HDescriptorDigest) ||
		guard.assignment.HDescriptorDigest != guard.hDigest ||
		guard.assignment.RInventoryDigest != r.InventoryDigest || r.Domain != "R-runtime" ||
		r.InstallationID != start.InstallationID || r.OwnerPlanDigest != "sha256:"+start.PlanDigest ||
		r.ReaderUID != uint32(start.RunnerUID) || r.ReaderGID != uint32(start.RunnerGID) || r.MachineUID != uint32(start.MachineUID) ||
		recheckHQStage2aDomainFiles(r) != nil {
		return empty, invalid
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(in.Launch)
	if err != nil || launchDigest != binding.LaunchInputMeasurement {
		return empty, invalid
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.Runner, in.Bridge, in.Start.HQUID, in.Request.StartID)
	if err != nil || !reflect.DeepEqual(guard.member, endpoints.MemberLaunchAssignment()) {
		return empty, invalid
	}
	return r, nil
}

func stage2aRunnerStateRoot(runner SoulRunner) (string, error) {
	invalid := errors.New("Soul runner state root is not private to its assigned UID")
	if !soulInstallationID.MatchString(runner.InstallationID) ||
		runner.Account != soulRunnerName(runner.InstallationID) ||
		runner.UID != os.Getuid() || runner.UID != os.Geteuid() || runner.GID != os.Getegid() {
		return "", invalid
	}
	home := darwinSoulRunnerHome(runner.Account)
	dir, err := openStage2aAdminDirectory(home, uint32(runner.UID))
	if err != nil {
		return "", invalid
	}
	defer dir.Close()
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Uid != uint32(runner.UID) ||
		st.Gid != uint32(runner.GID) || st.Mode != unix.S_IFDIR|0700 {
		return "", invalid
	}
	state := filepath.Join(home, "state")
	parent, err := stage2aOpenRunnerStateDir(int(dir.Fd()), "state", state, runner)
	if err != nil {
		return "", invalid
	}
	defer unix.Close(parent)
	return state, nil
}

func stage2aOpenRunnerStateDir(parent int, name, path string, runner SoulRunner) (int, error) {
	if err := unix.Mkdirat(parent, name, 0700); err != nil && err != unix.EEXIST {
		return -1, err
	}
	fd, err := unix.Openat(parent, name, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(runner.UID) ||
		st.Gid != uint32(runner.GID) || st.Mode != unix.S_IFDIR|0700 {
		unix.Close(fd)
		return -1, errors.New("Soul runner state directory has wrong owner or mode")
	}
	if actual, err := stage2aFDPath(fd); err != nil || actual != path || checkDarwinACLs([]string{path}) != nil {
		unix.Close(fd)
		return -1, errors.New("Soul runner state directory path changed")
	}
	return fd, nil
}

func marshalStage2aSoulsProtectedStart(envelope, digest string, launch Stage2aLaunchInputRecords,
	stateRoot string) ([]byte, error) {
	if !validStage2aExecDigest(digest) || envelope == "" || stateRoot == "" {
		return nil, errors.New("invalid protected Souls start")
	}
	raw, err := json.Marshal(stage2aSoulsProtectedStart{
		Schema: "agent-bot-souls/protected-start/v1", ReservationEnvelopeBase64URL: envelope,
		ReservationSHA256: digest, MachinePinPath: SoulAuthorityPin,
		LaunchInputRecords: launch, StateRoot: stateRoot,
	})
	if err != nil || len(raw) > stage2aSoulsStartLimit || stage2aStrictJSON(raw) != nil {
		return nil, errors.New("protected Souls start exceeds the fixed input contract")
	}
	return raw, nil
}
