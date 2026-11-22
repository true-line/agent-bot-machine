package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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
	pub ed25519.PublicKey, now time.Time) error {
	invalid := errors.New("Soul runner reservation differs from Machine's signed start")
	raw, err := decodeStage2aRoleBase64(run.ReservationEnvelopeBase64URL, 32<<10)
	if err != nil || stage2aReservationSHA256(raw) != run.ReservationSHA256 {
		return invalid
	}
	var envelope stage2aSignedReservation
	if decodeStage2aRoleJSON(raw, &envelope) != nil ||
		envelope.SchemaVersion != 2 || envelope.Purpose != stage2aAdminReservationPurpose ||
		envelope.IssuerPublicKeyBase64URL != base64.RawURLEncoding.EncodeToString(pub) {
		return invalid
	}
	canonical, err := marshalStage2aReservationJCS(envelope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return invalid
	}
	payloadRaw, err := decodeStage2aRoleBase64(envelope.PayloadBase64URL, 24<<10)
	if err != nil || stage2aReservationSHA256(payloadRaw) != envelope.PayloadSHA256 {
		return invalid
	}
	signature, err := decodeStage2aRoleBase64(envelope.SignatureBase64URL, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, append([]byte(stage2aAdminReservationPurpose+"\x00"), payloadRaw...), signature) {
		return invalid
	}
	var payload stage2aReservationPayload
	if decodeStage2aRoleJSON(payloadRaw, &payload) != nil ||
		payload.Contract != "machine/v2" || payload.Kind != "stage2a-reservation" || payload.SchemaVersion != 2 ||
		payload.Assignment.SoulArtifactSHA256 == "" ||
		!reflect.DeepEqual(payload.Assignment.SoulStartAssignment, in.Start) ||
		!reflect.DeepEqual(payload.MeasurementBinding, in.Binding) ||
		payload.Assignment.InstallationID != in.Request.InstallationID ||
		payload.Assignment.StartID != in.Request.StartID ||
		payload.Assignment.HQEpoch != in.Request.HQEpoch ||
		payload.Assignment.PlanDigest != in.Request.PlanDigest ||
		payload.Assignment.RunnerUID != os.Getuid() || payload.Assignment.RunnerUID != os.Geteuid() ||
		payload.Assignment.RunnerGID != os.Getegid() ||
		payload.MeasurementBinding.SoulArtifactSHA256 != string(payload.Assignment.SoulArtifactSHA256) {
		return invalid
	}
	expires, err := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil || !now.Before(expires) || expires.Sub(now) > 30*time.Second {
		return invalid
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(in.Launch)
	if err != nil || launchDigest != payload.MeasurementBinding.LaunchInputMeasurement {
		return invalid
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.Runner, in.Bridge, in.Start.HQUID, in.Request.StartID)
	if err != nil || !reflect.DeepEqual(payload.MemberEndpoint, endpoints.MemberLaunchAssignment()) {
		return invalid
	}
	return nil
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
