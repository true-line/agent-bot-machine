//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const stage2aSharedSealSchema = "agent-bot-machine/stage2a-shared-install-seal/v1"
const stage2aCooperativeRSealPurpose = "agent-bot/stage2a-cooperative-r-seal/v1"

// Only the root installer may hand an already prepared tree to the fixed,
// network-denied A helper. The helper has no caller-selected executable,
// operation, arguments, environment or supplementary groups.
func stage2aRunSealHelper(adminUID, adminGID int, raw []byte) (stage2aInstallSealReply, error) {
	var empty stage2aInstallSealReply
	if os.Getuid() != 0 || os.Geteuid() != 0 || adminUID < 400 || adminGID <= 0 ||
		len(raw) == 0 || len(raw) > 2<<20 {
		return empty, errStage2aReservationAuthority
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile,
		SoulLauncher, "stage2a-seal")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(raw)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(adminUID), Gid: uint32(adminGID), Groups: []uint32{},
	}}
	output, err := cmd.Output()
	if err != nil || len(output) == 0 || len(output) > 8<<10 ||
		stage2aStrictJSON(bytes.TrimSpace(output)) != nil {
		return empty, errors.New("Stage 2a A-owned seal helper refused")
	}
	var reply stage2aInstallSealReply
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF {
		return empty, errStage2aReservationAuthority
	}
	return reply, nil
}

// This request shares the custody and measurement primitive with protected
// installation, but authorizes only the cooperative R snapshot domain. A
// separate H descriptor will need its own reviewed inventory and purpose.
type stage2aSharedSealRequest struct {
	Schema         string                    `json:"schema"`
	Purpose        string                    `json:"purpose"`
	MachineAccount string                    `json:"machine_account"`
	MachineUID     int                       `json:"machine_uid"`
	MachineGID     int                       `json:"machine_gid"`
	RunnerAccount  string                    `json:"runner_account"`
	RunnerUID      int                       `json:"runner_uid"`
	RunnerGID      int                       `json:"runner_gid"`
	InstallationID string                    `json:"installation_id"`
	Namespace      stage2aInstalledDirectory `json:"snapshot_namespace"`
	LauncherSHA256 string                    `json:"launcher_sha256"`
	Prepared       stage2aPreparedSnapshot   `json:"prepared"`
	Approved       []Stage2aDefinitionRecord `json:"approved"`
	ApprovedDigest string                    `json:"approved_digest"`
}

func (r stage2aSharedSealRequest) validate() error {
	namespace, err := stage2aFrozenNamespace(r.InstallationID)
	if err != nil || r.Schema != stage2aSharedSealSchema ||
		r.Purpose != stage2aCooperativeRSealPurpose ||
		r.MachineUID < 400 || r.MachineGID <= 0 ||
		r.RunnerUID < 300 || r.RunnerUID > 399 || r.RunnerGID != r.RunnerUID ||
		r.MachineUID == r.RunnerUID ||
		!accountName.MatchString(r.MachineAccount) ||
		r.RunnerAccount != soulRunnerName(r.InstallationID) ||
		r.Namespace.Path != namespace || r.Namespace.Device == 0 ||
		r.Namespace.Inode == "" || r.Namespace.BirthSeconds <= 0 ||
		r.Namespace.BirthNanoseconds < 0 || r.Namespace.BirthNanoseconds >= 1e9 ||
		!soulDigest.MatchString(r.LauncherSHA256) ||
		r.Prepared.Digest != r.ApprovedDigest ||
		r.Prepared.WrapperPath == "" ||
		filepath.Dir(r.Prepared.WrapperPath) != namespace {
		return errStage2aReservationAuthority
	}
	digest, _, err := Stage2aDefinitionDigest(r.Approved)
	if err != nil || digest != r.ApprovedDigest || stage2aRunnerReadableInventory(r.Approved) != nil {
		return errStage2aReservationAuthority
	}
	return nil
}

func runStage2aSharedSeal(raw []byte) int {
	refuse := func() int { return harnessRefused }
	var request stage2aSharedSealRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF ||
		request.validate() != nil || !stage2aInstallSealNoIP() ||
		os.Getuid() != request.MachineUID || os.Geteuid() != request.MachineUID ||
		os.Getgid() != request.MachineGID || os.Getegid() != request.MachineGID ||
		!stage2aInstallSealOnlyPrimaryGroup(request.MachineGID) {
		return refuse()
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return refuse()
	}
	binary, err := managerBytes()
	if err != nil || harnessSHA(binary) != request.LauncherSHA256 {
		return refuse()
	}
	inode, birth := request.Namespace.identity()
	a := stage2aAdminSnapshots{
		uid: uint32(request.MachineUID), runnerReadGID: uint32(request.RunnerGID),
		namespace: request.Namespace.Path, namespaceDev: request.Namespace.Device,
		namespaceInode: inode, namespaceBirth: birth,
		verifyInstalledGroup: func() error {
			return verifyStage2aInstalledGroup(request.RunnerAccount, request.RunnerGID,
				request.MachineAccount, request.MachineUID,
				request.RunnerAccount, request.RunnerUID)
		},
	}
	name := stage2aInstallSnapshotName(request.InstallationID, "cooperative-r")
	identity, digest, err := stage2aSealPreparedSnapshotAt(a, request.Prepared, name, request.Approved, false)
	if err != nil || json.NewEncoder(os.Stdout).Encode(stage2aInstallSealReply{Identity: identity, Digest: digest}) != nil {
		return refuse()
	}
	return 0
}

// Root independently reopens the final tree; a child reply never becomes the
// installed receipt solely by claiming a digest or path.
func stage2aSealCooperativeRAsAdmin(r stage2aSharedSealRequest) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if r.validate() != nil {
		return empty, "", errStage2aReservationAuthority
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 2<<20 {
		return empty, "", errStage2aReservationAuthority
	}
	reply, err := stage2aRunSealHelper(r.MachineUID, r.MachineGID, raw)
	if err != nil || reply.Identity.RootPath != filepath.Join(r.Namespace.Path,
		stage2aInstallSnapshotName(r.InstallationID, "cooperative-r")) ||
		reply.Identity.OwnerUID != uint32(r.MachineUID) ||
		reply.Identity.OwnerGID != uint32(r.RunnerGID) ||
		reply.Identity.Mode != "0555" || reply.Digest != r.ApprovedDigest {
		return empty, "", errStage2aReservationAuthority
	}
	observed, digest, err := observeStage2aSourceAt(reply.Identity.RootPath,
		uint32(r.MachineUID), uint32(r.RunnerGID), r.Approved, false)
	if err != nil || observed != reply.Identity || digest != reply.Digest {
		return empty, "", errors.New("Stage 2a cooperative R seal differs on root observation")
	}
	return reply.Identity, reply.Digest, nil
}
