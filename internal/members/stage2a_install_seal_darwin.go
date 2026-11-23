//go:build darwin

package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aInstallSealSchema = "agent-bot-machine/stage2a-install-seal/v1"
const stage2aInstallSealProfile = "(version 1)\n(allow default)\n(deny network*)\n"

type stage2aInstallSealRequest struct {
	Schema   string                  `json:"schema"`
	Policy   stage2aInstalledPolicy  `json:"policy"`
	Prepared stage2aPreparedSnapshot `json:"prepared"`
	Kind     string                  `json:"kind"`
}

type stage2aInstallSealReply struct {
	Identity Stage2aSnapshotIdentity `json:"identity"`
	Digest   string                  `json:"digest"`
}

// The fixed install helper runs under A in a sandbox that denies IPv4 and
// IPv6. A sandbox failure must be detected before any snapshot is published.
func stage2aInstallSealNoIP() bool {
	for _, probe := range []struct{ network, address string }{
		{"tcp4", "127.0.0.1:1"}, {"tcp6", "[::1]:1"},
	} {
		connection, err := net.DialTimeout(probe.network, probe.address, 250*time.Millisecond)
		if connection != nil {
			connection.Close()
			return false
		}
		if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
			return false
		}
	}
	return true
}

func stage2aSealPreparedSnapshotAt(a stage2aAdminSnapshots, prepared stage2aPreparedSnapshot,
	name string, approved []Stage2aDefinitionRecord, runtime bool) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	if err := a.check(); err != nil {
		return empty, "", err
	}
	if !stage2aSnapshotName.MatchString(name) || filepath.Dir(prepared.WrapperPath) != a.namespace ||
		!strings.HasPrefix(filepath.Base(prepared.WrapperPath), ".stage2a-") ||
		prepared.Stage.RootPath != filepath.Join(prepared.WrapperPath, "snapshot") ||
		prepared.Wrapper.RootPath != prepared.WrapperPath ||
		prepared.Stage.OwnerUID != a.uid || prepared.Stage.OwnerGID != a.runnerReadGID ||
		prepared.Wrapper.OwnerUID != a.uid || prepared.Wrapper.OwnerGID != a.runnerReadGID ||
		prepared.Stage.Mode != "0700" || prepared.Wrapper.Mode != "0700" {
		return empty, "", errStage2aReservationAuthority
	}
	if runtime {
		var err error
		approved, err = stage2aExpandedRuntimeRecords(approved)
		if err != nil {
			return empty, "", err
		}
	} else if _, _, err := Stage2aDefinitionDigest(approved); err != nil {
		return empty, "", err
	}
	parentFD, err := unix.Open(a.namespace, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(parentFD)
	if err := stage2aPrivateSnapshotParent(parentFD, a.uid, a.runnerReadGID); err != nil {
		return empty, "", err
	}
	wrapperFD, err := unix.Openat(parentFD, filepath.Base(prepared.WrapperPath), stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(wrapperFD)
	wrapper, _, err := stage2aSnapshotIdentityForSource(wrapperFD, a.uid, a.runnerReadGID, true)
	if err != nil || wrapper != prepared.Wrapper || checkDarwinACLs([]string{prepared.WrapperPath}) != nil {
		return empty, "", errStage2aReservationAuthority
	}
	stageFD, err := unix.Openat(wrapperFD, "snapshot", stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return empty, "", err
	}
	defer unix.Close(stageFD)
	stage, _, err := stage2aSnapshotIdentityForSource(stageFD, a.uid, a.runnerReadGID, true)
	if err != nil || stage != prepared.Stage {
		return empty, "", errStage2aReservationAuthority
	}
	observe := observeStage2aSourceAt
	if runtime {
		observe = observeStage2aRuntimeAt
	}
	observed, digest, err := observe(prepared.Stage.RootPath, a.uid, a.runnerReadGID, approved, true)
	if err != nil || observed != prepared.Stage || digest != prepared.Digest {
		return empty, "", errors.New("Stage 2a prepared snapshot changed before A seal")
	}
	if err := unix.RenameatxNp(wrapperFD, "snapshot", parentFD, name, unix.RENAME_EXCL); err != nil {
		return empty, "", err
	}
	// The destination remains occupied on uncertain seal or sync; it cannot
	// be reused by another owner proof or a retry of this spent installation.
	if err := unix.Fchmod(stageFD, 0555); err != nil || unix.Fsync(stageFD) != nil ||
		unix.Fsync(wrapperFD) != nil || unix.Fsync(parentFD) != nil {
		return empty, "", errors.New("Stage 2a A-owned snapshot seal is uncertain")
	}
	finalPath := filepath.Join(a.namespace, name)
	identity, finalDigest, err := observe(finalPath, a.uid, a.runnerReadGID, approved, false)
	if err != nil || finalDigest != prepared.Digest || identity.RootPath != finalPath ||
		identity.OwnerUID != a.uid || identity.OwnerGID != a.runnerReadGID || identity.Mode != "0555" {
		return empty, "", errors.New("Stage 2a A-owned published snapshot differs")
	}
	return identity, finalDigest, nil
}

// RunStage2aInstallSeal is the only A-effective-UID publication step of an
// already paired, owner-reviewed root install. Its stdin is a fixed inherited
// handoff, never a network or HQ supplied general file operation.
func RunStage2aInstallSeal() int {
	refuse := func() int { return harnessRefused }
	if !stage2aInstallSealNoIP() {
		return refuse()
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 || stage2aStrictJSON(raw) != nil {
		return refuse()
	}
	var request stage2aInstallSealRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF ||
		request.Schema != stage2aInstallSealSchema ||
		request.Policy.Schema != "agent-bot-machine/stage2a-installed-authority/v1" ||
		request.Policy.MachineUID < 400 || request.Policy.MachineGID <= 0 ||
		os.Getuid() != request.Policy.MachineUID || os.Geteuid() != request.Policy.MachineUID ||
		os.Getgid() != request.Policy.MachineGID || os.Getegid() != request.Policy.MachineGID ||
		request.Policy.Binding.PlanID == "" || request.Policy.Binding.InstalledPlanDigest == "" {
		return refuse()
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return refuse()
	}
	binary, err := managerBytes()
	if err != nil || harnessSHA(binary) != request.Policy.LauncherSHA256 {
		return refuse()
	}
	_, a := request.Policy.stores()
	name := stage2aInstallSnapshotName(request.Policy.Binding.InstallationID, request.Kind)
	var approved []Stage2aDefinitionRecord
	runtime := false
	switch request.Kind {
	case "definition":
		approved = request.Policy.Definition
	case "inputs":
		approved, runtime = request.Policy.LaunchInputs.Files, true
	default:
		return refuse()
	}
	identity, digest, err := stage2aSealPreparedSnapshotAt(a, request.Prepared, name, approved, runtime)
	if err != nil || json.NewEncoder(os.Stdout).Encode(stage2aInstallSealReply{Identity: identity, Digest: digest}) != nil {
		return refuse()
	}
	return 0
}

func stage2aSealAsAdmin(p stage2aInstalledPolicy, prepared stage2aPreparedSnapshot,
	kind string) (Stage2aSnapshotIdentity, string, error) {
	var empty Stage2aSnapshotIdentity
	request := stage2aInstallSealRequest{Schema: stage2aInstallSealSchema,
		Policy: p, Prepared: prepared, Kind: kind}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 2<<20 {
		return empty, "", errStage2aReservationAuthority
	}
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile,
		SoulLauncher, "stage2a-seal")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(raw)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(p.MachineUID), Gid: uint32(p.MachineGID), Groups: []uint32{},
	}}
	output, err := cmd.Output()
	if err != nil || len(output) > 8<<10 || stage2aStrictJSON(bytes.TrimSpace(output)) != nil {
		return empty, "", errors.New("Stage 2a A-owned seal helper refused")
	}
	var reply stage2aInstallSealReply
	if json.Unmarshal(output, &reply) != nil ||
		reply.Identity.RootPath != filepath.Join(p.SnapshotNamespace.Path,
			stage2aInstallSnapshotName(p.Binding.InstallationID, kind)) ||
		reply.Identity.OwnerUID != uint32(p.MachineUID) ||
		reply.Identity.OwnerGID != uint32(p.Runner.GID) || reply.Identity.Mode != "0555" ||
		reply.Digest != prepared.Digest {
		return empty, "", errStage2aReservationAuthority
	}
	approved := p.Definition
	observe := observeStage2aSourceAt
	if kind == "inputs" {
		approved, err = stage2aExpandedRuntimeRecords(p.LaunchInputs.Files)
		if err != nil {
			return empty, "", err
		}
		observe = observeStage2aRuntimeAt
	}
	observed, digest, err := observe(reply.Identity.RootPath, uint32(p.MachineUID),
		uint32(p.Runner.GID), approved, false)
	if err != nil || observed != reply.Identity || digest != reply.Digest {
		return empty, "", errors.New("Stage 2a A seal differs on root observation")
	}
	return reply.Identity, reply.Digest, nil
}
