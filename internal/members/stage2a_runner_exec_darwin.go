package members

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// runStage2aRunner is the R side of the fixed HQ launch transition. The
// authenticated grant supplies the runtime files and frozen package; the
// caller controls only ACP bytes and when to close the stream.
func runStage2aRunner(ctx context.Context, request SoulRunRequest, start SoulStartAssignment,
	runner SoulRunner, bridge SoulBridge, binding Stage2aMeasurementBinding,
	launchInputs Stage2aLaunchInputRecords, definition []Stage2aDefinitionRecord,
	node, entry, reservationEnvelopeBase64URL, reservationSHA256 string,
	runtimeRef stage2aDomainInventoryRefV3, acp io.Reader, control, stdout, status *os.File) int {
	expires, err := time.Parse(time.RFC3339Nano, start.ExpiresAt)
	if err != nil || time.Until(expires) <= 0 || time.Until(expires) > 30*time.Second ||
		!request.valid() || start.Schema != "agent-bot-machine/soul-start-assignment/v2" ||
		start.PlanDigest != request.PlanDigest || start.InstallationID != request.InstallationID ||
		start.StartID != request.StartID || start.HQEpoch != request.HQEpoch ||
		runner.InstallationID != request.InstallationID || start.SoulID != runner.SoulID ||
		start.RunnerAccount != runner.Account || start.RunnerUID != runner.UID || start.RunnerGID != runner.GID ||
		!harnessKernelRole(HarnessAdapter{Account: runner.Account, UID: runner.UID}) ||
		os.Getenv("SUDO_USER") != DarwinHQAccount || os.Getenv("SUDO_UID") != strconv.Itoa(start.HQUID) ||
		acp == nil || control == nil || stdout == nil || status == nil || ctx.Err() != nil {
		return harnessRefused
	}
	if !stage2aReservationBindingMatches(binding, start, binding.HostID,
		uint32(start.MachineUID), uint32(start.RunnerGID)) {
		return harnessRefused
	}

	digest, _, err := Stage2aLaunchInputDigest(launchInputs)
	if err != nil || digest != binding.LaunchInputMeasurement {
		return harnessRefused
	}
	root := binding.Snapshots.LaunchInputs
	rInventory, err := stage2aCheckRunnerCodeV3(runtimeRef, node, entry)
	if err != nil {
		return harnessRefused
	}
	if err := stage2aCheckRuntimeSnapshot(root, launchInputs.Files); err != nil {
		return harnessRefused
	}
	defDigest, _, err := Stage2aDefinitionDigest(definition)
	if err != nil || defDigest != binding.DefinitionMeasurement ||
		!stage2aRunnerPackageMatchesRuntimeV3(runtimeRef, runner, binding, defDigest) {
		return harnessRefused
	}
	pkg := binding.Snapshots.Definition
	if err := stage2aCheckRunnerSnapshot(pkg, definition); err != nil {
		return harnessRefused
	}
	if launchInputs.SandboxPolicyDigest != "sha256:"+harnessSHA(soulRunnerProfile) ||
		launchInputs.SelectedCommand != node ||
		launchInputs.EffectiveConfig["profile"] != binding.ProfileInForce ||
		stage2aAdapterChildEnvV3(launchInputs, nil, runtimeRef, rInventory) != nil ||
		!stage2aSystemImageSelected(launchInputs, "/usr/bin/sandbox-exec") {
		return harnessRefused
	}
	if err := trustedPath(OSHost{}, SoulRunnerSandbox, false); err != nil {
		return harnessRefused
	}
	if err := checkDarwinACLs(pathAncestry(SoulRunnerSandbox)); err != nil {
		return harnessRefused
	}
	profile, err := openPinnedFile(SoulRunnerSandbox, harnessSHA(soulRunnerProfile))
	if err != nil || profile.Close() != nil {
		return harnessRefused
	}
	if err := trustedPath(OSHost{}, SoulChildSandbox, false); err != nil {
		return harnessRefused
	}
	if err := checkDarwinACLs(pathAncestry(SoulChildSandbox)); err != nil {
		return harnessRefused
	}
	childProfile, err := openPinnedFile(SoulChildSandbox, harnessSHA(soulChildProfile))
	if err != nil || childProfile.Close() != nil {
		return harnessRefused
	}

	argv, endpoints, err := stage2aRunnerArgvForStart(launchInputs, node, entry,
		pkg.RootPath, binding.ProfileInForce, runner, bridge, start.HQUID, request.StartID)
	if err != nil || ctx.Err() != nil || !time.Now().Before(expires) {
		return harnessRefused
	}
	stateRoot, err := stage2aRunnerStateRoot(runner)
	if err != nil {
		return harnessRefused
	}
	protectedStart, err := marshalStage2aSoulsProtectedStart(reservationEnvelopeBase64URL,
		reservationSHA256, launchInputs, stateRoot)
	if err != nil {
		return harnessRefused
	}
	startRead, startWrite, err := os.Pipe()
	if err != nil {
		return harnessRefused
	}
	defer startRead.Close()
	defer startWrite.Close()
	// R gets only HQ admission and B relay outbound. Its member socket is a
	// per-start listener; no direct IP or unrelated Unix destination is open.
	cmd := exec.Command("/usr/bin/sandbox-exec",
		"-D", "ADMISSION_SOCKET="+endpoints.Admission.SocketPath,
		"-D", "RELAY_SOCKET="+endpoints.Relay.SocketPath,
		"-D", "MEMBER_SOCKET="+endpoints.Member.SocketPath,
		"-f", SoulRunnerSandbox, node)
	cmd.Args = append(cmd.Args, argv[1:]...)
	cmd.Dir = pkg.RootPath
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + darwinSoulRunnerHome(runner.Account),
		"AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH=1"}
	if len(launchInputs.Environment) != len(cmd.Env) {
		return harnessRefused
	}
	for _, pair := range cmd.Env {
		key, value, _ := strings.Cut(pair, "=")
		if launchInputs.Environment[key] != value {
			return harnessRefused
		}
	}
	cmd.ExtraFiles = []*os.File{startRead}
	go func() {
		_, _ = startWrite.Write(protectedStart)
		_ = startWrite.Close()
	}()
	return superviseHarness(ctx, cmd, acp, control, stdout, &harnessReporter{output: status}, time.Second)
}

func stage2aSystemImageSelected(input Stage2aLaunchInputRecords, path string) bool {
	for _, image := range input.SystemImages.Selected {
		if image.Path == path {
			return true
		}
	}
	return false
}

func stage2aRuntimeFile(root, path, suffix string, files []Stage2aDefinitionRecord, executable bool) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil || !stage2aAbsolutePath(path) ||
		!stage2aRecordPath(relative) || !strings.HasSuffix(relative, "/"+suffix) {
		return false
	}
	for _, file := range files {
		if file.Path == relative && file.Kind == "regular" && stage2aReadOnlyMode(file.Mode) {
			return !executable || (file.Mode[2]-'0')&1 != 0
		}
	}
	return false
}

func stage2aCheckRunnerSnapshot(expected Stage2aSnapshotIdentity, files []Stage2aDefinitionRecord) error {
	dir, err := openStage2aAdminDirectory(expected.RootPath, expected.OwnerUID)
	if err != nil {
		return err
	}
	defer dir.Close()
	observed, _, err := observeStage2aFrozenAt(expected.RootPath, expected.OwnerUID, expected.OwnerGID, files)
	if err != nil || observed != expected {
		return errors.New("Soul runner snapshot changed before execution")
	}
	return nil
}

// Launch inputs describe a regular-file inventory under the runtime snapshot.
// The Soul definition observer requires the separate Contents layout.
func stage2aCheckRuntimeSnapshot(expected Stage2aSnapshotIdentity, files []Stage2aDefinitionRecord) error {
	invalid := errors.New("Soul runtime snapshot differs from approved files")
	if _, err := stage2aLaunchFiles(files); err != nil {
		return invalid
	}
	dir, err := openStage2aAdminDirectory(expected.RootPath, expected.OwnerUID)
	if err != nil {
		return err
	}
	defer dir.Close()
	fd := int(dir.Fd())
	observed, st, err := stage2aSnapshotIdentity(fd, expected.OwnerUID, expected.OwnerGID)
	if err != nil || observed != expected {
		return invalid
	}
	want := make(map[string]Stage2aDefinitionRecord, len(files))
	dirs := make(map[string]bool)
	for _, file := range files {
		want[file.Path] = file
		for parent := filepath.Dir(file.Path); parent != "."; parent = filepath.Dir(parent) {
			dirs[parent] = true
		}
	}
	var entries []stage2aObservedEntry
	var total uint64
	if stage2aCollectFrozen(dir, "", expected.OwnerUID, expected.OwnerGID, false, &entries, &total, false) != nil ||
		len(entries) != len(want)+len(dirs) {
		return invalid
	}
	metadata := make(map[string]unix.Stat_t, len(entries))
	for _, entry := range entries {
		metadata[entry.record.Path] = entry.stat
		if entry.record.Kind == "directory" {
			if !dirs[entry.record.Path] {
				return invalid
			}
		} else {
			file, ok := want[entry.record.Path]
			if !ok || file.Mode != entry.record.Mode || *file.Size != *entry.record.Size {
				return invalid
			}
		}
	}
	for _, record := range files {
		file, err := stage2aReopenFrozen(fd, record.Path, expected.OwnerUID, expected.OwnerGID, metadata)
		if err != nil {
			return invalid
		}
		digest := sha256.New()
		n, readErr := io.Copy(digest, io.LimitReader(file, int64(*record.Size)+1))
		var stat unix.Stat_t
		statErr := unix.Fstat(int(file.Fd()), &stat)
		closeErr := file.Close()
		if readErr != nil || statErr != nil || closeErr != nil || uint64(n) != *record.Size ||
			!stage2aSameNode(stat, metadata[record.Path]) || fmt.Sprintf("%x", digest.Sum(nil)) != record.SHA256 {
			return invalid
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !stage2aSameNode(st, after) {
		return invalid
	}
	return nil
}
