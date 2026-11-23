//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const stage2aCooperativeAuthorityDir = launchRuntimeDir + "/cooperative-authorities"
const stage2aCooperativeInstalledSchemaV3 = "agent-bot-machine/soul-cooperative-installed-authority/v3"

type soulCooperativeInstalledV3 struct {
	Schema               string                      `json:"schema"`
	Policy               SoulCooperativeLaunchPolicy `json:"policy"`
	PairCommitment       string                      `json:"pair_commitment"`
	CanonicalPlan        json.RawMessage             `json:"canonical_plan"`
	RootReceipt          json.RawMessage             `json:"root_receipt"`
	Claims               stage2aInstalledDirectory   `json:"claims"`
	AdmissionDirectory   stage2aInstalledDirectory   `json:"admission_directory"`
	BrokerDirectory      stage2aInstalledDirectory   `json:"broker_directory"`
	MemberDirectory      stage2aInstalledDirectory   `json:"member_directory"`
	RelayDirectory       stage2aInstalledDirectory   `json:"relay_directory"`
	RequestDirectory     stage2aInstalledDirectory   `json:"request_directory"`
	StagingDirectory     stage2aInstalledDirectory   `json:"staging_directory"`
	CompletionDirectory  stage2aInstalledDirectory   `json:"completion_directory"`
	RuntimeV3            stage2aDomainInventoryRefV3 `json:"runtime_v3"`
	DefinitionSnapshot   Stage2aSnapshotIdentity     `json:"definition_snapshot"`
	LaunchInputsSnapshot Stage2aSnapshotIdentity     `json:"launch_inputs_snapshot"`
}

func (p soulCooperativeInstalledV3) claimStore() stage2aAdminClaimStore {
	inode, birth := p.Claims.identity()
	return stage2aAdminClaimStore{path: p.Claims.Path,
		uid: uint32(p.Policy.MachineUID), gid: uint32(p.Policy.MachineGID),
		device: p.Claims.Device, inode: inode, birthtime: birth,
		legacyUnspent: func(installationID, startID string) error {
			if installationID != p.Policy.Runner.InstallationID || !soulStartID.MatchString(startID) {
				return errSoulCooperativeAuthority
			}
			protected, err := stage2aAuthorityPath(installationID)
			if err != nil {
				return errSoulCooperativeAuthority
			}
			if _, err := os.Lstat(protected); !errors.Is(err, os.ErrNotExist) {
				return errSoulCooperativeAuthority
			}
			return nil
		},
	}
}

func stage2aCooperativeClaimsPath(installationID string) string {
	return filepath.Join(stage2aClaimsParent, "c-"+soulEndpointInstallationSlot(installationID))
}

func stage2aCooperativeAuthorityPath(installationID string) (string, error) {
	if !soulInstallationID.MatchString(installationID) {
		return "", errSoulCooperativeAuthority
	}
	return filepath.Join(stage2aCooperativeAuthorityDir,
		soulEndpointInstallationSlot(installationID)+".json"), nil
}

func publishSoulCooperativeInstalled(s Saved, p SoulCooperativeLaunchPolicy,
	pair string, runtime stage2aDomainInventoryRefV3,
	definition, launchInputs Stage2aSnapshotIdentity, plan, receipt []byte) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !digestPattern.MatchString(pair) ||
		runtime.Domain != "R-runtime" || runtime.InstallationID != p.Runner.InstallationID ||
		runtime.OwnerPlanDigest != "sha256:"+s.PlanDigest ||
		runtime.ReviewedSourceInventoryDigest != p.RuntimeV3.InventoryDigest ||
		runtime.Snapshot.Path != p.RuntimeRoot ||
		runtime.MachineUID != uint32(p.MachineUID) ||
		runtime.ReaderUID != uint32(p.Runner.UID) ||
		runtime.ReaderGID != uint32(p.Runner.GID) ||
		definition.RootPath != p.Runner.PackageRoot ||
		launchInputs.RootPath != cooperativeReviewedInputsRoot(p.Runner.InstallationID) ||
		definition.OwnerUID != uint32(p.MachineUID) ||
		launchInputs.OwnerUID != uint32(p.MachineUID) ||
		definition.OwnerGID != uint32(p.Runner.GID) ||
		launchInputs.OwnerGID != uint32(p.Runner.GID) ||
		definition.Mode != "0555" || launchInputs.Mode != "0555" {
		return errSoulCooperativeAuthority
	}
	claims, err := stage2aInstalledDirectoryIdentity(
		stage2aCooperativeClaimsPath(p.Runner.InstallationID), p.MachineUID, p.MachineGID, 0700)
	if err != nil {
		return err
	}
	if p.Bridge == nil {
		return errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID)
	if err != nil {
		return err
	}
	admissionDir, err := stage2aInstalledDirectoryIdentity(ends.Admission.Directory,
		ends.Admission.OwnerUID, ends.Admission.GroupGID, uint16(ends.Admission.DirMode))
	if err != nil {
		return err
	}
	brokerDir, err := stage2aInstalledDirectoryIdentity(ends.Broker.Directory,
		ends.Broker.OwnerUID, ends.Broker.GroupGID, uint16(ends.Broker.DirMode))
	if err != nil {
		return err
	}
	memberDir, err := stage2aInstalledDirectoryIdentity(ends.Member.Directory,
		ends.Member.OwnerUID, ends.Member.GroupGID, uint16(ends.Member.DirMode))
	if err != nil {
		return err
	}
	relayDir, err := stage2aInstalledDirectoryIdentity(ends.Relay.Directory,
		ends.Relay.OwnerUID, ends.Relay.GroupGID, uint16(ends.Relay.DirMode))
	if err != nil {
		return err
	}
	parents := soulCooperativeBParentsV3{Broker: brokerDir, Member: memberDir, Relay: relayDir}
	_, _, bridgeDigest, err := soulCooperativeBLaunchIntentV3(p, p.ReviewedStartID, parents)
	if err != nil || bridgeDigest != p.LaunchInputs.BridgeLaunchSHA256 {
		return errSoulCooperativeAuthority
	}
	launch, err := cooperativeLaunchPaths(p.Runner.InstallationID)
	if err != nil {
		return err
	}
	requestDir, err := stage2aInstalledDirectoryIdentity(launch.requestDir,
		p.MachineUID, p.Runner.GID, 02750)
	if err != nil {
		return err
	}
	stagingDir, err := stage2aInstalledDirectoryIdentity(launch.stagingDir,
		p.MachineUID, p.Runner.GID, 02700)
	if err != nil {
		return err
	}
	completionDir, err := stage2aInstalledDirectoryIdentity(launch.completionDir,
		p.MachineUID, p.Runner.GID, 02770)
	if err != nil {
		return err
	}
	installed := soulCooperativeInstalledV3{Schema: stage2aCooperativeInstalledSchemaV3,
		Policy: p, PairCommitment: pair, CanonicalPlan: plan, RootReceipt: receipt,
		Claims: claims, AdmissionDirectory: admissionDir, BrokerDirectory: brokerDir,
		MemberDirectory: memberDir, RelayDirectory: relayDir,
		RequestDirectory: requestDir, StagingDirectory: stagingDir, CompletionDirectory: completionDir,
		RuntimeV3:          runtime,
		DefinitionSnapshot: definition, LaunchInputsSnapshot: launchInputs}
	raw, err := json.Marshal(installed)
	if err != nil || len(raw) > 2<<20 || stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return errSoulCooperativeAuthority
	}
	path, err := stage2aCooperativeAuthorityPath(p.Runner.InstallationID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errSoulCooperativeAuthority
	}
	f, err := os.CreateTemp(stage2aCooperativeAuthorityDir, ".cooperative-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chown(p.MachineUID, p.MachineGID); err == nil {
		err = f.Chmod(0400)
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := unix.RenamexNp(f.Name(), path, unix.RENAME_EXCL); err != nil {
		return err
	}
	return syncUpgradeDir(stage2aCooperativeAuthorityDir)
}

// The A loader reopens both immutable receipt bytes and the sealed R tree.
// It does not accept a caller-supplied digest as installed authority.
func loadSoulCooperativeInstalledV3(key ed25519.PublicKey, hqUID int, epoch,
	installationID string) (soulCooperativeInstalledV3, stage2aVerifiedDomainRefV3, error) {
	var empty soulCooperativeInstalledV3
	var emptyR stage2aVerifiedDomainRefV3
	path, err := stage2aCooperativeAuthorityPath(installationID)
	if err != nil {
		return empty, emptyR, err
	}
	if os.Getuid() <= 399 || os.Getuid() != os.Geteuid() || len(key) != ed25519.PublicKeySize {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	pin, err := stage2aReadRootFile(SoulAuthorityPin, ed25519.PublicKeySize, 0444)
	if err != nil || !bytes.Equal(pin, key) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	dir, err := openStage2aAdminDirectory(stage2aCooperativeAuthorityDir, uint32(os.Getuid()))
	if err != nil {
		return empty, emptyR, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return empty, emptyR, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|0400 ||
		before.Uid != uint32(os.Getuid()) || before.Gid != uint32(os.Getgid()) ||
		before.Nlink != 1 || before.Size <= 0 || before.Size > 2<<20 ||
		checkDarwinACLs([]string{path}) != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(raw) != int(before.Size) || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || stage2aStrictJSONBounded(raw, 2<<20, stage2aV3MaxJSONNodes) != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	var installed soulCooperativeInstalledV3
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&installed) != nil || decoder.Decode(new(any)) != io.EOF ||
		installed.Schema != stage2aCooperativeInstalledSchemaV3 ||
		installed.Policy.Schema != soulCooperativeRuntimeInstallSchemaV3 ||
		installed.Policy.validate() != nil || installed.Policy.Runner.InstallationID != installationID ||
		installed.Policy.HQUID != hqUID || installed.Policy.HQEpoch != epoch ||
		installed.Policy.MachineUID != os.Getuid() || installed.Policy.MachineGID != os.Getgid() ||
		!digestPattern.MatchString(installed.PairCommitment) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	var receipt Receipt
	if json.Unmarshal(installed.RootReceipt, &receipt) != nil || !ValidApproval(receipt.PlanID, receipt.PlanDigest) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	rootReceipt, err := stage2aReadRootFile(ReceiptPath(receipt.PlanID), 256<<10, 0644)
	if err != nil || !bytes.Equal(rootReceipt, installed.RootReceipt) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	checked := SoulCooperativeInstalledAuthority{Policy: installed.Policy, InstallationOwner: receipt.Owner,
		PlanID: receipt.PlanID, PlanDigest: receipt.PlanDigest,
		ReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(installed.RootReceipt)),
		CanonicalPlan: installed.CanonicalPlan, RootReceipt: installed.RootReceipt}
	if !checked.matchesInstalledRecord() {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	protectedPath, err := stage2aAuthorityPath(installationID)
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	if _, err := os.Lstat(protectedPath); !errors.Is(err, os.ErrNotExist) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	claims, err := stage2aInstalledDirectoryIdentity(stage2aCooperativeClaimsPath(installationID),
		installed.Policy.MachineUID, installed.Policy.MachineGID, 0700)
	if err != nil || claims != installed.Claims {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	if installed.Policy.Bridge == nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	proofDir := filepath.Join(stage2aProofParent, soulEndpointInstallationSlot(installationID))
	if _, err := stage2aInstalledDirectoryIdentity(proofDir, installed.Policy.MachineUID,
		installed.Policy.Bridge.GID, 02710); err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	rule, err := renderSoulCooperativeBRule(installed.Policy)
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	ruleBytes, err := stage2aReadRootFile(stage2aInstallRulePath(installationID), int64(len(rule)), 0440)
	if err != nil || !bytes.Equal(ruleBytes, []byte(rule)) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(installed.Policy.Runner, *installed.Policy.Bridge,
		installed.Policy.HQUID, installed.Policy.ReviewedStartID)
	if err != nil || !cooperativeEndpointDirectoryMatches(installed.AdmissionDirectory,
		ends.Admission.Directory, ends.Admission.OwnerUID, ends.Admission.GroupGID) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	if !cooperativeEndpointDirectoryMatches(installed.BrokerDirectory,
		ends.Broker.Directory, ends.Broker.OwnerUID, ends.Broker.GroupGID) ||
		!cooperativeEndpointDirectoryMatches(installed.MemberDirectory,
			ends.Member.Directory, ends.Member.OwnerUID, ends.Member.GroupGID) ||
		!cooperativeEndpointDirectoryMatches(installed.RelayDirectory,
			ends.Relay.Directory, ends.Relay.OwnerUID, ends.Relay.GroupGID) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	parents := soulCooperativeBParentsV3{Broker: installed.BrokerDirectory,
		Member: installed.MemberDirectory, Relay: installed.RelayDirectory}
	_, _, bridgeDigest, err := soulCooperativeBLaunchIntentV3(installed.Policy,
		installed.Policy.ReviewedStartID, parents)
	if err != nil || bridgeDigest != installed.Policy.LaunchInputs.BridgeLaunchSHA256 {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	launch, err := cooperativeLaunchPaths(installationID)
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	requestDir, err := stage2aInstalledDirectoryIdentity(launch.requestDir,
		installed.Policy.MachineUID, installed.Policy.Runner.GID, 02750)
	if err != nil || requestDir != installed.RequestDirectory {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	stagingDir, err := stage2aInstalledDirectoryIdentity(launch.stagingDir,
		installed.Policy.MachineUID, installed.Policy.Runner.GID, 02700)
	if err != nil || stagingDir != installed.StagingDirectory {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	completionDir, err := stage2aInstalledDirectoryIdentity(launch.completionDir,
		installed.Policy.MachineUID, installed.Policy.Runner.GID, 02770)
	if err != nil || completionDir != installed.CompletionDirectory {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	wantPlist, err := renderSoulCooperativeLaunchd(installed.Policy)
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	installedPlist, err := stage2aReadRootFile(launch.plist, int64(len(wantPlist)), 0644)
	if err != nil || !bytes.Equal(installedPlist, []byte(wantPlist)) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	r, err := stage2aObserveInstalledDomainV3(installed.RuntimeV3.Snapshot.Path,
		installed.RuntimeV3.Sidecar.Path, uint32(installed.Policy.MachineUID),
		uint32(installed.Policy.Runner.UID), uint32(installed.Policy.Runner.GID),
		"sha256:"+receipt.PlanDigest, installed.Policy.RuntimeV3.InventoryDigest)
	if err != nil || r.ref != installed.RuntimeV3 {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	definition, digest, err := observeStage2aSourceAt(installed.DefinitionSnapshot.RootPath,
		uint32(installed.Policy.MachineUID), uint32(installed.Policy.Runner.GID),
		installed.Policy.Definition, false)
	if err != nil || definition != installed.DefinitionSnapshot ||
		digest != installed.Policy.DefinitionMeasurement ||
		definition.RootPath != installed.Policy.Runner.PackageRoot {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	files, err := stage2aExpandedRuntimeRecords(installed.Policy.LaunchInputs.Files)
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	inputs, _, err := observeStage2aRuntimeAt(installed.LaunchInputsSnapshot.RootPath,
		uint32(installed.Policy.MachineUID), uint32(installed.Policy.Runner.GID), files, false)
	if err != nil || inputs != installed.LaunchInputsSnapshot ||
		inputs.RootPath != cooperativeReviewedInputsRoot(installationID) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	adapters, err := stage2aReadProjectedFile(inputs,
		installed.Policy.LaunchInputs.Files, "host/adapters.json")
	if err != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	installation, err := stage2aReadProjectedFile(inputs,
		installed.Policy.LaunchInputs.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(*installed.Policy.LaunchInputs,
		adapters, installation) != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	profile, err := stage2aReadFrozenClaimFile(inputs, installed.Policy.LaunchInputs.Files,
		"policy/soul-runner-egress.sb")
	if err != nil || !bytes.Equal(profile, soulRunnerProfile) ||
		installed.Policy.LaunchInputs.SandboxPolicyDigest != "sha256:"+harnessSHA(profile) ||
		!stage2aSystemImageSelected(*installed.Policy.LaunchInputs, "/usr/bin/sandbox-exec") {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	sealedProfile, err := stage2aReadRootFile(SoulRunnerSandbox, int64(len(profile)), 0444)
	if err != nil || !bytes.Equal(sealedProfile, profile) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	bridgeProfile, err := stage2aReadRootFile(SoulBridgeSandbox, int64(len(soulBridgeProfile)), 0444)
	if err != nil || !bytes.Equal(bridgeProfile, soulBridgeProfile) ||
		verifyHarnessExecutable(SoulBridgeBinary, installed.Policy.BridgeExecutable.SHA256) != nil {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	childProfile, err := stage2aReadRootFile(SoulChildSandbox, int64(len(soulChildProfile)), 0444)
	if err != nil || !bytes.Equal(childProfile, soulChildProfile) {
		return empty, emptyR, errSoulCooperativeAuthority
	}
	return installed, r, nil
}

// A has no membership in R's socket group. It observes the H:R directory
// leaf through its root-owned parent without gaining traversal or read access.
func cooperativeEndpointDirectoryMatches(want stage2aInstalledDirectory,
	path string, uid, gid int) bool {
	if want.Path != path || want.Inode == "" || want.BirthSeconds <= 0 {
		return false
	}
	parent, err := openStage2aAdminDirectory(filepath.Dir(path), uint32(os.Getuid()))
	if err != nil {
		return false
	}
	defer parent.Close()
	var st unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		st.Mode != unix.S_IFDIR|02750 || st.Uid != uint32(uid) || st.Gid != uint32(gid) ||
		st.Dev != want.Device || fmt.Sprint(st.Ino) != want.Inode ||
		st.Btim.Sec != want.BirthSeconds || st.Btim.Nsec != want.BirthNanoseconds ||
		checkDarwinACLs([]string{path}) != nil {
		return false
	}
	return true
}
