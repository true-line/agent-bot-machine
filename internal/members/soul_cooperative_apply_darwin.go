//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

// Cooperative R has its own reviewed plan and installed authority. Protected
// bridge grants, installed policies and sudo rules are not inputs.
func runSoulCooperativeLaunchApply(s Saved, a Approval, owner string, _ Host, deps Deps,
	paired func(Approval, func() error) error) cli.Result {
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "cooperative Soul launch apply refused: %v", err)
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || deps.Root != nil ||
		a.Purpose != SoulCooperativeLaunchInstallPurpose || a.PlanID != s.PlanID ||
		a.PlanDigest != s.PlanDigest || !digestPattern.MatchString(a.PairCommitment) ||
		!digestPattern.MatchString(a.MachineFingerprint) || s.SoulCooperativeLaunch == nil {
		return refused(errors.New("root, exact paired owner proof and cooperative plan are required"))
	}
	p := *s.SoulCooperativeLaunch
	if p.Schema != soulCooperativeRuntimeInstallSchemaV3 || p.RuntimeV3 == nil ||
		p.validate() != nil || CheckDarwinSoulCooperativeLaunch(s, owner, p.HQUID) != nil {
		return refused(errors.New("saved v3 cooperative plan or host changed"))
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(p.MachinePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize ||
		fmt.Sprintf("%x", sha256.Sum256(key)) != a.MachineFingerprint {
		return refused(errors.New("reviewed Machine key differs from paired signer"))
	}
	ownerAccount, err := user.Lookup(owner)
	if err != nil {
		return refused(errors.New("reviewing owner account is unavailable"))
	}
	ownerUID, err := strconv.ParseUint(ownerAccount.Uid, 10, 32)
	if err != nil || ownerUID < 400 {
		return refused(errors.New("reviewing owner UID is invalid"))
	}
	authorize := harnessAuthority(a, upgradePairGuard(paired), deps.Time)
	if err := authorize(nil); err != nil {
		return refused(err)
	}
	if err := checkStage2aLegacyClaimsEmpty(); err != nil {
		return refused(err)
	}
	protectedPath, err := stage2aAuthorityPath(p.Runner.InstallationID)
	if err != nil {
		return refused(err)
	}
	if _, err := os.Lstat(protectedPath); !errors.Is(err, os.ErrNotExist) {
		return refused(errors.New("installation already has protected authority"))
	}
	if _, err := os.Lstat(stage2aInstallRulePath(p.Runner.InstallationID)); !errors.Is(err, os.ErrNotExist) {
		return refused(errors.New("installation already has protected runtime grant"))
	}
	manager, err := managerBytes()
	if err != nil || harnessSHA(manager) != p.LauncherSHA256 {
		return refused(errors.New("running Machine executable differs from reviewed launcher"))
	}
	bridgeBinary, err := stage2aReadInstallSource(p.BridgeBinarySource, maxReleaseBytes)
	if err != nil || harnessSHA(bridgeBinary) != p.BridgeExecutable.SHA256 {
		return refused(errors.New("reviewed B executable differs from source bytes"))
	}
	rule, err := renderSoulCooperativeBRule(p)
	if err != nil || stage2aCheckSudoersRule([]byte(rule), stage2aInstallRulePath(p.Runner.InstallationID), s.PlanID) != nil {
		return refused(errors.New("fixed cooperative B sudo rule differs from owner review"))
	}
	inv, inventoryRaw, err := stage2aReadReviewedRuntimeV3(*p.RuntimeV3, p.Runner.InstallationID)
	if err != nil {
		return refused(err)
	}
	if !cooperativeRuntimeEntriesMatch(inv, p) {
		return refused(errors.New("sealed R inventory lacks the reviewed Node or Souls code"))
	}
	var soulsEntryDigest string
	for _, row := range inv.Files {
		if row.Path == p.Entry {
			soulsEntryDigest = row.SHA256
		}
	}
	if p.LaunchInputs.ComponentDigests["souls"] != soulsEntryDigest ||
		p.LaunchInputs.ComponentDigests["bridge"] != "sha256:"+p.BridgeExecutable.SHA256 {
		return refused(errors.New("cooperative launch component digests differ from sealed R code"))
	}
	for _, component := range p.RuntimeV3.Components {
		if err := stage2aVerifyRuntimeV3Artifact(component, uint32(ownerUID), inv); err != nil {
			return refused(err)
		}
	}
	root := OSRoot{}
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner,
		HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: s.Plan.Members,
		Changes: s.Plan.Changes(), Result: "started"}
	if err := authorize(func() error {
		receipt.StartedAt = deps.Time().UTC().Format(approvalTime)
		claimed, claimErr := root.Claim(s.PlanID, encodeReceipt(receipt))
		if claimErr != nil {
			return claimErr
		}
		if !claimed {
			return errors.New("cooperative Soul approval was already used")
		}
		return syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID)))
	}); err != nil {
		return refused(err)
	}
	var installedR stage2aDomainInventoryRefV3
	var definition, launchInputs Stage2aSnapshotIdentity
	var undoLaunchd func()
	installErr := authorize(func() error {
		var err error
		installedR, err = installSoulCooperativeR(s, p, key, inventoryRaw, bridgeBinary)
		if err != nil {
			return err
		}
		definition, launchInputs, err = installSoulCooperativeSnapshots(p, uint32(ownerUID))
		return err
	})
	if installErr == nil {
		installErr = authorize(func() error {
			var err error
			undoLaunchd, err = installSoulCooperativeLaunchd(p)
			return err
		})
	}
	rulePath := stage2aInstallRulePath(p.Runner.InstallationID)
	ruleInstalled := false
	if installErr == nil {
		installErr = authorize(func() error {
			if err := stage2aInstallRootFile(rulePath, []byte(rule), 0440); err != nil {
				return err
			}
			ruleInstalled = true
			if err := stage2aVerifySudoersRole(p.Bridge.Account, "cooperative-soul-bridge"); err != nil {
				return err
			}
			return stage2aVerifySudoersRole(p.Runner.Account, "cooperative-soul-child")
		})
	}
	if installErr == nil {
		installErr = authorize(func() error {
			receipt.Result = "applied"
			receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
			canonical, err := s.Plan.Canonical()
			if err != nil {
				return err
			}
			return publishSoulCooperativeInstalled(s, p, a.PairCommitment, installedR,
				definition, launchInputs,
				canonical, encodeReceipt(receipt))
		})
	}
	if installErr == nil {
		installErr = authorize(func() error {
			if err := root.Finish(s.PlanID, encodeReceipt(receipt)); err != nil {
				return err
			}
			return syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID)))
		})
	}
	if installErr != nil {
		if ruleInstalled {
			installErr = errors.Join(installErr, os.Remove(rulePath), syncUpgradeDir(filepath.Dir(rulePath)))
		}
		if undoLaunchd != nil {
			undoLaunchd()
		}
		receipt.Result, receipt.FailedAt = "failed", "cooperative Soul R installation"
		receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
		installErr = errors.Join(installErr, root.Finish(s.PlanID, encodeReceipt(receipt)))
		return failure(diag.MembersApplyFailed, "cooperative Soul installation stopped: %v", installErr)
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", s.PlanID).
		Set("plan_digest", s.PlanDigest).Set("applied", true).Set("receipt", ReceiptPath(s.PlanID))}}
}

func cooperativeRuntimeEntriesMatch(inv stage2aDomainInventoryV3, p SoulCooperativeLaunchPolicy) bool {
	var node, entry, packageJSON bool
	for _, row := range inv.Files {
		switch row.Path {
		case "bin/node":
			node = row.Kind == "regular" && row.Mode == "0550" &&
				row.SHA256 == "sha256:"+p.NodeSHA256
		case "bin/agent-bot-souls.mjs":
			entry = row.Kind == "regular" && (row.Mode == "0440" || row.Mode == "0550") &&
				row.ComponentID == "souls" && stage2aPrefixedDigest.MatchString(row.SHA256)
		case "package.json":
			packageJSON = row.Kind == "regular" && row.Mode == "0440" &&
				row.ComponentID == "souls" && stage2aPrefixedDigest.MatchString(row.SHA256)
		}
	}
	return node && entry && packageJSON
}

func installSoulCooperativeR(s Saved, p SoulCooperativeLaunchPolicy, key, inventory, bridgeBinary []byte) (stage2aDomainInventoryRefV3, error) {
	var empty stage2aDomainInventoryRefV3
	if p.Bridge == nil {
		return empty, errSoulCooperativeAuthority
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, *p.Bridge, p.HQUID, p.ReviewedStartID)
	if err != nil {
		return empty, err
	}
	if err := stage2aEnsureInstallDirectory(launchRuntimeDir, 0, 0, 0755); err != nil {
		return empty, err
	}
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     uint16
	}{
		{filepath.Join(launchRuntimeDir, "c"), 0, 0, 0711},
		{filepath.Join(launchRuntimeDir, "r"), 0, 0, 0711},
		{filepath.Join(launchRuntimeDir, "m"), 0, 0, 0711},
		{filepath.Join(launchRuntimeDir, "s"), 0, 0, 0711},
		{ends.Admission.Directory, ends.Admission.OwnerUID, ends.Admission.GroupGID, uint16(ends.Admission.DirMode)},
		{DarwinBrokerDir, 0, 0, 0755},
		{stage2aProofParent, 0, 0, 0711},
		{filepath.Join(stage2aProofParent, soulEndpointInstallationSlot(p.Runner.InstallationID)), p.MachineUID, p.Bridge.GID, 02710},
		{ends.Broker.Directory, ends.Broker.OwnerUID, ends.Broker.GroupGID, uint16(ends.Broker.DirMode)},
		{ends.Member.Directory, ends.Member.OwnerUID, ends.Member.GroupGID, uint16(ends.Member.DirMode)},
		{ends.Relay.Directory, ends.Relay.OwnerUID, ends.Relay.GroupGID, uint16(ends.Relay.DirMode)},
		{stage2aCooperativeAuthorityDir, p.MachineUID, p.MachineGID, 0700},
		{stage2aClaimsParent, 0, 0, 0711},
		{stage2aCooperativeClaimsPath(p.Runner.InstallationID), p.MachineUID, p.MachineGID, 0700},
	} {
		if err := stage2aEnsureInstallDirectory(d.path, d.uid, d.gid, d.mode); err != nil {
			return empty, err
		}
	}
	if err := stage2aInstallRootFile(SoulAuthorityPin, key, 0444); err != nil {
		return empty, err
	}
	manager, err := managerBytes()
	if err != nil || harnessSHA(manager) != p.LauncherSHA256 {
		return empty, errSoulCooperativeAuthority
	}
	if err := stage2aInstallRootFile(SoulLauncher, manager, 0755); err != nil {
		return empty, err
	}
	if err := stage2aInstallRootFile(SoulBridgeBinary, bridgeBinary, 0755); err != nil {
		return empty, err
	}
	if err := stage2aInstallRootFile(SoulBridgeSandbox, soulBridgeProfile, 0444); err != nil {
		return empty, err
	}
	if p.LaunchInputs == nil || p.LaunchInputs.SandboxPolicyDigest !=
		"sha256:"+harnessSHA(soulRunnerProfile) ||
		!stage2aSystemImageSelected(*p.LaunchInputs, "/usr/bin/sandbox-exec") {
		return empty, errSoulCooperativeAuthority
	}
	if err := stage2aInstallRootFile(SoulRunnerSandbox, soulRunnerProfile, 0444); err != nil {
		return empty, err
	}
	if err := stage2aInstallRootFile(SoulChildSandbox, soulChildProfile, 0444); err != nil {
		return empty, err
	}
	machine, err := user.LookupId(strconv.Itoa(p.MachineUID))
	if err != nil || !accountName.MatchString(machine.Username) {
		return empty, errSoulCooperativeAuthority
	}
	return stage2aInstallRuntimeV3AsAdmin(stage2aRuntimeStageV3{
		InstallationID: p.Runner.InstallationID,
		MachineAccount: machine.Username, MachineUID: p.MachineUID, MachineGID: p.MachineGID,
		ReaderAccount: p.Runner.Account, ReaderUID: p.Runner.UID, ReaderGID: p.Runner.GID,
		PlanDigest: s.PlanDigest, InventoryDigest: p.RuntimeV3.InventoryDigest,
		LauncherSHA256: p.LauncherSHA256, Inventory: inventory,
		SourceRoots: p.RuntimeV3.SourceRoots,
	})
}

func installSoulCooperativeSnapshots(p SoulCooperativeLaunchPolicy, ownerUID uint32) (
	Stage2aSnapshotIdentity, Stage2aSnapshotIdentity, error) {
	var empty Stage2aSnapshotIdentity
	namespace, err := stage2aFrozenNamespace(p.Runner.InstallationID)
	if err != nil {
		return empty, empty, err
	}
	if err := stage2aEnsureInstallDirectory(stage2aFrozenSnapshotParent, 0, 0, 0711); err != nil {
		return empty, empty, err
	}
	if err := stage2aEnsureInstallDirectory(namespace, p.MachineUID, p.Runner.GID, 0750); err != nil {
		return empty, empty, err
	}
	ns, err := stage2aInstalledDirectoryIdentity(namespace, p.MachineUID, p.Runner.GID, 0750)
	if err != nil {
		return empty, empty, err
	}
	machine, err := user.LookupId(strconv.Itoa(p.MachineUID))
	if err != nil || !accountName.MatchString(machine.Username) {
		return empty, empty, errSoulCooperativeAuthority
	}
	var results [2]Stage2aSnapshotIdentity
	for i, source := range []struct {
		path, kind, purpose string
		records             []Stage2aDefinitionRecord
		runtime             bool
	}{
		{p.DefinitionSource, "definition", stage2aCooperativeDefinitionSealPurpose, p.Definition, false},
		{p.LaunchInputsSource, "inputs", stage2aCooperativeInputsSealPurpose, p.LaunchInputs.Files, true},
	} {
		st, err := os.Lstat(source.path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return empty, empty, errSoulCooperativeAuthority
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != ownerUID &&
			stat.Uid != uint32(p.HQUID) && stat.Uid != uint32(p.MachineUID)) {
			return empty, empty, errSoulCooperativeAuthority
		}
		opened, err := openStage2aAdminDirectory(source.path, stat.Uid)
		if err != nil {
			return empty, empty, err
		}
		opened.Close()
		prepared, err := prepareStage2aInstallSnapshotAt(source.path, namespace,
			stage2aInstallSnapshotName(p.Runner.InstallationID, source.kind),
			stat.Uid, stat.Gid, uint32(p.MachineUID), uint32(p.Runner.GID),
			source.records, source.runtime)
		if err != nil {
			return empty, empty, err
		}
		request := stage2aSharedSealRequest{Schema: stage2aSharedSealSchema,
			Purpose: source.purpose, Kind: source.kind,
			MachineAccount: machine.Username, MachineUID: p.MachineUID, MachineGID: p.MachineGID,
			RunnerAccount: p.Runner.Account, RunnerUID: p.Runner.UID, RunnerGID: p.Runner.GID,
			InstallationID: p.Runner.InstallationID, Namespace: ns,
			LauncherSHA256: p.LauncherSHA256, Prepared: prepared,
			Approved: source.records, ApprovedDigest: prepared.Digest}
		identity, digest, err := stage2aSealCooperativeSnapshotAsAdmin(request)
		stage2aCleanPrivateStage(prepared.WrapperPath)
		if err != nil {
			return empty, empty, err
		}
		if i == 0 && digest != p.DefinitionMeasurement {
			return empty, empty, errSoulCooperativeAuthority
		}
		results[i] = identity
	}
	profile, err := stage2aReadFrozenClaimFile(results[1], p.LaunchInputs.Files,
		"policy/soul-runner-egress.sb")
	if err != nil || !bytes.Equal(profile, soulRunnerProfile) {
		return empty, empty, errSoulCooperativeAuthority
	}
	adapters, err := stage2aReadProjectedFile(results[1], p.LaunchInputs.Files, "host/adapters.json")
	if err != nil {
		return empty, empty, errSoulCooperativeAuthority
	}
	installation, err := stage2aReadProjectedFile(results[1], p.LaunchInputs.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(*p.LaunchInputs, adapters, installation) != nil {
		return empty, empty, errSoulCooperativeAuthority
	}
	return results[0], results[1], nil
}
