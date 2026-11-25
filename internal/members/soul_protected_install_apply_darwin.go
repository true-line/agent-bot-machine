//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
	"golang.org/x/sys/unix"
)

const stage2aClaimsParent = launchRuntimeDir + "/stage2a-claims"
const stage2aArtifactsParent = launchRuntimeDir + "/soul-artifacts"
const stage2aProofParent = launchRuntimeDir + "/b-grants"

func runSoulProtectedLaunchApply(s Saved, a Approval, owner string, h Host, deps Deps,
	paired func(Approval, func() error) error) cli.Result {
	refused := func(err error) cli.Result {
		return failure(diag.MembersNotApproved, "protected Soul launch apply refused: %v", err)
	}
	// A reviewed v3 R installation may seal source bytes while positive start
	// stays closed. The legacy v2 installer must not acquire new authority.
	if !stage2aProtectedStartContractReady &&
		(s.SoulProtectedLaunch == nil || s.SoulProtectedLaunch.RuntimeV3 == nil) {
		return refused(errors.New("authenticated H/R code contract and preloader are not released"))
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || deps.Root != nil ||
		a.Purpose != SoulProtectedLaunchInstallPurpose || a.PlanID != s.PlanID ||
		a.PlanDigest != s.PlanDigest || !digestPattern.MatchString(a.PairCommitment) ||
		!digestPattern.MatchString(a.MachineFingerprint) {
		return refused(errors.New("root, exact paired owner proof and production installer are required"))
	}
	request := s.SoulProtectedLaunch
	if request == nil {
		return refused(errors.New("missing protected Soul installation request"))
	}
	key, err := hex.DecodeString(request.MachinePublicKey)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(key)) != a.MachineFingerprint {
		return refused(errors.New("reviewed Machine public key differs from paired signer"))
	}
	var policy stage2aInstalledPolicy
	if json.Unmarshal(request.Policy, &policy) != nil ||
		CheckDarwinSoulProtectedLaunch(s, owner, policy.HQUID) != nil {
		return refused(errors.New("saved protected Soul plan or host changed"))
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
	var localTestOwner stage2aLocalTestOwnerPlan
	var localTestOwnerSHA string
	var localTestQ stage2aLocalTestQPlan
	var localTestQRef stage2aLocalTestQApprovalReference
	var localTestQEnvelope []byte
	if request.Schema == stage2aLocalTestInstallSchema {
		approvedUntil, parseErr := time.Parse(time.RFC3339Nano, policy.ApprovedUntil)
		if parseErr != nil {
			return refused(errStage2aReservationAuthority)
		}
		localTestOwner, localTestOwnerSHA, err = parseStage2aLocalTestOwnerPlan(
			policy.ObservedBodyLocalTest, policy.BridgeQualification, approvedUntil)
		if err != nil || policy.LocalTestQPlanID != request.LocalTestQPlanID {
			return refused(errStage2aReservationAuthority)
		}
		qPath, pathErr := stage2aLocalTestQRootEnvelopePathForPlan(request.LocalTestQPlanID)
		if pathErr != nil {
			return refused(pathErr)
		}
		localTestQEnvelope, err = stage2aReadRootFile(qPath, stage2aV3EnvelopeLimit, 0400)
		if err != nil {
			return refused(errStage2aReservationAuthority)
		}
		localTestQ, localTestQRef, err = stage2aLocalTestQApprovalForInstall(
			localTestQEnvelope, ed25519.PublicKey(key), s.PlanID, s.PlanDigest,
			request.LocalTestQPlanID, policy.Binding.InstallationID, localTestOwnerSHA,
			localTestOwner.Revision, localTestOwner.Members[0].AdapterManifestSHA256,
			a.MachineFingerprint, a.PairCommitment, deps.Time())
		if err != nil {
			return refused(err)
		}
		lead := localTestOwner.Members[0]
		if _, err := stage2aLocalTestInstallReceiptFor(localTestOwner, localTestOwnerSHA,
			localTestQ, "sha256:"+localTestQRef.PlanDigest, localTestQRef,
			stage2aLocalTestMeasuredLead{AdapterManifestSHA256: lead.AdapterManifestSHA256,
				CommandSHA256: lead.CommandSHA256, AdjacentCLISHA256: lead.AdjacentCLISHA256},
			s.PlanID, s.PlanDigest, policy.Binding.InstallationID, ed25519.PublicKey(key)); err != nil {
			return refused(errStage2aReservationAuthority)
		}
	}
	if err := checkStage2aLegacyClaimsEmpty(); err != nil {
		return refused(err)
	}
	manager, err := managerBytes()
	if err != nil || harnessSHA(manager) != policy.LauncherSHA256 {
		return refused(errors.New("running Machine executable differs from reviewed Soul launcher"))
	}
	artifact, err := stage2aReadInstallSource(request.ArtifactSource, stage2aMaxFileBytes)
	if err != nil || stage2aReservationSHA256(artifact) != "sha256:"+policy.Binding.SoulArtifactSHA256 {
		return refused(errors.New("frozen Soul artifact differs from owner review"))
	}
	bridgeBinary, err := stage2aReadInstallSource(request.BridgeBinarySource, maxReleaseBytes)
	if err != nil || harnessSHA(bridgeBinary) != policy.BridgeExecutable.SHA256 {
		return refused(errors.New("native bridge binary differs from owner review"))
	}
	rulePath := stage2aInstallRulePath(policy.Binding.InstallationID)
	publishRule := request.RuntimeV3 == nil
	var rule string
	if publishRule {
		rule, err = RenderSoulProtectedRule([]SoulRunner{policy.Runner}, []SoulBridge{policy.Bridge}, policy.HQUID, nil, policy.LauncherSHA256)
		if err != nil {
			return refused(err)
		}
		if err := stage2aCheckSudoersRule([]byte(rule), rulePath, s.PlanID); err != nil {
			return refused(err)
		}
	} else if _, err := os.Lstat(rulePath); !errors.Is(err, os.ErrNotExist) {
		return refused(errors.New("R-only install found an existing protected launch rule"))
	}
	root := OSRoot{}
	receipt := Receipt{PlanID: s.PlanID, PlanDigest: s.PlanDigest, Owner: owner,
		HQAccount: DarwinHQAccount, Dir: DarwinDir, Members: s.Plan.Members,
		Changes: s.Plan.Changes(), Result: "started"}
	err = authorize(func() error {
		receipt.StartedAt = deps.Time().UTC().Format(approvalTime)
		claimed, claimErr := root.Claim(s.PlanID, encodeReceipt(receipt))
		if claimErr != nil {
			return claimErr
		}
		if !claimed {
			return errors.New("protected Soul approval was already used")
		}
		return syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID)))
	})
	if err != nil {
		return refused(err)
	}
	var installErr error
	if request.Schema == stage2aLocalTestInstallSchema {
		installErr = authorize(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			spent, err := loadAndSpendStage2aLocalTestQRootApproval(ctx,
				localTestQ, localTestQRef, localTestOwnerSHA, a.MachineFingerprint,
				a.PairCommitment, ed25519.PublicKey(key), deps.Time())
			if err != nil || spent.ApprovalEnvelopeSHA256 != stage2aReservationSHA256(localTestQEnvelope) {
				return errStage2aReservationAuthority
			}
			spentRaw, err := marshalStage2aReservationJCS(spent)
			if err != nil {
				return errStage2aReservationAuthority
			}
			receipt.Stage2aLocalTestQSpend = spentRaw
			return nil
		})
	}
	if installErr == nil {
		installErr = authorize(func() error {
			return stage2aInstallFiles(s, request, &policy, uint32(ownerUID), key, manager, artifact, bridgeBinary)
		})
	}
	committed := false
	if installErr == nil {
		installErr = authorize(func() error {
			if request.Schema == stage2aLocalTestInstallSchema {
				localReceipt, err := stage2aLocalTestReceiptFromSealedRuntime(policy,
					localTestOwner, localTestOwnerSHA, localTestQ, localTestQRef, ed25519.PublicKey(key))
				if err != nil {
					return err
				}
				localRaw, err := marshalStage2aReservationJCS(localReceipt)
				if err != nil {
					return err
				}
				policy.ObservedBodyLocalTestReceipt = &localReceipt
				receipt.Stage2aLocalTestReceipt = localRaw
				receipt.Stage2aLocalTestQApprovalEnvelope = base64.RawURLEncoding.EncodeToString(localTestQEnvelope)
			}
			receipt.Result = "applied"
			receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
			receipt.Stage2aRuntimeV3 = policy.RuntimeV3
			canonical, err := s.Plan.Canonical()
			if err != nil {
				return err
			}
			policy.Plan = bytes.TrimSuffix(canonical, []byte{'\n'})
			policy.Receipt = encodeReceipt(receipt)
			return stage2aPublishInstalledPolicy(policy)
		})
	}
	if installErr == nil && publishRule {
		installErr = authorize(func() error {
			if err := stage2aInstallRootFile(rulePath, []byte(rule), 0440); err != nil {
				return err
			}
			if err := stage2aVerifySudoersRole(policy.Runner.Account, "soul-run"); err != nil {
				return err
			}
			if err := stage2aVerifySudoersRole(policy.Runner.Account, "soul-child"); err != nil {
				return err
			}
			return stage2aVerifySudoersRole(policy.Bridge.Account, "soul-bridge")
		})
	}
	if installErr == nil {
		installErr = authorize(func() error {
			if err := root.Finish(s.PlanID, encodeReceipt(receipt)); err != nil {
				return err
			}
			if err := syncUpgradeDir(filepath.Dir(ReceiptPath(s.PlanID))); err != nil {
				return err
			}
			committed = true
			return nil
		})
	}
	if installErr != nil {
		// A visible partial install has no successful receipt or no complete
		// rule. Preserve occupied names for explicit reviewed retirement.
		if !committed {
			receipt.Result, receipt.FailedAt = "failed", "protected Soul installation"
			receipt.FinishedAt = deps.Time().UTC().Format(approvalTime)
			installErr = errors.Join(installErr, root.Finish(s.PlanID, encodeReceipt(receipt)))
		}
		return failure(diag.MembersApplyFailed, "protected Soul installation stopped: %v", installErr)
	}
	committedReceipt := encodeReceipt(receipt)
	physicalReceipt := filepath.Join("/private"+DarwinReceiptsDir, s.PlanID+".json")
	readback, readErr := stage2aReadRootFile(physicalReceipt, int64(len(committedReceipt)), 0644)
	if readErr != nil || !bytes.Equal(readback, committedReceipt) {
		return failure(diag.MembersApplyFailed, "protected Soul applied receipt failed root readback")
	}
	row := output.New().Set("plan_id", s.PlanID).Set("plan_digest", s.PlanDigest).
		Set("applied", true).Set("receipt", ReceiptPath(s.PlanID)).
		Set("receipt_sha256", stage2aReservationSHA256(readback))
	if request.Schema == stage2aLocalTestInstallSchema {
		row.Set("q_plan_id", request.LocalTestQPlanID).
			Set("q_plan_sha256", "sha256:"+localTestQRef.PlanDigest).
			Set("q_envelope_sha256", stage2aReservationSHA256(localTestQEnvelope))
	}
	return cli.Result{Records: []*output.Record{row}}
}

func stage2aInstallFiles(s Saved, request *SoulProtectedLaunchInstall, p *stage2aInstalledPolicy, ownerUID uint32,
	key, manager, artifact, bridgeBinary []byte) error {
	if request.RuntimeV3 != nil && !stage2aProtectedPackageMeasurementV3(*p) {
		return errStage2aReservationAuthority
	}
	p.Binding.PlanID, p.Binding.InstalledPlanDigest = s.PlanID, s.PlanDigest
	if err := stage2aEnsureInstallDirectory(launchRuntimeDir, 0, 0, 0755); err != nil {
		return err
	}
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     uint16
	}{
		{stage2aArtifactsParent, 0, 0, 0755},
		{stage2aAuthorityDirectory, p.MachineUID, p.MachineGID, 0700},
		{stage2aClaimsParent, 0, 0, 0711},
		{stage2aProofParent, 0, 0, 0711},
		{stage2aFrozenSnapshotParent, 0, 0, 0711},
	} {
		if err := stage2aEnsureInstallDirectory(d.path, d.uid, d.gid, d.mode); err != nil {
			return err
		}
	}
	claimPath := filepath.Join(stage2aClaimsParent, soulEndpointInstallationSlot(p.Binding.InstallationID))
	namespace, _ := stage2aFrozenNamespace(p.Binding.InstallationID)
	proofPath := filepath.Join(stage2aProofParent, soulEndpointInstallationSlot(p.Binding.InstallationID))
	for _, d := range []struct {
		path     string
		uid, gid int
		mode     uint16
	}{
		{claimPath, p.MachineUID, p.MachineGID, 0700},
		{namespace, p.MachineUID, p.Runner.GID, 0750},
		{proofPath, p.MachineUID, p.Bridge.GID, 02710},
	} {
		if err := stage2aEnsureInstallDirectory(d.path, d.uid, d.gid, d.mode); err != nil {
			return err
		}
	}
	var err error
	p.Claims, err = stage2aInstalledDirectoryIdentity(claimPath, p.MachineUID, p.MachineGID, 0700)
	if err != nil {
		return err
	}
	p.SnapshotNamespace, err = stage2aInstalledDirectoryIdentity(namespace, p.MachineUID, p.Runner.GID, 0750)
	if err != nil {
		return err
	}
	ends, err := DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, "st_000000000000000000000000")
	if err != nil {
		return err
	}
	for _, endpoint := range []SoulEndpoint{ends.Broker, ends.Member, ends.Relay, ends.Admission} {
		if _, err := stage2aInstalledDirectoryIdentity(endpoint.Directory, endpoint.OwnerUID, endpoint.GroupGID, uint16(endpoint.DirMode)); err != nil {
			return err
		}
	}
	p.RelayParent, err = stage2aInstalledDirectoryIdentity(ends.Relay.Directory, ends.Relay.OwnerUID, ends.Relay.GroupGID, uint16(ends.Relay.DirMode))
	if err != nil {
		return err
	}
	for _, asset := range []struct {
		path string
		raw  []byte
		mode uint16
	}{
		{SoulAuthorityPin, key, 0444}, {SoulLauncher, manager, 0755},
		{SoulRunnerSandbox, soulRunnerProfile, 0444}, {SoulBridgeSandbox, soulBridgeProfile, 0444},
		{SoulChildSandbox, soulChildProfile, 0444},
		{SoulBridgeBinary, bridgeBinary, 0755},
		{p.ArtifactPath, artifact, 0444},
	} {
		if err := stage2aInstallRootFile(asset.path, asset.raw, asset.mode); err != nil {
			return err
		}
	}
	for _, source := range []struct {
		path, kind string
		records    []Stage2aDefinitionRecord
		identity   *Stage2aSnapshotIdentity
		runtime    bool
	}{
		{request.DefinitionSource, "definition", p.Definition, &p.Binding.Snapshots.Definition, false},
		{request.LaunchInputsSource, "inputs", p.LaunchInputs.Files, &p.Binding.Snapshots.LaunchInputs, true},
	} {
		st, err := os.Lstat(source.path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errStage2aReservationAuthority
		}
		sys := st.Sys().(*syscall.Stat_t)
		// Inputs may be staged by the reviewing owner or dedicated HQ. The
		// exact source path, complete inventory and hashes are in the approved
		// plan; a no-follow walk rejects writable or redirected ancestors.
		if sys.Uid != 0 && sys.Uid != ownerUID && sys.Uid != uint32(p.HQUID) &&
			sys.Uid != uint32(p.MachineUID) {
			return errStage2aReservationAuthority
		}
		sourceDir, err := openStage2aAdminDirectory(source.path, sys.Uid)
		if err != nil {
			return errStage2aReservationAuthority
		}
		sourceDir.Close()
		prepared, err := prepareStage2aInstallSnapshotAt(source.path, namespace,
			stage2aInstallSnapshotName(p.Binding.InstallationID, source.kind),
			sys.Uid, sys.Gid, uint32(p.MachineUID), uint32(p.Runner.GID), source.records, source.runtime)
		if err != nil {
			return err
		}
		identity, digest, err := stage2aSealAsAdmin(*p, prepared, source.kind)
		stage2aCleanPrivateStage(prepared.WrapperPath)
		if err != nil {
			return err
		}
		if source.identity == &p.Binding.Snapshots.Definition && digest != p.Binding.DefinitionMeasurement {
			return errStage2aReservationAuthority
		}
		*source.identity = identity
	}
	var runtimeInventory stage2aDomainInventoryV3
	if request.RuntimeV3 != nil {
		inv, raw, err := stage2aReadReviewedRuntimeV3(*request.RuntimeV3, p.Binding.InstallationID)
		if err != nil {
			return err
		}
		for _, component := range request.RuntimeV3.Components {
			if err := stage2aVerifyRuntimeV3Artifact(component, ownerUID, inv); err != nil {
				return err
			}
		}
		ref, err := stage2aInstallRuntimeV3AsAdmin(stage2aRuntimeStageV3{
			InstallationID: p.Binding.InstallationID,
			MachineAccount: p.MachineAccount, MachineUID: p.MachineUID, MachineGID: p.MachineGID,
			ReaderAccount: p.Runner.Account, ReaderUID: p.Runner.UID, ReaderGID: p.Runner.GID,
			PlanDigest: s.PlanDigest, InventoryDigest: request.RuntimeV3.InventoryDigest,
			LauncherSHA256: p.LauncherSHA256, Inventory: raw,
			SourceRoots: request.RuntimeV3.SourceRoots,
		})
		if err != nil {
			return err
		}
		p.RuntimeV3 = &ref
		runtimeInventory = inv
	}
	if _, _, err := stage2aBindingDigestForOwner(p.Binding, uint32(p.MachineUID)); err != nil {
		return err
	}
	if p.RuntimeV3 == nil && !stage2aSelectedCommandRecorded(p.Binding, p.Definition, p.LaunchInputs) ||
		p.RuntimeV3 != nil && !stage2aSelectedCommandRecordedV3(*p, runtimeInventory) {
		return errStage2aReservationAuthority
	}
	adapters, err := stage2aReadProjectedFile(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files, "host/adapters.json")
	if err != nil {
		return err
	}
	installation, err := stage2aReadProjectedFile(p.Binding.Snapshots.LaunchInputs, p.LaunchInputs.Files, "host/installation.json")
	if err != nil || CheckStage2aHostProjectionBytes(p.LaunchInputs, adapters, installation) != nil {
		return errStage2aReservationAuthority
	}
	if err := stage2aCheckFrozenSoulClaim(p.Binding.Snapshots.Definition, p.Definition, p.Binding.SoulID, p.Binding.ClaimedDefinitionDigest); err != nil {
		return err
	}
	return nil
}

func stage2aInstallRulePath(installationID string) string {
	return filepath.Join("/private/etc/sudoers.d", "agent-bot-hq-soul-"+soulEndpointInstallationSlot(installationID))
}

func checkStage2aLegacyClaimsEmpty() error {
	names, err := os.ReadDir(soulStartClaimsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || len(names) != 0 {
		return errors.New("legacy root-owned Soul start claims require reviewed migration before protected installation")
	}
	return nil
}

func stage2aReadInstallSource(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > limit || checkDarwinACLs([]string{path}) != nil {
		return nil, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}

func stage2aEnsureInstallDirectory(path string, uid, gid int, mode uint16) error {
	if st, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		createMode := os.FileMode(mode)
		if mode&02000 != 0 {
			createMode = os.FileMode(mode &^ 02000)
		}
		created, err := createProtectedDirectory(path, uid, gid, createMode)
		if err != nil {
			return err
		}
		if mode&02000 != 0 {
			if err = unix.Fchmod(int(created.Fd()), uint32(mode)); err == nil {
				err = created.Sync()
			}
		}
		created.Close()
		if err != nil {
			return err
		}
	} else if err != nil || !st.IsDir() {
		return errStage2aReservationAuthority
	}
	_, err := stage2aInstalledDirectoryIdentity(path, uid, gid, mode)
	return err
}

func stage2aInstalledDirectoryIdentity(path string, uid, gid int, mode uint16) (stage2aInstalledDirectory, error) {
	var out stage2aInstalledDirectory
	fd, err := unix.Open(path, stage2aDirectoryOpenFlags, 0)
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|mode || st.Uid != uint32(uid) || st.Gid != uint32(gid) || st.Btim.Sec <= 0 || checkDarwinACLs([]string{path}) != nil {
		return out, errStage2aReservationAuthority
	}
	out = stage2aInstalledDirectory{Path: path, Device: st.Dev, Inode: fmt.Sprint(st.Ino), BirthSeconds: st.Btim.Sec, BirthNanoseconds: st.Btim.Nsec}
	return out, nil
}

func stage2aInstallRootFile(path string, raw []byte, mode uint16) error {
	if len(raw) == 0 {
		return errStage2aReservationAuthority
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeUpgradeFile(path, raw, os.FileMode(mode), true); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	actual, err := stage2aReadRootFile(path, int64(len(raw)), mode)
	if err != nil || !bytes.Equal(raw, actual) {
		return errStage2aReservationAuthority
	}
	return nil
}

func stage2aPublishInstalledPolicy(p stage2aInstalledPolicy) error {
	path, err := stage2aAuthorityPath(p.Binding.InstallationID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 1<<20 || stage2aStrictJSON(raw) != nil {
		return errStage2aReservationAuthority
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errStage2aReservationAuthority
	}
	f, err := os.CreateTemp(stage2aAuthorityDirectory, ".stage2a-policy-*")
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
	return syncUpgradeDir(stage2aAuthorityDirectory)
}

func stage2aCheckSudoersRule(raw []byte, final, id string) error {
	if !ValidApproval(id, strings.Repeat("0", 64)) || len(raw) == 0 || len(raw) > 16<<10 {
		return errStage2aReservationAuthority
	}
	f, err := os.CreateTemp(filepath.Dir(final), ".stage2a-rule-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Chmod(0440); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	cmd := exec.Command("/usr/sbin/visudo", "-c", "-f", f.Name())
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return cmd.Run()
}

func stage2aVerifySudoersRole(account, role string) error {
	cmd := exec.Command("/usr/bin/sudo", "-n", "-l", "-U", DarwinHQAccount, "-u", account, "--", SoulLauncher, role)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return cmd.Run()
}
