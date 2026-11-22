//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
)

const stage2aInstallSchema = "agent-bot-machine/soul-protected-launch-install/v1"

var stage2aMessagesQuery = regexp.MustCompile(`^[a-zA-Z0-9._=&%-]{0,128}$`)

func decodeSoulProtectedLaunch(raw []byte) (*SoulProtectedLaunchInstall, error) {
	if len(raw) == 0 || len(raw) > 48<<10 || stage2aStrictJSON(raw) != nil {
		return nil, errors.New("protected Soul launch request exceeds the paired review limit or is invalid JSON")
	}
	var request SoulProtectedLaunchInstall
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid protected Soul launch request")
	}
	if request.Schema != stage2aInstallSchema || !stage2aAbsolutePath(request.ArtifactSource) ||
		!stage2aAbsolutePath(request.BridgeBinarySource) ||
		!stage2aAbsolutePath(request.DefinitionSource) || !stage2aAbsolutePath(request.LaunchInputsSource) ||
		len(request.Policy) == 0 || len(request.Policy) > 40<<10 {
		return nil, errors.New("protected Soul launch request has invalid sources or policy")
	}
	key, err := hex.DecodeString(request.MachinePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != request.MachinePublicKey {
		return nil, errors.New("protected Soul launch request has no exact Machine public key")
	}
	return &request, nil
}

func planSoulProtectedLaunch(deps Deps, file string) cli.Result {
	raw, err := readQualificationInput(file)
	if err != nil {
		return failure(diag.MembersListInvalid, "cannot read protected Soul launch request: %v", err)
	}
	request, err := decodeSoulProtectedLaunch(raw)
	if err != nil {
		return failure(diag.MembersListInvalid, "%v", err)
	}
	var h Host = OSHost{}
	if deps.Host != nil {
		h = deps.Host()
	}
	owner, err := deps.ResolveUsername(usernameOS(PlatformDarwin))
	if err != nil {
		return failure(diag.MembersAccountRefused, "cannot identify the planning owner: %v", err)
	}
	p, err := Build(Input{SoulProtectedLaunch: request, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, h)
	if err != nil {
		return mapRefusal(err, diag.MembersPlanFailed, "cannot plan protected Soul launch")
	}
	// Build records the exact running launcher digest. Save that normalized
	// request, not the caller's unreviewed placeholder.
	request = p.SoulProtectedLaunch
	digest, err := p.Digest()
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot digest protected Soul launch plan: %v", err)
	}
	now := deps.Time()
	id, err := deps.PlanID(now)
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot make protected Soul launch plan ID: %v", err)
	}
	state, err := deps.ResolveStateDir("darwin")
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot locate owner plan store: %v", err)
	}
	s := Saved{SoulProtectedLaunch: request, PlanID: id, PlanDigest: digest,
		CreatedAt: now.UTC().Format(approvalTime), Plan: p}
	if err := save(filepath.Join(state, "members", "plans"), s); err != nil {
		return failure(diag.MembersPlanFailed, "cannot save protected Soul launch plan: %v", err)
	}
	row := output.New().Set("plan_id", id).Set("plan_digest", digest).
		Set("purpose", SoulProtectedLaunchInstallPurpose).Set("members", p.Members).
		Set("changes", p.Changes()).Set("applied", false).
		Set("advice", "The paired HQ must obtain the owner's exact proof before root applies this protected launch plan.")
	return cli.Result{Records: []*output.Record{row}}
}

func buildSoulProtectedLaunch(in Input, h Host) (Plan, error) {
	invalid := errors.New("invalid protected Soul launch installation")
	if in.Platform != PlatformDarwin || in.HQAccount != DarwinHQAccount || in.Dir != DarwinDir ||
		len(in.Members) != 0 || in.HarnessAccounts || in.SoulRunnerAccounts != nil ||
		in.SoulBridgeAccounts != nil || in.HarnessLaunch != nil || in.HQService != nil ||
		in.UpgradeFrom != nil || in.SoulProtectedLaunch == nil {
		return Plan{}, invalid
	}
	r := *in.SoulProtectedLaunch
	if _, err := decodeSoulProtectedLaunch(mustStage2aJSON(r)); err != nil {
		return Plan{}, err
	}
	var policy stage2aInstalledPolicy
	d := json.NewDecoder(bytes.NewReader(r.Policy))
	d.DisallowUnknownFields()
	if d.Decode(&policy) != nil || d.Decode(new(any)) != io.EOF ||
		policy.Schema != "agent-bot-machine/stage2a-installed-authority/v1" ||
		policy.PlanOwner != in.Invoker || policy.MachineUID < 400 || policy.MachineGID < 1 ||
		policy.HQUID < 300 || policy.HQUID > 399 ||
		policy.Binding.Contract != "machine/v2" || policy.Binding.SchemaVersion != 2 ||
		policy.Binding.Kind != "stage2a-measurement-binding" ||
		policy.Binding.ProfileInForce != "managed-protected" ||
		policy.Binding.PlanID != "" || policy.Binding.InstalledPlanDigest != "" ||
		policy.Binding.StartID != "" || policy.Binding.LaunchID != "" ||
		len(policy.Plan) != 0 || len(policy.Receipt) != 0 || policy.Claims != (stage2aInstalledDirectory{}) ||
		policy.SnapshotNamespace != (stage2aInstalledDirectory{}) || policy.RelayParent != (stage2aInstalledDirectory{}) || policy.LegacySpent == nil ||
		len(policy.LegacySpent) != 0 || !soulHQEpoch.MatchString(policy.Binding.HQEpoch) ||
		!stage2aBindingID.MatchString(policy.Binding.HostID) ||
		!stage2aBindingID.MatchString(policy.Binding.InstallationID) ||
		!soulIdentity.MatchString(policy.Binding.SoulID) ||
		!soulDigest.MatchString(policy.Binding.PackageSHA256) ||
		!soulDigest.MatchString(policy.Binding.SoulArtifactSHA256) ||
		!stage2aPrefixedDigest.MatchString(policy.Binding.ClaimedDefinitionDigest) ||
		policy.Runner.InstallationID != policy.Binding.InstallationID ||
		policy.Runner.SoulID != policy.Binding.SoulID ||
		policy.Bridge.InstallationID != policy.Binding.InstallationID ||
		policy.Bridge.SoulID != policy.Binding.SoulID ||
		policy.Runner.PackageSHA256 != policy.Binding.PackageSHA256 ||
		policy.Runner.Account != soulRunnerName(policy.Binding.InstallationID) ||
		policy.Bridge.Account != SoulBridgeName(policy.Binding.InstallationID) ||
		policy.ArtifactPath != stage2aArtifactPath(policy.Binding.InstallationID) ||
		!stage2aAbsolutePath(policy.Runner.PackageRoot) ||
		policy.Node == "" || policy.Entry == "" {
		return Plan{}, invalid
	}
	namespace, err := stage2aFrozenNamespace(policy.Binding.InstallationID)
	if err != nil || !stage2aInstallSnapshotClaim(policy.Binding.Snapshots.Definition,
		filepath.Join(namespace, stage2aInstallSnapshotName(policy.Binding.InstallationID, "definition")),
		policy.MachineUID, policy.Runner.GID) ||
		!stage2aInstallSnapshotClaim(policy.Binding.Snapshots.LaunchInputs,
			filepath.Join(namespace, stage2aInstallSnapshotName(policy.Binding.InstallationID, "inputs")),
			policy.MachineUID, policy.Runner.GID) {
		return Plan{}, invalid
	}
	if !stage2aRuntimeFile(policy.Binding.Snapshots.LaunchInputs.RootPath, policy.Node, "bin/node", policy.LaunchInputs.Files, true) ||
		!stage2aRuntimeFile(policy.Binding.Snapshots.LaunchInputs.RootPath, policy.Entry, "bin/agent-bot-souls.mjs", policy.LaunchInputs.Files, false) ||
		policy.LaunchInputs.SelectedCommand != policy.Node ||
		policy.LaunchInputs.SandboxPolicyDigest != "sha256:"+harnessSHA(soulRunnerProfile) ||
		!stage2aSystemImageSelected(policy.LaunchInputs, "/usr/bin/sandbox-exec") ||
		policy.BridgeExecutable.Path != SoulBridgeBinary ||
		!soulDigest.MatchString(policy.BridgeExecutable.SHA256) ||
		policy.LaunchInputs.ComponentDigests["bridge"] != "sha256:"+policy.BridgeExecutable.SHA256 ||
		!stage2aBindingID.MatchString(policy.BridgeQualification.Model) ||
		!stage2aBindingID.MatchString(policy.BridgeQualification.HTTPHost) ||
		!stage2aPrefixedDigest.MatchString(policy.BridgeQualification.RequestSHA256) ||
		!stage2aPrefixedDigest.MatchString(policy.BridgeQualification.HeadersSHA256) ||
		!stage2aPrefixedDigest.MatchString(policy.BridgeQualification.ClientKeySHA256) ||
		!stage2aMessagesQuery.MatchString(policy.BridgeQualification.MessagesQuery) ||
		len(policy.BridgeQualification.ResponseText) == 0 ||
		len(policy.BridgeQualification.ResponseText) > 4096 ||
		!utf8.ValidString(policy.BridgeQualification.ResponseText) {
		return Plan{}, invalid
	}
	if _, err := time.Parse(time.RFC3339Nano, policy.ApprovedUntil); err != nil {
		return Plan{}, invalid
	}
	definitionDigest, _, err := Stage2aDefinitionDigest(policy.Definition)
	if err != nil || definitionDigest != policy.Binding.DefinitionMeasurement {
		return Plan{}, invalid
	}
	launchDigest, _, err := Stage2aLaunchInputDigest(policy.LaunchInputs)
	if err != nil || launchDigest != policy.Binding.LaunchInputMeasurement ||
		stage2aAdapterChildEnv(policy.LaunchInputs, &policy.BridgeQualification,
			policy.Binding.Snapshots.LaunchInputs.RootPath) != nil {
		return Plan{}, invalid
	}
	if err := ValidateSoulBridges([]SoulRunner{policy.Runner}, []SoulBridge{policy.Bridge}, policy.HQUID, nil); err != nil {
		return Plan{}, err
	}
	for _, role := range []struct {
		name     string
		uid, gid int
	}{
		{DarwinHQAccount, policy.HQUID, policy.HQUID},
		{policy.MachineAccount, policy.MachineUID, policy.MachineGID},
		{policy.Runner.Account, policy.Runner.UID, policy.Runner.GID},
		{policy.Bridge.Account, policy.Bridge.UID, policy.Bridge.GID},
	} {
		account, ok, err := h.Account(role.name)
		if err != nil || !ok || account.UID != role.uid || account.GID != role.gid {
			return Plan{}, invalid
		}
	}
	me, err := managerBytes()
	if err != nil {
		return Plan{}, err
	}
	launcherDigest := fmt.Sprintf("%x", sha256.Sum256(me))
	if policy.LauncherSHA256 != "" && policy.LauncherSHA256 != launcherDigest {
		return Plan{}, invalid
	}
	policy.LauncherSHA256 = launcherDigest
	r.Policy = mustStage2aJSON(policy)
	p := Plan{Version: PlanVersion, HQAccount: DarwinHQAccount, Dir: DarwinDir,
		Members: []string{policy.Bridge.Account, policy.Runner.Account}, Purpose: SoulProtectedLaunchInstallPurpose,
		SoulProtectedLaunch: &r,
		Steps: []Step{{Kind: "soul-protected-launch", Target: policy.Binding.InstallationID,
			Action: ActionWrite, Detail: "install exact pinned launcher, sandbox policies, Machine public key, per-Soul rule and A-owned authority; publish root applied receipt"}},
	}
	slices.Sort(p.Members)
	canonical, err := p.Canonical()
	if err != nil || len(canonical) > 48<<10 {
		return Plan{}, invalid
	}
	return p, nil
}

func CheckDarwinSoulProtectedLaunch(s Saved, owner string, uid int) error {
	invalid := errors.New("saved protected Soul launch plan is not the paired operation")
	if s.SoulProtectedLaunch == nil || s.Plan.Purpose != SoulProtectedLaunchInstallPurpose ||
		!ValidApproval(s.PlanID, s.PlanDigest) {
		return invalid
	}
	canonical, err := s.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != s.PlanDigest {
		return invalid
	}
	rebuilt, err := Build(Input{SoulProtectedLaunch: s.SoulProtectedLaunch, HQAccount: DarwinHQAccount,
		Dir: DarwinDir, Platform: PlatformDarwin, Invoker: owner}, OSHost{})
	if err != nil {
		return err
	}
	actual, err := rebuilt.Canonical()
	if err != nil || !bytes.Equal(actual, canonical) {
		return invalid
	}
	if len(s.Plan.Steps) != 1 || s.Plan.Steps[0].UID != 0 || uid < 300 || uid > 399 {
		return invalid
	}
	var policy stage2aInstalledPolicy
	if json.Unmarshal(s.SoulProtectedLaunch.Policy, &policy) != nil || policy.HQUID != uid {
		return invalid
	}
	return nil
}

func stage2aArtifactPath(installationID string) string {
	return filepath.Join(launchRuntimeDir, "soul-artifacts", soulEndpointInstallationSlot(installationID)+".soul")
}

func stage2aInstallSnapshotName(installationID, kind string) string {
	sum := sha256.Sum256([]byte("agent-bot-machine/stage2a-install-snapshot/v1\x00" + kind + "\x00" + installationID))
	return fmt.Sprintf("snap_%x", sum[:12])
}

func stage2aInstallSnapshotClaim(value Stage2aSnapshotIdentity, path string, uid, gid int) bool {
	return value.RootPath == path && value.OwnerUID == uint32(uid) &&
		value.OwnerGID == uint32(gid) && value.Mode == "0555" &&
		value.Device == "" && value.Inode == "" && value.Generation == "" &&
		value.BirthtimeNS == ""
}

func mustStage2aJSON(value any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}
