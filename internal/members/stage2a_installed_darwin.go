//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aAuthorityDirectory = launchRuntimeDir + "/stage2a-authorities"
const stage2aLaunchInstallPurpose = "soul-protected-launch-install"

func stage2aAuthorityPath(installationID string) (string, error) {
	if !soulInstallationID.MatchString(installationID) {
		return "", errStage2aReservationAuthority
	}
	return filepath.Join(stage2aAuthorityDirectory, soulEndpointInstallationSlot(installationID)+".json"), nil
}

type stage2aInstalledDirectory struct {
	Path             string `json:"path"`
	Device           int32  `json:"device"`
	Inode            string `json:"inode"`
	BirthSeconds     int64  `json:"birth_seconds"`
	BirthNanoseconds int64  `json:"birth_nanoseconds"`
}

type stage2aInstalledPolicy struct {
	Schema              string                     `json:"schema"`
	MachineAccount      string                     `json:"machine_account"`
	MachineUID          int                        `json:"machine_uid"`
	MachineGID          int                        `json:"machine_gid"`
	PlanOwner           string                     `json:"plan_owner"`
	HQUID               int                        `json:"hq_uid"`
	ApprovedUntil       string                     `json:"approved_until"`
	Plan                json.RawMessage            `json:"canonical_plan"`
	Receipt             json.RawMessage            `json:"root_receipt"`
	Claims              stage2aInstalledDirectory  `json:"claims"`
	SnapshotNamespace   stage2aInstalledDirectory  `json:"snapshot_namespace"`
	RelayParent         stage2aInstalledDirectory  `json:"relay_parent"`
	LegacySpent         []string                   `json:"legacy_spent_start_ids"`
	LauncherSHA256      string                     `json:"launcher_sha256"`
	ArtifactPath        string                     `json:"artifact_path"`
	Runner              SoulRunner                 `json:"runner"`
	Bridge              SoulBridge                 `json:"bridge"`
	Binding             Stage2aMeasurementBinding  `json:"measurement_binding"`
	Definition          []Stage2aDefinitionRecord  `json:"definition"`
	LaunchInputs        Stage2aLaunchInputRecords  `json:"launch_inputs"`
	Node                string                     `json:"node"`
	Entry               string                     `json:"entry"`
	BridgeExecutable    HarnessArtifact            `json:"bridge_executable"`
	BridgeQualification Stage2aBridgeQualification `json:"bridge_qualification"`
}

func stage2aReadRootFile(path string, maximum int64, modes ...uint16) ([]byte, error) {
	dir, err := openStage2aAdminDirectory(filepath.Dir(path), 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || !slices.Contains(modes, st.Mode&07777) ||
		st.Size <= 0 || st.Size > maximum || checkDarwinACLs([]string{path}) != nil {
		return nil, errStage2aReservationAuthority
	}
	body, err := io.ReadAll(io.LimitReader(f, maximum+1))
	var after unix.Stat_t
	if err != nil || int64(len(body)) != st.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
		return nil, errStage2aReservationAuthority
	}
	return body, nil
}

func stage2aReadAdminPolicy(path string, maximum int64) ([]byte, error) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if uid <= 399 || uid != uint32(os.Geteuid()) || gid == 0 || gid != uint32(os.Getegid()) ||
		filepath.Dir(path) != stage2aAuthorityDirectory {
		return nil, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(stage2aAuthorityDirectory, uid)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var parent unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &parent) != nil || parent.Mode != unix.S_IFDIR|0700 ||
		parent.Uid != uid || parent.Gid != gid {
		return nil, errStage2aReservationAuthority
	}
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(path), stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0400 ||
		st.Uid != uid || st.Gid != gid || st.Nlink != 1 || st.Size <= 0 || st.Size > maximum ||
		checkDarwinACLs([]string{path}) != nil {
		return nil, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	var after unix.Stat_t
	if err != nil || int64(len(raw)) != st.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}

func (d stage2aInstalledDirectory) identity() (uint64, unix.Timespec) {
	inode, _ := strconv.ParseUint(d.Inode, 10, 64)
	return inode, unix.Timespec{Sec: d.BirthSeconds, Nsec: d.BirthNanoseconds}
}

func loadStage2aInstalledPolicy(key ed25519.PublicKey, hqUID int, epoch, installationID string) (stage2aInstalledPolicy, []byte, error) {
	return loadStage2aInstalledPolicyWithLease(key, hqUID, epoch, installationID, true)
}

// Stop must remain available after launch approval expires. Every custody,
// pairing, installed receipt, and policy check still applies to this path.
func loadStage2aInstalledPolicyForStop(key ed25519.PublicKey, hqUID int, epoch, installationID string) (stage2aInstalledPolicy, []byte, error) {
	return loadStage2aInstalledPolicyWithLease(key, hqUID, epoch, installationID, false)
}

func loadStage2aInstalledPolicyWithLease(key ed25519.PublicKey, hqUID int, epoch, installationID string, requireLiveLease bool) (stage2aInstalledPolicy, []byte, error) {
	var p stage2aInstalledPolicy
	path, err := stage2aAuthorityPath(installationID)
	if err != nil {
		return p, nil, err
	}
	pin, err := stage2aReadRootFile(SoulAuthorityPin, ed25519.PublicKeySize, 0444)
	if err != nil || !bytes.Equal(key, pin) {
		return p, nil, errStage2aReservationAuthority
	}
	raw, err := stage2aReadAdminPolicy(path, 1<<20)
	if err != nil || stage2aStrictJSON(raw) != nil {
		return p, nil, errStage2aReservationAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil || p.Schema != "agent-bot-machine/stage2a-installed-authority/v1" ||
		p.HQUID != hqUID || p.Binding.HQEpoch != epoch || p.Binding.InstallationID != installationID ||
		p.Binding.StartID != "" || p.Binding.LaunchID != "" ||
		p.MachineUID != os.Getuid() || p.MachineUID != os.Geteuid() || p.MachineUID <= 399 ||
		p.MachineGID != os.Getgid() || p.MachineGID != os.Getegid() || p.MachineGID <= 0 ||
		p.Binding.ProfileInForce != "managed-protected" ||
		p.LegacySpent == nil || !ValidApproval(p.Binding.PlanID, p.Binding.InstalledPlanDigest) {
		return p, nil, errStage2aReservationAuthority
	}
	var approvedPlan Plan
	planDecoder := json.NewDecoder(bytes.NewReader(p.Plan))
	planDecoder.DisallowUnknownFields()
	if stage2aStrictJSON(p.Plan) != nil || planDecoder.Decode(&approvedPlan) != nil ||
		approvedPlan.Purpose != stage2aLaunchInstallPurpose || approvedPlan.HQAccount != DarwinHQAccount ||
		approvedPlan.Dir != DarwinDir {
		return p, nil, errStage2aReservationAuthority
	}
	canonicalPlan, err := approvedPlan.Canonical()
	if err != nil || !bytes.Equal(p.Plan, bytes.TrimSuffix(canonicalPlan, []byte{'\n'})) ||
		p.Binding.InstalledPlanDigest != strings.TrimPrefix(stage2aReservationSHA256(canonicalPlan), "sha256:") ||
		!stage2aInstalledPolicyMatchesPlan(p, approvedPlan, key) {
		return p, nil, errStage2aReservationAuthority
	}
	expiry, err := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	if err != nil || (requireLiveLease && !expiry.After(time.Now())) {
		return p, nil, errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(p.MachineUID))
	if err != nil || account.Username != p.MachineAccount || account.Gid != strconv.Itoa(p.MachineGID) {
		return p, nil, errStage2aReservationAuthority
	}
	var receipt Receipt
	if json.Unmarshal(p.Receipt, &receipt) != nil || receipt.Result != "applied" || receipt.StartedAt == "" || receipt.FinishedAt == "" ||
		receipt.PlanID != p.Binding.PlanID || receipt.PlanDigest != p.Binding.InstalledPlanDigest ||
		receipt.Owner != p.PlanOwner || receipt.HQAccount != DarwinHQAccount {
		return p, nil, errStage2aReservationAuthority
	}
	// A may store a copy of the applied receipt for the signed reservation,
	// but cannot make that copy authoritative. Reopen the actual root-held
	// applied receipt and compare its exact bytes on every use.
	receiptPath := filepath.Join("/private"+DarwinReceiptsDir, p.Binding.PlanID+".json")
	installedReceipt, err := stage2aReadRootFile(receiptPath, 256<<10, 0644)
	if err != nil || !bytes.Equal(installedReceipt, p.Receipt) {
		return p, nil, errStage2aReservationAuthority
	}
	if p.Runner.Account != soulRunnerName(p.Binding.InstallationID) || p.Bridge.Account != SoulBridgeName(p.Binding.InstallationID) ||
		p.Runner.InstallationID != p.Binding.InstallationID || p.Bridge.InstallationID != p.Binding.InstallationID ||
		p.Runner.SoulID != p.Binding.SoulID || p.Bridge.SoulID != p.Binding.SoulID ||
		!soulDigest.MatchString(p.LauncherSHA256) || verifyHarnessExecutable(SoulLauncher, p.LauncherSHA256) != nil {
		return p, nil, errStage2aReservationAuthority
	}
	for _, role := range []struct {
		account  string
		uid, gid int
	}{
		{p.Runner.Account, p.Runner.UID, p.Runner.GID}, {p.Bridge.Account, p.Bridge.UID, p.Bridge.GID},
	} {
		u, err := user.Lookup(role.account)
		if err != nil || u.Uid != strconv.Itoa(role.uid) || u.Gid != strconv.Itoa(role.gid) {
			return p, nil, errStage2aReservationAuthority
		}
	}
	if p.verifyRunnerGroup() != nil {
		return p, nil, errStage2aReservationAuthority
	}
	return p, raw, nil
}

func (p stage2aInstalledPolicy) verifyRunnerGroup() error {
	return verifyStage2aInstalledGroup(p.Runner.Account, p.Runner.GID,
		p.MachineAccount, p.MachineUID, p.Runner.Account, p.Runner.UID)
}

// A's runtime file is compared to the exact owner-reviewed template after
// removing only fields produced by the paired installer. A cannot make an
// unrelated root receipt appear to approve changed launch bytes or roles.
func stage2aInstalledPolicyMatchesPlan(p stage2aInstalledPolicy, approved Plan, pub ed25519.PublicKey) bool {
	r := approved.SoulProtectedLaunch
	if r == nil || r.Schema != stage2aInstallSchema ||
		p.Binding.PlanID == "" || p.Binding.InstalledPlanDigest == "" ||
		p.ArtifactPath != stage2aArtifactPath(p.Binding.InstallationID) {
		return false
	}
	key, err := hex.DecodeString(r.MachinePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || !bytes.Equal(key, pub) {
		return false
	}
	template := p
	template.Plan, template.Receipt = nil, nil
	template.Claims, template.SnapshotNamespace = stage2aInstalledDirectory{}, stage2aInstalledDirectory{}
	template.RelayParent = stage2aInstalledDirectory{}
	template.Binding.PlanID, template.Binding.InstalledPlanDigest = "", ""
	for _, s := range []*Stage2aSnapshotIdentity{&template.Binding.Snapshots.Definition, &template.Binding.Snapshots.LaunchInputs} {
		s.Device, s.Inode, s.Generation, s.BirthtimeNS = "", "", "", ""
	}
	actual, err := json.Marshal(template)
	if err != nil || stage2aStrictJSON(actual) != nil || stage2aStrictJSON(r.Policy) != nil {
		return false
	}
	var expected any
	var observed any
	return json.Unmarshal(r.Policy, &expected) == nil && json.Unmarshal(actual, &observed) == nil &&
		reflect.DeepEqual(expected, observed)
}

func (p stage2aInstalledPolicy) stores() (stage2aAdminClaimStore, stage2aAdminSnapshots) {
	claimInode, claimBirth := p.Claims.identity()
	snapshotInode, snapshotBirth := p.SnapshotNamespace.identity()
	return stage2aAdminClaimStore{
		path: p.Claims.Path, uid: uint32(p.MachineUID), gid: uint32(p.MachineGID), device: p.Claims.Device, inode: claimInode, birthtime: claimBirth,
		legacyUnspent: func(installationID, startID string) error {
			if installationID != p.Binding.InstallationID || slices.Contains(p.LegacySpent, startID) {
				return errStage2aReservationSpent
			}
			for _, spent := range p.LegacySpent {
				if !soulStartID.MatchString(spent) {
					return errStage2aReservationAuthority
				}
			}
			return nil
		},
	}, stage2aAdminSnapshots{
		namespace: p.SnapshotNamespace.Path, uid: uint32(p.MachineUID), runnerReadGID: uint32(p.Runner.GID),
		namespaceDev: p.SnapshotNamespace.Device, namespaceInode: snapshotInode, namespaceBirth: snapshotBirth,
		verifyInstalledGroup: p.verifyRunnerGroup,
	}
}

func (p stage2aInstalledPolicy) inputs(req stage2aReservationRequest, a stage2aAdminSnapshots, key ed25519.PublicKey) (stage2aReservationInputs, error) {
	var in stage2aReservationInputs
	b := p.Binding
	if b.InstallationID != req.start.InstallationID || b.InstalledPlanDigest != req.start.PlanDigest || b.HQEpoch != req.start.HQEpoch {
		return in, errStage2aReservationAuthority
	}
	b.StartID, b.LaunchID = req.start.StartID, req.launchID
	artifact, err := stage2aReadRootFile(p.ArtifactPath, stage2aMaxFileBytes, 0444, 0644)
	if err != nil || stage2aReservationSHA256(artifact) != "sha256:"+b.SoulArtifactSHA256 {
		return in, errStage2aReservationAuthority
	}
	definition, err := observeStage2aAdminSnapshot(a, filepath.Base(b.Snapshots.Definition.RootPath), b.Snapshots.Definition, p.Definition)
	if err != nil || definition != b.DefinitionMeasurement ||
		stage2aCheckFrozenSoulClaim(b.Snapshots.Definition, p.Definition, b.SoulID, b.ClaimedDefinitionDigest) != nil {
		return in, errStage2aReservationAuthority
	}
	if err := observeInstalledStage2aLaunchInputs(a, b, p.LaunchInputs); err != nil {
		return in, err
	}
	_, err = DeriveSoulBridgeEndpoints(p.Runner, p.Bridge, p.HQUID, req.start.StartID)
	if err != nil {
		return in, err
	}
	// A cannot traverse the H:R and R:B socket directories. The endpoint
	// owners enforce vacancy with exclusive bind and the role handshake.
	approvedUntil, _ := time.Parse(time.RFC3339Nano, p.ApprovedUntil)
	in = stage2aReservationInputs{
		hostID: b.HostID, planID: b.PlanID, installedPlan: p.Plan, installedReceipt: p.Receipt,
		runner: p.Runner, bridge: p.Bridge, hqUID: p.HQUID, machineUID: p.MachineUID, enrolledAdminKey: key,
		expires: minStage2aTime(approvedUntil, time.Now().Add(30*time.Second)), binding: b,
		approvedArtifact: stage2aSoulArtifactSHA256(b.SoulArtifactSHA256), installedArtifact: stage2aSoulArtifactSHA256(b.SoulArtifactSHA256),
	}
	if _, err := rand.Read(in.admissionChallenge[:]); err != nil {
		return stage2aReservationInputs{}, err
	}
	return in, nil
}

func minStage2aTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func stage2aEncodeEnvelope(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
