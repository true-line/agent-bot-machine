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
	"os"
	"path/filepath"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/qwts/managed-machine/internal/cli"
	"github.com/qwts/managed-machine/internal/command"
	"github.com/qwts/managed-machine/internal/diag"
	"github.com/qwts/managed-machine/internal/output"
	"github.com/qwts/managed-machine/internal/plan"
	"github.com/qwts/managed-machine/internal/statedir"
	"golang.org/x/sys/unix"
)

func stage2aLocalTestQCLIDarwin(ctx cli.Context) *diag.Diagnostic {
	host, dg := command.DetectHost(ctx)
	if dg != nil {
		return dg
	}
	if platform, ok := platformOf(string(host.Target)); !ok || platform != PlatformDarwin {
		return failure(diag.MembersUnsupported, "local-test Q preparation requires macOS").Diagnostic
	}
	return nil
}

func stage2aLocalTestQCLIPlan(saved Saved, hostUUID, driverSHA string,
	key ed25519.PublicKey, now time.Time) (stage2aLocalTestQPlan, []byte, string, error) {
	var policy stage2aInstalledPolicy
	if saved.SoulProtectedLaunch == nil ||
		saved.SoulProtectedLaunch.Schema != stage2aLocalTestInstallSchema ||
		!plan.ValidID(saved.SoulProtectedLaunch.LocalTestQPlanID) ||
		json.Unmarshal(saved.SoulProtectedLaunch.Policy, &policy) != nil ||
		policy.LocalTestQPlanID != saved.SoulProtectedLaunch.LocalTestQPlanID ||
		policy.Binding.InstallationID == "" || len(key) != ed25519.PublicKeySize {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	until, err := time.Parse(time.RFC3339Nano, policy.ApprovedUntil)
	if err != nil || !now.Before(until) {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	owner, ownerSHA, err := parseStage2aLocalTestOwnerPlan(
		policy.ObservedBodyLocalTest, policy.BridgeQualification, until)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	q := stage2aLocalTestQPlan{Schema: stage2aLocalTestQSchema,
		Purpose: stage2aLocalTestQPurpose, HostUUID: hostUUID,
		InstallationID:  policy.Binding.InstallationID,
		InstalledPlanID: saved.PlanID, InstalledPlanDigest: saved.PlanDigest,
		OwnerPlanSHA256: ownerSHA, SourceRevision: owner.Revision,
		CandidateManifestSHA256: owner.Members[0].AdapterManifestSHA256,
		DriverPlanSHA256:        driverSHA, AKeyID: stage2aReservationSHA256(key),
		ExpiresAt: owner.ExpiresAt}
	raw, err := marshalStage2aReservationJCS(q)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	parsed, digest, err := parseStage2aLocalTestQPlan(raw)
	if err != nil || parsed != q {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	return q, raw, digest, nil
}

func stage2aLocalTestQWriteOrCheck(dir *os.File, name string, raw []byte, uid, gid uint32) error {
	path := filepath.Join(dir.Name(), name)
	if err := stage2aRuntimeWriteFile(dir, name, raw, 0600, uid, gid); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	actual, err := stage2aReadProtectedFileForUID(path, int64(len(raw)), uid, gid, 0600)
	if err != nil || !bytes.Equal(actual, raw) {
		return errStage2aReservationAuthority
	}
	return dir.Sync()
}

// The owner-reviewed install fixes the Machine key before root publishes the
// Soul pin. An existing pin is an additional constraint, never a source for
// replacing that reviewed key. Root staging also checks the separate paired
// install approval's fingerprint before accepting a Q envelope.
func stage2aLocalTestQReviewedMachineKey(request *SoulProtectedLaunchInstall,
	fingerprint, pinPath string, uid, gid uint32) (ed25519.PublicKey, error) {
	if request == nil {
		return nil, errStage2aReservationAuthority
	}
	key, err := hex.DecodeString(request.MachinePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize ||
		hex.EncodeToString(key) != request.MachinePublicKey ||
		(fingerprint != "" && fmt.Sprintf("%x", sha256.Sum256(key)) != fingerprint) {
		return nil, errStage2aReservationAuthority
	}
	if _, err := os.Lstat(pinPath); errors.Is(err, os.ErrNotExist) {
		return ed25519.PublicKey(key), nil
	} else if err != nil {
		return nil, errStage2aReservationAuthority
	}
	pin, err := stage2aReadProtectedFileForUID(pinPath, ed25519.PublicKeySize, uid, gid, 0444)
	if err != nil || !bytes.Equal(pin, key) {
		return nil, errStage2aReservationAuthority
	}
	return ed25519.PublicKey(key), nil
}

// local-test-q-plan runs only as A. The saved install plan already fixes the Q
// ID, owner plan and candidate; the CLI derives those fields, never accepts
// them from HQ or the caller's driver file.
func runStage2aLocalTestQPlan(_ Deps, ctx cli.Context, args []string) cli.Result {
	if len(args) != 3 || !plan.ValidID(args[0]) || !qualificationPhysicalUUID.MatchString(args[1]) {
		return cli.Result{Diagnostic: command.UsageErr("local-test-q-plan takes an install plan ID, physical host UUID, and pinned driver plan file")}
	}
	if dg := stage2aLocalTestQCLIDarwin(ctx); dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	account, state, _, uid, gid, err := stage2aLocalTestQAccount()
	if err != nil {
		return failure(diag.MembersAccountRefused, "local-test Q plan requires the enrolled A account")
	}
	ownerState, err := statedir.Path("darwin", func(k string) string {
		if k == "HOME" {
			return account.HomeDir
		}
		return ""
	})
	if err != nil {
		return failure(diag.MembersPlanFailed, "A's install plan state is unavailable")
	}
	savedPath := filepath.Join(ownerState, "members", "plans", args[0]+".json")
	saved, err := readStage2aCandidateSavedPlanV3(savedPath, uid, gid)
	var policy stage2aInstalledPolicy
	savedReview, reviewErr := saved.CanonicalForReview()
	if err != nil || saved.PlanID != args[0] || saved.SoulProtectedLaunch == nil ||
		reviewErr != nil || fmt.Sprintf("%x", sha256.Sum256(savedReview)) != saved.PlanDigest ||
		json.Unmarshal(saved.SoulProtectedLaunch.Policy, &policy) != nil ||
		CheckDarwinSoulProtectedLaunch(saved, account.Username, policy.HQUID) != nil {
		return failure(diag.MembersPlanFailed, "saved local-test install plan is unavailable or changed")
	}
	driverRaw, err := readQualificationInput(args[2])
	if err != nil || len(driverRaw) > stage2aLocalTestQDriverPlanLimit ||
		stage2aStrictJSONBounded(driverRaw, stage2aLocalTestQDriverPlanLimit, 4096) != nil {
		return failure(diag.MembersListInvalid, "pinned Q driver plan is unavailable or invalid")
	}
	var driver stage2aLocalTestQDriverPlan
	canonical, err := jsoncanonicalizer.Transform(driverRaw)
	if err != nil || !bytes.Equal(canonical, driverRaw) ||
		stage2aDecodeExact(driverRaw, &driver) != nil || !driver.pinned() {
		return failure(diag.MembersListInvalid, "Q driver plan must be canonical and pin Contracts v0.10.3")
	}
	key, err := stage2aLocalTestQReviewedMachineKey(saved.SoulProtectedLaunch,
		"", SoulAuthorityPin, 0, 0)
	if err != nil {
		return failure(diag.MembersPlanFailed, "reviewed Machine key or existing root pin is invalid")
	}
	q, qRaw, digest, err := stage2aLocalTestQCLIPlan(saved, args[1],
		stage2aReservationSHA256(driverRaw), ed25519.PublicKey(key), time.Now())
	if err != nil {
		return failure(diag.MembersPlanFailed, "cannot derive exact local-test Q plan: %v", err)
	}
	if stage2aLocalTestQMatchesInstallForCLI(q, digest, saved, policy, key) != nil {
		return failure(diag.MembersPlanFailed, "Q plan differs from reviewed installation or physical host")
	}
	dir, err := openStage2aAdminDirectory(state, uid)
	if err != nil {
		return failure(diag.MembersPlanFailed, "A-private Q state is unavailable")
	}
	defer dir.Close()
	driverPath, _ := stage2aLocalTestQDriverPlanPath(state, saved.SoulProtectedLaunch.LocalTestQPlanID)
	qPath, _ := stage2aLocalTestQPlanPath(state, saved.SoulProtectedLaunch.LocalTestQPlanID)
	if stage2aLocalTestQWriteOrCheck(dir, filepath.Base(driverPath), driverRaw, uid, gid) != nil ||
		stage2aLocalTestQWriteOrCheck(dir, filepath.Base(qPath), qRaw, uid, gid) != nil {
		return failure(diag.MembersPlanFailed, "A-private Q source is occupied or could not be sealed")
	}
	if source, err := stage2aLoadLocalTestQSource(saved.SoulProtectedLaunch.LocalTestQPlanID,
		ed25519.PublicKey(key), policy.HQUID, time.Now()); err != nil || source.planDigest != digest {
		return failure(diag.MembersPlanFailed, "sealed A-private Q source failed readback")
	}
	return cli.Result{Records: []*output.Record{output.New().Set("plan_id", saved.SoulProtectedLaunch.LocalTestQPlanID).
		Set("plan_sha256", digest).Set("plan_path", qPath).Set("driver_plan_sha256", q.DriverPlanSHA256).
		Set("installed_plan_id", saved.PlanID).Set("installed_plan_digest", saved.PlanDigest).
		Set("approval_purpose", stage2aLocalTestQPurpose).Set("approved", false)}}
}

func stage2aLocalTestQMatchesInstallForCLI(q stage2aLocalTestQPlan, digest string, saved Saved,
	policy stage2aInstalledPolicy, key []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := stage2aLocalTestQMatchesInstall(q, saved.SoulProtectedLaunch.LocalTestQPlanID,
		digest[len("sha256:"):], saved, ed25519.PublicKey(key), policy.HQUID,
		time.Now(), func(hostUUID string) error { return observeStage2aQualificationHost(ctx, hostUUID) })
	return err
}

func stage2aLocalTestQCLIReply(raw []byte, expectedPlanID string) (Stage2aLocalTestQApprovalReply, []byte, error) {
	var reply Stage2aLocalTestQApprovalReply
	if len(raw) == 0 || len(raw) > 16<<10 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &reply) != nil || reply.PlanID != expectedPlanID ||
		!stage2aPrefixedDigest.MatchString(reply.PlanSHA256) ||
		!stage2aPrefixedDigest.MatchString(reply.ApprovalEnvelopeSHA256) {
		return reply, nil, errStage2aReservationAuthority
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(reply.ApprovalEnvelopeBase64URL)
	if err != nil || len(envelope) == 0 || len(envelope) > stage2aV3EnvelopeLimit ||
		base64.RawURLEncoding.EncodeToString(envelope) != reply.ApprovalEnvelopeBase64URL ||
		stage2aReservationSHA256(envelope) != reply.ApprovalEnvelopeSHA256 {
		return reply, nil, errStage2aReservationAuthority
	}
	return reply, envelope, nil
}

// local-test-q-stage is an inert root staging step. The normal paired root
// apply reopens this fixed file, spends the distinct Q, and validates the
// measured installed runtime before publishing Provider access.
func runStage2aLocalTestQStage(deps Deps, ctx cli.Context, args []string) cli.Result {
	if len(args) != 2 || !plan.ValidID(args[0]) {
		return cli.Result{Diagnostic: command.UsageErr("local-test-q-stage takes an install plan ID and exact Q issue reply file")}
	}
	if dg := stage2aLocalTestQCLIDarwin(ctx); dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	owner, home, dg := membersSudoOwner(deps, "local-test-q-stage "+args[0])
	if dg != nil {
		return cli.Result{Diagnostic: dg}
	}
	state, err := statedir.Path("darwin", func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return failure(diag.MembersPlanFailed, "owner plan state is unavailable")
	}
	savedRaw, err := readQualificationInput(filepath.Join(state, "members", "plans", args[0]+".json"))
	var saved Saved
	if err != nil || stage2aDecodeExact(savedRaw, &saved) != nil || saved.PlanID != args[0] ||
		saved.SoulProtectedLaunch == nil || saved.SoulProtectedLaunch.Schema != stage2aLocalTestInstallSchema {
		return failure(diag.MembersPlanFailed, "reviewed local-test install plan is unavailable")
	}
	canonical, err := saved.CanonicalForReview()
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(canonical)) != saved.PlanDigest {
		return failure(diag.MembersPlanFailed, "saved install plan digest changed")
	}
	var policy stage2aInstalledPolicy
	if json.Unmarshal(saved.SoulProtectedLaunch.Policy, &policy) != nil ||
		CheckDarwinSoulProtectedLaunch(saved, owner, policy.HQUID) != nil {
		return failure(diag.MembersPlanFailed, "saved install policy changed")
	}
	if deps.DaemonState == nil || deps.CheckUpgradePair == nil {
		return failure(diag.MembersNotApproved, "current paired Machine guard is unavailable")
	}
	daemonDir, daemonAccount, err := deps.DaemonState(owner, home)
	if err != nil || daemonDir == "" || daemonAccount == "" {
		return failure(diag.MembersNotApproved, "paired Machine state is unavailable")
	}
	approval, why := loadApproval(OSHost{}, daemonDir, daemonAccount, saved.PlanID, PlatformDarwin, time.Now())
	if why != "" || approval.Purpose != SoulProtectedLaunchInstallPurpose ||
		approval.PlanDigest != saved.PlanDigest {
		return failure(diag.MembersNotApproved, "exact paired install approval is unavailable")
	}
	key, err := stage2aLocalTestQReviewedMachineKey(saved.SoulProtectedLaunch,
		approval.MachineFingerprint, SoulAuthorityPin, 0, 0)
	if err != nil {
		return failure(diag.MembersNotApproved, "Machine key differs from reviewed owner approval")
	}
	replyRaw, err := readQualificationInput(args[1])
	if err != nil {
		return failure(diag.MembersListInvalid, "Q issue reply is invalid or targets another plan")
	}
	reply, envelope, err := stage2aLocalTestQCLIReply(replyRaw, saved.SoulProtectedLaunch.LocalTestQPlanID)
	if err != nil {
		return failure(diag.MembersListInvalid, "Q issue envelope digest or encoding differs")
	}
	until, err := time.Parse(time.RFC3339Nano, policy.ApprovedUntil)
	if err != nil {
		return failure(diag.MembersPlanFailed, "install approval interval is invalid")
	}
	ownerPlan, ownerSHA, err := parseStage2aLocalTestOwnerPlan(
		policy.ObservedBodyLocalTest, policy.BridgeQualification, until)
	if err != nil {
		return failure(diag.MembersPlanFailed, "owner local-test plan changed")
	}
	q, ref, err := stage2aLocalTestQApprovalForInstall(envelope, ed25519.PublicKey(key),
		saved.PlanID, saved.PlanDigest, reply.PlanID, policy.Binding.InstallationID,
		ownerSHA, ownerPlan.Revision, ownerPlan.Members[0].AdapterManifestSHA256,
		approval.MachineFingerprint, approval.PairCommitment, time.Now())
	qRaw, _ := marshalStage2aReservationJCS(q)
	if err != nil || stage2aReservationSHA256(qRaw) != reply.PlanSHA256 ||
		ref.PlanID != reply.PlanID {
		return failure(diag.MembersNotApproved, "signed Q approval does not match the owner plan")
	}
	if deps.CheckUpgradePair(daemonDir, daemonAccount, approval.PairCommitment, nil) != nil {
		return failure(diag.MembersNotApproved, "paired Machine guard changed")
	}
	rootPath, err := stage2aLocalTestQRootEnvelopePathForPlan(reply.PlanID)
	if err != nil || stage2aInstallRootFile(rootPath, envelope, 0400) != nil {
		return failure(diag.MembersApplyFailed, "fixed root Q approval path is occupied or unavailable")
	}
	return cli.Result{Records: []*output.Record{output.New().Set("installed_plan_id", saved.PlanID).
		Set("installed_plan_digest", saved.PlanDigest).Set("q_plan_id", reply.PlanID).
		Set("q_plan_sha256", reply.PlanSHA256).Set("q_envelope_sha256", reply.ApprovalEnvelopeSHA256).
		Set("root_path", rootPath).Set("staged", true).Set("applied", false)}}
}
