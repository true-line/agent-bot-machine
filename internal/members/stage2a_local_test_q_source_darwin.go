//go:build darwin

package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/qwts/managed-machine/internal/plan"
	"github.com/qwts/managed-machine/internal/statedir"
	"golang.org/x/sys/unix"
)

const stage2aLocalTestQPlanLimit = 8192

type stage2aLocalTestQSource struct {
	plan         stage2aLocalTestQPlan
	planRaw      []byte
	planDigest   string
	ownerPlanSHA string
	account      *user.User
	state        string
	stateLexical string
	uid, gid     uint32
	policy       stage2aInstalledPolicy
}

func stage2aLocalTestQPlanPath(state, planID string) (string, error) {
	if !stage2aAbsolutePath(state) || filepath.Clean(state) != state || !plan.ValidID(planID) {
		return "", errStage2aReservationAuthority
	}
	return filepath.Join(state, planID+".stage2a-local-test-q-plan.json"), nil
}

// Resolve A's own enrolled account. Neither the HQ request nor a root
// installer supplies a directory, owner, machine key, or pairing commitment.
func stage2aLocalTestQAccount() (*user.User, string, string, uint32, uint32, error) {
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 400 || gid == 0 || uid != os.Geteuid() || gid != os.Getegid() {
		return nil, "", "", 0, 0, errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || account.Username == "" || account.Gid != strconv.Itoa(gid) ||
		!stage2aAbsolutePath(account.HomeDir) {
		return nil, "", "", 0, 0, errStage2aReservationAuthority
	}
	physicalHome, err := filepath.EvalSymlinks(account.HomeDir)
	if err != nil || !stage2aAbsolutePath(physicalHome) {
		return nil, "", "", 0, 0, errStage2aReservationAuthority
	}
	state := filepath.Join(physicalHome, ".config", "agent-machine")
	lexical := filepath.Join(account.HomeDir, ".config", "agent-machine")
	return account, state, lexical, uint32(uid), uint32(gid), nil
}

func stage2aLocalTestQReadPlan(state, planID string, uid, gid uint32) (stage2aLocalTestQPlan, []byte, string, error) {
	path, err := stage2aLocalTestQPlanPath(state, planID)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(state, uid)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	defer dir.Close()
	if checkStage2aReservationFile(int(dir.Fd()), uid, gid, unix.S_IFDIR|0700) != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	raw, err := stage2aReadProtectedFileForUID(path, stage2aLocalTestQPlanLimit, uid, gid, 0600)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	q, digest, err := parseStage2aLocalTestQPlan(raw)
	if err != nil {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(q)
	if err != nil || !bytes.Equal(canonical, raw) {
		return stage2aLocalTestQPlan{}, nil, "", errStage2aReservationAuthority
	}
	return q, raw, digest, nil
}

func stage2aLocalTestQSavedInstall(home string, q stage2aLocalTestQPlan, uid, gid uint32) (Saved, error) {
	state, err := statedir.Path("darwin", func(key string) string {
		if key == "HOME" {
			return home
		}
		return ""
	})
	if err != nil {
		return Saved{}, errStage2aReservationAuthority
	}
	path := filepath.Join(state, "members", "plans", q.InstalledPlanID+".json")
	saved, err := readStage2aCandidateSavedPlanV3(path, uid, gid)
	if err != nil || saved.PlanID != q.InstalledPlanID || saved.PlanDigest != q.InstalledPlanDigest {
		return Saved{}, errStage2aReservationAuthority
	}
	canonical, err := saved.CanonicalForReview()
	digest := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(digest[:]) != saved.PlanDigest {
		return Saved{}, errStage2aReservationAuthority
	}
	return saved, nil
}

// This join is repeated at owner challenge and immediately before A's Q
// claim. The only variable input is the fixed A-private Q plan ID; installed
// release bytes are still unavailable before the root install and must be
// remeasured later by root and A.
func stage2aLocalTestQMatchesInstall(q stage2aLocalTestQPlan, planID, digest string,
	saved Saved, key ed25519.PublicKey, hqUID int, now time.Time,
	checkHost func(string) error) (stage2aInstalledPolicy, string, error) {
	var policy stage2aInstalledPolicy
	if checkHost == nil || len(key) != ed25519.PublicKeySize ||
		!ValidApproval(planID, digest) || saved.SoulProtectedLaunch == nil ||
		saved.PlanID != q.InstalledPlanID || saved.PlanDigest != q.InstalledPlanDigest ||
		saved.SoulProtectedLaunch.Schema != stage2aLocalTestInstallSchema ||
		saved.SoulProtectedLaunch.LocalTestQPlanID != planID ||
		saved.SoulProtectedLaunch.MachinePublicKey != hex.EncodeToString(key) ||
		q.AKeyID != stage2aReservationSHA256(key) || q.Purpose != stage2aLocalTestQPurpose ||
		q.Schema != stage2aLocalTestQSchema || q.HostUUID == "" ||
		hqUID < 300 || hqUID > 399 ||
		json.Unmarshal(saved.SoulProtectedLaunch.Policy, &policy) != nil ||
		policy.HQUID != hqUID || policy.Binding.InstallationID != q.InstallationID ||
		policy.LocalTestQPlanID != planID || policy.ObservedBodyLocalTestReceipt != nil {
		return stage2aInstalledPolicy{}, "", errStage2aReservationAuthority
	}
	until, err := time.Parse(time.RFC3339Nano, policy.ApprovedUntil)
	if err != nil || !now.Before(until) {
		return stage2aInstalledPolicy{}, "", errStage2aReservationAuthority
	}
	owner, ownerSHA, err := parseStage2aLocalTestOwnerPlan(policy.ObservedBodyLocalTest,
		policy.BridgeQualification, until)
	if err != nil || q.OwnerPlanSHA256 != ownerSHA || q.SourceRevision != owner.Revision ||
		q.CandidateManifestSHA256 != owner.Members[0].AdapterManifestSHA256 ||
		owner.RunnerHomeLexical != darwinSoulRunnerHome(policy.Runner.Account) ||
		policy.Runner.Account != soulRunnerName(q.InstallationID) {
		return stage2aInstalledPolicy{}, "", errStage2aReservationAuthority
	}
	qUntil, err := time.Parse(time.RFC3339Nano, q.ExpiresAt)
	ownerUntil, ownerErr := time.Parse(time.RFC3339Nano, owner.ExpiresAt)
	if err != nil || ownerErr != nil || !now.Before(qUntil) || qUntil.After(ownerUntil) ||
		checkHost(q.HostUUID) != nil {
		return stage2aInstalledPolicy{}, "", errStage2aReservationAuthority
	}
	return policy, ownerSHA, nil
}

func stage2aLoadLocalTestQSource(planID string, key ed25519.PublicKey, hqUID int,
	now time.Time) (stage2aLocalTestQSource, error) {
	var empty stage2aLocalTestQSource
	account, state, lexical, uid, gid, err := stage2aLocalTestQAccount()
	if err != nil {
		return empty, err
	}
	q, raw, digest, err := stage2aLocalTestQReadPlan(state, planID, uid, gid)
	if err != nil {
		return empty, err
	}
	saved, err := stage2aLocalTestQSavedInstall(account.HomeDir, q, uid, gid)
	if err != nil || CheckDarwinSoulProtectedLaunch(saved, account.Username, hqUID) != nil {
		return empty, errStage2aReservationAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	policy, ownerSHA, err := stage2aLocalTestQMatchesInstall(q, planID, digest[len("sha256:"):],
		saved, key, hqUID, now, func(uuid string) error {
			return observeStage2aQualificationHost(ctx, uuid)
		})
	if err != nil {
		return empty, err
	}
	driverSHA, err := stage2aLocalTestQReviewedDriverSHA(state, planID, uid, gid)
	if err != nil || driverSHA != q.DriverPlanSHA256 {
		return empty, errStage2aReservationAuthority
	}
	return stage2aLocalTestQSource{plan: q, planRaw: raw, planDigest: digest,
		ownerPlanSHA: ownerSHA, account: account, state: state, stateLexical: lexical,
		uid: uid, gid: gid, policy: policy}, nil
}

// The daemon uses this for the distinct paired owner challenge. It returns
// the exact canonical Q object shown to the owner; it cannot sign or admit a
// start. The caller's home and owner names must equal the enrolled A account.
func ReviewStage2aLocalTestQPlan(home, owner, planID, digest string, hqUID int,
	key ed25519.PublicKey) (string, error) {
	account, _, _, _, _, err := stage2aLocalTestQAccount()
	if err != nil || account.Username != owner || account.HomeDir != home {
		return "", errStage2aReservationAuthority
	}
	source, err := stage2aLoadLocalTestQSource(planID, key, hqUID, time.Now())
	if err != nil || source.planDigest != "sha256:"+digest {
		return "", errStage2aReservationAuthority
	}
	return string(source.planRaw), nil
}

func stage2aLocalTestQClaimStore(source stage2aLocalTestQSource) (stage2aAdminClaimStore, *os.File, error) {
	dir, err := openStage2aAdminDirectory(source.state, source.uid)
	if err != nil {
		return stage2aAdminClaimStore{}, nil, errStage2aReservationAuthority
	}
	var st unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 ||
		st.Uid != source.uid || st.Gid != source.gid {
		dir.Close()
		return stage2aAdminClaimStore{}, nil, errStage2aReservationAuthority
	}
	store := stage2aAdminClaimStore{path: source.state, uid: source.uid, gid: source.gid,
		device: st.Dev, inode: st.Ino, birthtime: st.Btim}
	if store.checkDirectory(dir) != nil {
		dir.Close()
		return stage2aAdminClaimStore{}, nil, errStage2aReservationAuthority
	}
	return store, dir, nil
}

// A's current service key signs only after reopening the Q and install
// sources under the current pair guard. No private key or root file path
// crosses the daemon request. The owner must separately stage the returned
// signed envelope at root's fixed 0400 path before root apply.
func (s *Stage2aService) issueLocalTestQApproval(hqUID int, epoch, planID string,
	checkPair func(string, string, string, func() error) error) (Stage2aLocalTestQApprovalReply, error) {
	var empty Stage2aLocalTestQApprovalReply
	if s == nil || checkPair == nil || len(s.key) != ed25519.PrivateKeySize ||
		hqUID < 300 || hqUID > 399 || epoch == "" || !plan.ValidID(planID) {
		return empty, errStage2aReservationAuthority
	}
	key := s.key.Public().(ed25519.PublicKey)
	source, err := stage2aLoadLocalTestQSource(planID, key, hqUID, time.Now())
	if err != nil || source.policy.Binding.HQEpoch != epoch {
		return empty, errStage2aReservationAuthority
	}
	approval, why := loadApproval(OSHost{}, source.stateLexical,
		source.account.Username, planID, PlatformDarwin, time.Now())
	if why != "" || approval.Purpose != stage2aLocalTestQPurpose ||
		approval.PlanDigest != source.planDigest[len("sha256:"):] ||
		approval.MachineFingerprint != fmt.Sprintf("%x", sha256.Sum256(key)) {
		return empty, errStage2aReservationAuthority
	}
	var envelope []byte
	err = checkPair(source.stateLexical, source.account.Username, approval.PairCommitment,
		func() error {
			current, err := stage2aLoadLocalTestQSource(planID, key, hqUID, time.Now())
			if err != nil || current.planDigest != source.planDigest ||
				!bytes.Equal(current.planRaw, source.planRaw) ||
				current.policy.Binding.HQEpoch != epoch || current.state != source.state {
				return errStage2aReservationAuthority
			}
			stored, why := loadApproval(OSHost{}, current.stateLexical,
				current.account.Username, planID, PlatformDarwin, time.Now())
			if why != "" || stored != approval {
				return errStage2aReservationAuthority
			}
			store, dir, err := stage2aLocalTestQClaimStore(current)
			if err != nil {
				return err
			}
			defer dir.Close()
			envelope, err = commitAndSignStage2aLocalTestQApproval(store, dir, current.plan,
				approval, current.plan.HostUUID, current.ownerPlanSHA,
				approval.MachineFingerprint, approval.PairCommitment, key,
				time.Now(), s.sign)
			return err
		})
	if err != nil || len(envelope) == 0 ||
		checkPair(source.stateLexical, source.account.Username, approval.PairCommitment, nil) != nil {
		return empty, errStage2aReservationAuthority
	}
	return Stage2aLocalTestQApprovalReply{
		PlanID: planID, PlanSHA256: source.planDigest,
		ApprovalEnvelopeBase64URL: stage2aEncodeEnvelope(envelope),
		ApprovalEnvelopeSHA256:    stage2aReservationSHA256(envelope),
	}, nil
}

type Stage2aLocalTestQApprovalReply struct {
	PlanID                    string `json:"plan_id"`
	PlanSHA256                string `json:"plan_sha256"`
	ApprovalEnvelopeBase64URL string `json:"approval_envelope_base64url"`
	ApprovalEnvelopeSHA256    string `json:"approval_envelope_sha256"`
}

// IssueLocalTestQApproval is available only on the production candidate
// service, after the distinct paired owner Q approval has been recorded.
func (s *Stage2aService) IssueLocalTestQApproval(hqUID int, epoch, planID string) (Stage2aLocalTestQApprovalReply, error) {
	if s == nil || s.localTestQPair == nil {
		return Stage2aLocalTestQApprovalReply{}, errStage2aReservationAuthority
	}
	return s.issueLocalTestQApproval(hqUID, epoch, planID, s.localTestQPair)
}
