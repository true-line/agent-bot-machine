//go:build darwin

package members

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// The root-installed Q plan is retained as an A-owned private file. A reads
// these exact bytes again before spending the owner's one-use qualification
// approval; neither the paired HQ selector nor the worker pipe supplies them.
func readStage2aCandidateSavedPlanV3(path string, uid, gid uint32) (Saved, error) {
	var empty Saved
	if uid < 400 || uid != uint32(os.Getuid()) || uid != uint32(os.Geteuid()) ||
		gid != uint32(os.Getgid()) || gid != uint32(os.Getegid()) ||
		!stage2aAbsolutePath(path) || checkDarwinACLs(pathAncestry(path)) != nil {
		return empty, errStage2aReservationAuthority
	}
	fd, err := unix.Open(path, stage2aFileOpenFlags, 0)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600) != nil ||
		checkDarwinACLs([]string{path}) != nil {
		return empty, errStage2aReservationAuthority
	}
	const limit = 4 << 20
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Size <= 0 || before.Size > limit {
		return empty, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil ||
		!stage2aSameNode(before, after) || stage2aStrictJSONBounded(raw, limit, 16384) != nil {
		return empty, errStage2aReservationAuthority
	}
	var saved Saved
	if stage2aDecodeExact(raw, &saved) != nil {
		return empty, errStage2aReservationAuthority
	}
	return saved, nil
}

func stage2aCandidateDesignatedHostCheckV3(install stage2aQualificationQInstall) func(QualificationRequest) error {
	return func(request QualificationRequest) error {
		if request.Candidate == nil || request.Host.ID != install.Review.HostID ||
			request.Candidate.HostUUID != install.Review.HostUUID {
			return errQualificationAdmissionUnavailable
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return observeStage2aQualificationHost(ctx, install.Review.HostUUID)
	}
}

func stage2aCandidateInstalledQCheckV3(install stage2aQualificationQInstall) func(QualificationRequest) error {
	return func(request QualificationRequest) error {
		q := request.Candidate
		if q == nil || q.InstallationID != install.Review.InstallationID ||
			q.InstalledPlanDigest != install.Review.InstalledPlanDigest || q.TestPlan != install.Review.TestPlan ||
			request.TestProvider.ConfigPath != install.Review.Provider.Path ||
			request.TestProvider.ConfigSHA != install.Review.Provider.SHA256 ||
			request.Runner.BinaryPath != install.Source.Path || request.Runner.BinarySHA != install.Source.SHA256 ||
			verifyQualificationFile(install.Review.TestPlan) != nil || verifyQualificationFile(install.Review.Provider) != nil ||
			checkStage2aQualificationQTrigger(install) != nil {
			return errQualificationAdmissionUnavailable
		}
		account, found, err := (OSHost{}).Account(stage2aQualificationQAccount)
		if err != nil || !found || account.UID != install.UID || account.GID != install.GID ||
			account.Home != stage2aQualificationQRoleHome || account.Shell != DarwinNoLoginShell {
			return errQualificationAdmissionUnavailable
		}
		loaded, err := stage2aQualificationQLaunchdLoaded()
		if err != nil || !loaded {
			return errQualificationAdmissionUnavailable
		}
		return nil
	}
}

func stage2aCandidateInstallMatchesRuntimeV3(install stage2aQualificationQInstall,
	runtime stage2aInstalledRuntimeV3) bool {
	hq, found, err := (OSHost{}).Account(DarwinHQAccount)
	return err == nil && found && stage2aCandidateInstallMatchesRuntimeWithHQV3(install, runtime, hq)
}

func stage2aCandidateInstallMatchesRuntimeWithHQV3(install stage2aQualificationQInstall,
	runtime stage2aInstalledRuntimeV3, hq Account) bool {
	p := runtime.Policy
	return hq.UID == p.HQUID && hq.GID == install.HQGID &&
		runtime.VerifiedR.verified && p.RuntimeV3 != nil &&
		install.AdminUID == p.MachineUID && install.AdminGID == p.MachineGID &&
		install.HQUID == p.HQUID &&
		install.RunnerGID == p.Runner.GID && install.BridgeGID == p.Bridge.GID &&
		install.Review.InstallationID == p.Binding.InstallationID &&
		install.Review.InstalledPlanDigest == p.Binding.InstalledPlanDigest &&
		install.Review.HostID == p.Binding.HostID
}

func loadStage2aCandidatePlanSourceV3(install stage2aQualificationQInstall,
	keyFingerprint string) (Saved, Approval, string, string, error) {
	var empty Saved
	var noApproval Approval
	if os.Getuid() != install.AdminUID || os.Geteuid() != install.AdminUID ||
		os.Getgid() != install.AdminGID || os.Getegid() != install.AdminGID ||
		!digestPattern.MatchString(keyFingerprint) || !install.Review.valid() {
		return empty, noApproval, "", "", errStage2aReservationAuthority
	}
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	if err != nil || account.Gid != strconv.Itoa(install.AdminGID) ||
		!stage2aAbsolutePath(account.HomeDir) || account.Username == "" {
		return empty, noApproval, "", "", errStage2aReservationAuthority
	}
	saved, err := readStage2aCandidateSavedPlanV3(filepath.Join(stage2aQualificationQHome, "saved-plan.json"),
		uint32(install.AdminUID), uint32(install.AdminGID))
	if err != nil || saved.PlanID != install.Review.PlanID || saved.PlanDigest != install.Review.PlanDigest ||
		saved.QualificationRun == nil || saved.QualificationRun.Request.Candidate == nil {
		return empty, noApproval, "", "", errStage2aReservationAuthority
	}
	canonical, err := saved.CanonicalForReview()
	sum := sha256.Sum256(canonical)
	if err != nil || hex.EncodeToString(sum[:]) != saved.PlanDigest {
		return empty, noApproval, "", "", errStage2aReservationAuthority
	}
	state := filepath.Join(account.HomeDir, ".config", "agent-machine")
	approval, why := loadApproval(OSHost{}, state, account.Username, saved.PlanID, PlatformDarwin, time.Now())
	if why != "" || approval.PlanDigest != saved.PlanDigest || approval.Purpose != HarnessQualificationPurpose ||
		approval.MachineFingerprint != keyFingerprint || !digestPattern.MatchString(approval.PairCommitment) {
		return empty, noApproval, "", "", errStage2aReservationAuthority
	}
	return saved, approval, install.Review.Owner, state, nil
}
