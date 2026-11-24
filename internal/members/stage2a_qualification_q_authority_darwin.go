package members

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const stage2aQualificationQPlanPath = stage2aQualificationQHome + "/saved-plan.json"

// The root-installed descriptor commits the canonical owner-reviewed plan.
// A reads the retained copy through the fixed root-owned directory.
func loadStage2aQualificationQAuthority(ctx context.Context) (stage2aQualificationQInstall, QualificationRequest, error) {
	var empty QualificationRequest
	install, err := loadStage2aQualificationQInstall()
	if err != nil || os.Getuid() != os.Geteuid() || os.Geteuid() != install.AdminUID ||
		os.Getgid() != os.Getegid() || os.Getegid() != install.AdminGID {
		return install, empty, errQualificationAdmissionUnavailable
	}
	dir, err := openStage2aAdminDirectory(stage2aQualificationQHome, 0)
	if err != nil {
		return install, empty, errQualificationAdmissionUnavailable
	}
	defer dir.Close()
	const planLimit = 4 << 20
	fd, err := unix.Openat(int(dir.Fd()), "saved-plan.json", stage2aFileOpenFlags, 0)
	if err != nil {
		return install, empty, errQualificationAdmissionUnavailable
	}
	file := os.NewFile(uintptr(fd), stage2aQualificationQPlanPath)
	defer file.Close()
	var st, after unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Nlink != 1 ||
		st.Uid != uint32(install.AdminUID) || st.Gid != uint32(install.AdminGID) ||
		st.Size <= 0 || st.Size > planLimit || checkDarwinACLs([]string{stage2aQualificationQPlanPath}) != nil {
		return install, empty, errQualificationAdmissionUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, planLimit+1))
	if err != nil || int64(len(raw)) != st.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(st, after) {
		return install, empty, errQualificationAdmissionUnavailable
	}
	request, err := decodeStage2aQualificationQPlan(raw, install)
	if err != nil || measureStage2aQualificationQPlan(ctx, install, request) != nil {
		return install, empty, errQualificationAdmissionUnavailable
	}
	return install, request, nil
}

func decodeStage2aQualificationQPlan(raw []byte, install stage2aQualificationQInstall) (QualificationRequest, error) {
	var saved Saved
	var empty QualificationRequest
	review := install.Review
	if !review.valid() || stage2aStrictJSON(raw) != nil || json.Unmarshal(raw, &saved) != nil ||
		saved.PlanID != review.PlanID || saved.PlanDigest != review.PlanDigest || saved.QualificationRun == nil {
		return empty, errQualificationAdmissionUnavailable
	}
	request := saved.QualificationRun.Request
	candidate := request.Candidate
	if request.SchemaVersion != 2 || candidate == nil || validateQualificationRequest(request) != nil ||
		candidate.HostUUID != review.HostUUID || request.Host.ID != review.HostID ||
		candidate.InstallationID != review.InstallationID || candidate.InstalledPlanDigest != review.InstalledPlanDigest ||
		candidate.TestPlan != review.TestPlan || request.TestProvider.ConfigPath != review.Provider.Path ||
		request.TestProvider.ConfigSHA != review.Provider.SHA256 ||
		request.Runner.BinaryPath != install.Source.Path ||
		request.Runner.BinarySHA != install.Source.SHA256 {
		return empty, errQualificationAdmissionUnavailable
	}
	canonical, err := saved.CanonicalForReview()
	if err != nil || stage2aQualificationSHA256(canonical) != "sha256:"+review.PlanDigest {
		return empty, errQualificationAdmissionUnavailable
	}
	return request, nil
}

func measureStage2aQualificationQPlan(ctx context.Context, install stage2aQualificationQInstall, request QualificationRequest) error {
	harness := request.Adapter.Harness
	if observeStage2aQualificationHost(ctx, install.Review.HostUUID) != nil ||
		verifyQualificationFile(install.Review.TestPlan) != nil || verifyQualificationFile(install.Review.Provider) != nil ||
		verifyQualificationExecutable(harness.BinaryPath, harness.BinarySHA) != nil {
		return errQualificationAdmissionUnavailable
	}
	return nil
}
