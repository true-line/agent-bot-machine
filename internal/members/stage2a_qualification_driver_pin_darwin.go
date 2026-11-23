package members

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// This projection comes from the exact owner-reviewed test plan bytes. A
// obtains their digest from the active reservation, outside the wire.
type stage2aDriverReview struct {
	testPlanSHA256 string
	Schema         string            `json:"owner_driver_schema"`
	Socket         string            `json:"owner_driver_socket"`
	Executable     qualificationFile `json:"owner_driver_executable"`
	Argv           []string          `json:"owner_driver_argv"`
	Policy         qualificationFile `json:"owner_driver_policy"`
	Authority      qualificationFile `json:"owner_driver_authority"`
	CohortID       string            `json:"owner_driver_cohort_id"`
	SuiteRevision  string            `json:"owner_driver_suite_revision"`
	AuthorityArgv  []string          `json:"owner_driver_authority_argv"`
}

func loadStage2aQualificationDriverReview(testPlan qualificationFile) (stage2aDriverReview, error) {
	var review stage2aDriverReview
	if !stage2aAbsolutePath(testPlan.Path) || !qualificationDigest.MatchString(testPlan.SHA256) {
		return review, errStage2aReservationAuthority
	}
	f, err := os.OpenFile(testPlan.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return review, errStage2aReservationAuthority
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return review, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) > 65536 || stage2aQualificationSHA256(raw) != "sha256:"+testPlan.SHA256 || rejectDuplicateJSONKeys(raw) != nil ||
		json.Unmarshal(raw, &review) != nil || review.Schema != stage2aDriverCaseSchema ||
		!stage2aAbsolutePath(review.Socket) || review.Executable.Path == "" || !qualificationDigest.MatchString(review.Executable.SHA256) ||
		validateSoulExpectedArguments(review.Executable.Path, review.Argv) != nil ||
		review.Argv[0] != review.Executable.Path {
		return stage2aDriverReview{}, errStage2aReservationAuthority
	}
	review.testPlanSHA256 = "sha256:" + testPlan.SHA256
	return review, nil
}

func acceptStage2aReviewedQualificationDriver(ctx context.Context, listener *stage2aQualificationDriverListener,
	review stage2aDriverReview) (*net.UnixConn, stage2aQualificationDriverPeer, error) {
	if listener == nil || listener.path != review.Socket || review.Schema != stage2aDriverCaseSchema ||
		verifyQualificationExecutable(review.Executable.Path, review.Executable.SHA256) != nil {
		return nil, stage2aQualificationDriverPeer{}, errStage2aReservationAuthority
	}
	conn, peer, err := listener.accept(ctx, review.Executable.Path, review.Argv)
	if err != nil {
		return nil, stage2aQualificationDriverPeer{}, err
	}
	if peer.recheck() != nil || verifyQualificationExecutable(review.Executable.Path, review.Executable.SHA256) != nil {
		conn.Close()
		return nil, stage2aQualificationDriverPeer{}, errStage2aReservationAuthority
	}
	return conn, peer, nil
}

func verifyStage2aDriverAuthorityImage(file qualificationFile, adminUID int) error {
	const maximum = 512 << 20
	if adminUID <= 0 || !stage2aAbsolutePath(file.Path) || !qualificationDigest.MatchString(file.SHA256) {
		return errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(filepath.Dir(file.Path), uint32(adminUID))
	if err != nil {
		return err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(file.Path), stage2aFileOpenFlags, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), file.Path)
	defer f.Close()
	var before, after, path unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		(before.Uid != uint32(adminUID) && before.Uid != 0) || before.Mode&07022 != 0 ||
		before.Mode&0100 == 0 || before.Size <= 0 || before.Size > maximum ||
		checkDarwinACLs([]string{file.Path}) != nil {
		return errStage2aReservationAuthority
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maximum+1))
	if err != nil || n != before.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 ||
		checkDarwinNode(f) != nil ||
		unix.Fstat(fd, &after) != nil || unix.Lstat(file.Path, &path) != nil ||
		!sameStage2aDriverBaselineFile(before, after) || !sameStage2aDriverBaselineFile(path, after) {
		return errStage2aReservationAuthority
	}
	return nil
}
