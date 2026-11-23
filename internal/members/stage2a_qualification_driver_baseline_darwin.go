package members

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

var errStage2aDriverLiveUnsupported = errors.New("owner driver supports before-launch baselines only")

type stage2aDriverBaselineWitness struct {
	Path          string `json:"path"`
	ContentSHA256 string `json:"content_sha256"`
	Device        string `json:"device"`
	Inode         string `json:"inode"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Mode          uint16 `json:"mode"`
}

func sampleStage2aDriverBaselineFile(file qualificationFile, adminUID int) (stage2aDriverBaselineWitness, error) {
	var empty stage2aDriverBaselineWitness
	if !stage2aAbsolutePath(file.Path) || !qualificationDigest.MatchString(file.SHA256) || adminUID <= 0 {
		return empty, errStage2aReservationAuthority
	}
	f, err := os.OpenFile(file.Path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	var before, after, path unix.Stat_t
	if unix.Fstat(int(f.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		(before.Uid != uint32(adminUID) && before.Uid != 0) || before.Mode&07022 != 0 ||
		before.Size == 0 || before.Size > stage2aQualificationFrameMax {
		return empty, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, stage2aQualificationFrameMax+1))
	if err != nil || stage2aQualificationSHA256(raw) != "sha256:"+file.SHA256 ||
		unix.Fstat(int(f.Fd()), &after) != nil || unix.Lstat(file.Path, &path) != nil ||
		!sameStage2aDriverBaselineFile(before, after) || !sameStage2aDriverBaselineFile(path, after) {
		return empty, errStage2aReservationAuthority
	}
	return stage2aDriverBaselineWitness{
		Path: file.Path, ContentSHA256: "sha256:" + file.SHA256,
		Device: strconv.FormatInt(int64(before.Dev), 10), Inode: strconv.FormatUint(before.Ino, 10),
		UID: before.Uid, GID: before.Gid, Mode: before.Mode & 07777,
	}, nil
}

func sameStage2aDriverBaselineFile(a, b unix.Stat_t) bool {
	// Reading a file may change its access time.
	a.Atim, b.Atim = unix.Timespec{}, unix.Timespec{}
	return a == b
}

func verifyStage2aDriverBaseline(ctx context.Context, command stage2aDriverCommand,
	review stage2aDriverReview, provider qualificationFile, adminUID int) (stage2aDriverCorroboration, error) {
	var empty stage2aDriverCorroboration
	if ctx.Err() != nil || command.Phase != stage2aDriverBeforeLaunch ||
		command.TestPlanSHA256 != review.testPlanSHA256 {
		return empty, errStage2aDriverLiveUnsupported
	}
	file := provider
	switch {
	case command.Profile == "managed-protected" && command.Gate == "T03" && command.Event == "policy-baseline":
		file = review.Policy
	case command.Profile == "managed-protected" && command.Gate == "T02" && command.Event == "custody-baseline":
	case command.Profile == "managed-cooperative" && command.Gate == "T21" && command.Event == "cooperative-baseline":
	default:
		return empty, errStage2aReservationAuthority
	}
	witness, err := sampleStage2aDriverBaselineFile(file, adminUID)
	if err != nil {
		return empty, err
	}
	osWitness, err := marshalStage2aReservationJCS(witness)
	if err != nil {
		return empty, err
	}
	commandRaw, err := marshalStage2aReservationJCS(command)
	if err != nil {
		return empty, err
	}
	artifact, err := marshalStage2aReservationJCS(map[string]any{
		"kind": "baseline-capture", "request_sha256": stage2aQualificationSHA256(commandRaw),
		"os_witness_sha256": stage2aQualificationSHA256(osWitness),
	})
	if err != nil {
		return empty, err
	}
	return stage2aDriverCorroboration{
		artifact: artifact, osWitness: osWitness,
		probe: stage2aQualificationObserveV1{
			Paths: []stage2aQualificationPathRequestV1{{Role: "reviewed-baseline", Path: witness.Path}},
		},
	}, nil
}

// A calls this after opening Q from the durable reservation and before
// publishing launchd state. The independent guard must prove that cutover
// has not occurred. The driver only samples the installed baseline pins.
func driveStage2aReviewedBaseline(ctx context.Context, listener *stage2aQualificationDriverListener,
	session *stage2aQualificationSessionV1, beforePublication func() error) (stage2aDriverReview, stage2aQualificationDriverPeer, []stage2aDriverEvidence, error) {
	install, err := loadStage2aQualificationQInstall()
	if err != nil || listener == nil || listener.uid != install.AdminUID || listener.gid != install.AdminGID {
		if session != nil {
			session.close()
		}
		return stage2aDriverReview{}, stage2aQualificationDriverPeer{}, nil, errStage2aReservationAuthority
	}
	testPlan := install.Review.TestPlan
	review, err := loadStage2aQualificationDriverReview(testPlan)
	if err != nil {
		if session != nil {
			session.close()
		}
		return stage2aDriverReview{}, stage2aQualificationDriverPeer{}, nil, err
	}
	return driveStage2aQualificationPhase(ctx, listener, testPlan, session, stage2aDriverBeforeLaunch, beforePublication,
		func(ctx context.Context, command stage2aDriverCommand, digest string) (stage2aDriverCorroboration, error) {
			// The two processes each capture pinned local bytes and independently
			// sample the OS. The exchange itself compares their resulting digests.
			return verifyStage2aDriverBaseline(ctx, command, review, install.Review.Provider, install.AdminUID)
		})
}
