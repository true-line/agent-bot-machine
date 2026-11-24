package members

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"time"
)

// RunStage2aQualificationOwnerDriver is a nonroot, no-argument
// worker. It takes code, socket, policy and provider pins from the installed
// owner review and admits only the reviewed local A process.
func RunStage2aQualificationOwnerDriver() error {
	install, err := loadStage2aQualificationQInstall()
	if err != nil || os.Getuid() <= 0 || os.Getuid() != os.Geteuid() || os.Getuid() != install.AdminUID ||
		os.Getgid() != os.Getegid() || os.Getgid() != install.AdminGID {
		return errStage2aReservationAuthority
	}
	review, err := loadStage2aQualificationDriverReview(install.Review.TestPlan)
	if err != nil {
		return err
	}
	account, err := user.LookupId(strconv.Itoa(install.AdminUID))
	self, selfErr := os.Executable()
	if err != nil || selfErr != nil || self != review.Executable.Path || review.Socket != stage2aQualificationDriverPath(account.HomeDir) ||
		len(review.AuthorityArgv) == 0 || review.AuthorityArgv[0] != review.Authority.Path ||
		verifyStage2aDriverAuthorityImage(review.Authority, install.AdminUID) != nil ||
		!slices.Equal(os.Args, review.Argv) || verifyQualificationExecutable(review.Executable.Path, review.Executable.SHA256) != nil {
		return errStage2aReservationAuthority
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", review.Socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	peer, err := ObserveSoulAdmissionPeer(conn.(*net.UnixConn))
	if err != nil || peer.UID != install.AdminUID || peer.PID == os.Getpid() {
		return errStage2aReservationAuthority
	}
	observed, err := observeSoulProcess(peer.PID, review.Authority.Path, review.AuthorityArgv)
	if err != nil || !stage2aQualificationKernelMatches(observed.Kernel, peer.PID, install.AdminUID, install.AdminGID) {
		return errStage2aReservationAuthority
	}
	return serveStage2aDriverReviewed(ctx, conn, review, install.Review, install.AdminUID, func() error {
		current, err := observeSoulProcess(peer.PID, review.Authority.Path, review.AuthorityArgv)
		if err != nil || !sameSoulKernelProcess(current.Kernel, observed.Kernel) {
			return errStage2aReservationAuthority
		}
		return nil
	})
}

func serveStage2aDriverBaseline(ctx context.Context, conn net.Conn, review stage2aDriverReview,
	provider qualificationFile, adminUID int, checkA func() error) error {
	return serveStage2aDriverReviewed(ctx, conn, review, stage2aQualificationQReview{Provider: provider, DriverBaselineOnly: true}, adminUID, checkA)
}

func serveStage2aDriverReviewed(ctx context.Context, conn net.Conn, review stage2aDriverReview,
	install stage2aQualificationQReview, adminUID int, checkA func() error) error {
	if conn.SetReadDeadline(time.Now().Add(10*time.Second)) != nil || checkA() != nil {
		return errStage2aReservationAuthority
	}
	raw, err := readStage2aQualificationFrame(conn)
	if err != nil {
		return err
	}
	var first stage2aDriverCommand
	if json.Unmarshal(raw, &first) != nil || first.TestPlanSHA256 != review.testPlanSHA256 ||
		len(first.SessionID) != 32 || !stage2aQualificationHex(first.SessionID) ||
		!stage2aQualificationDigest(first.ReservationSHA256) ||
		!soulInstallationID.MatchString(first.InstallationID) || !soulStartID.MatchString(first.StartID) {
		return errStage2aReservationAuthority
	}
	if first.Phase != stage2aDriverBeforeLaunch ||
		(!install.DriverBaselineOnly && (!install.DriverLiveT03 || first.Profile != "managed-protected")) {
		return errStage2aDriverLiveUnsupported
	}
	begin := stage2aQualificationBeginV1{
		SessionID: first.SessionID, InstallationID: first.InstallationID, StartID: first.StartID,
		ReservationSHA256: first.ReservationSHA256, TestPlanSHA256: review.testPlanSHA256, Profile: first.Profile,
	}
	err = serveStage2aQualificationDriverCasesFrom(ctx, conn, begin, first.Phase, raw,
		func(ctx context.Context, command stage2aDriverCommand) (string, error) {
			if err := checkA(); err != nil {
				return "", err
			}
			capture, err := verifyStage2aDriverBaseline(ctx, command, review, install.Provider, adminUID)
			if err != nil || checkA() != nil {
				return "", errStage2aReservationAuthority
			}
			return stage2aQualificationSHA256(capture.artifact), nil
		})
	if err != nil {
		return err
	}
	if install.DriverLiveT03 {
		err := serveStage2aQualificationDriverCases(ctx, conn, begin, stage2aDriverLiveT03,
			func(_ context.Context, command stage2aDriverCommand) (string, error) {
				if err := checkA(); err != nil {
					return "", err
				}
				return readStage2aDriverLiveArtifact(conn, command, checkA)
			})
		if err != nil {
			return err
		}
	}
	// Keep the authenticated generation alive until A has corroborated the
	// last response and closed its side of the one-use connection.
	var trailing [1]byte
	if n, err := conn.Read(trailing[:]); n != 0 || err != io.EOF {
		return errStage2aReservationAuthority
	}
	return nil
}

type stage2aDriverLiveArmed struct {
	Schema     string `json:"schema"`
	Kind       string `json:"kind"`
	RequestSHA string `json:"request_sha256"`
}

func confirmStage2aDriverLiveArmed(conn net.Conn, commandRaw []byte) error {
	raw, err := readStage2aQualificationFrame(conn)
	if err != nil {
		return err
	}
	var reply stage2aDriverLiveArmed
	_, err = stage2aQualificationKeysV1(raw, []string{"schema", "kind", "request_sha256"}, "")
	if err != nil || json.Unmarshal(raw, &reply) != nil || reply.Schema != stage2aDriverCaseSchema ||
		reply.Kind != "live-armed" || reply.RequestSHA != stage2aQualificationSHA256(commandRaw) {
		return errStage2aReservationAuthority
	}
	return nil
}

type stage2aDriverLiveArtifact struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	RequestSHA  string `json:"request_sha256"`
	ArtifactSHA string `json:"artifact_sha256"`
}

func readStage2aDriverLiveArtifact(conn net.Conn, command stage2aDriverCommand, checkA func() error) (string, error) {
	var artifact stage2aDriverLiveArtifact
	request, err := marshalStage2aReservationJCS(command)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	digest := stage2aQualificationSHA256(request)
	if _, err := writeStage2aQualificationFrame(conn, stage2aDriverLiveArmed{
		Schema: stage2aDriverCaseSchema, Kind: "live-armed", RequestSHA: digest,
	}); err != nil {
		return "", err
	}
	raw, err := readStage2aQualificationFrame(conn)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	_, err = stage2aQualificationKeysV1(raw, []string{"schema", "kind", "request_sha256", "artifact_sha256"}, "")
	if err != nil || json.Unmarshal(raw, &artifact) != nil || artifact.Schema != stage2aDriverCaseSchema ||
		artifact.Kind != "live-artifact" || artifact.RequestSHA != digest ||
		!stage2aQualificationDigest(artifact.ArtifactSHA) || checkA() != nil {
		return "", errStage2aReservationAuthority
	}
	return artifact.ArtifactSHA, nil
}
