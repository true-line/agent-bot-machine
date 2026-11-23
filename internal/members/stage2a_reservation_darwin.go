package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

const stage2aReservationPurpose = "agent-bot/stage2a-reservation/v1"

var (
	errStage2aReservationAuthority = errors.New("Stage 2a reservation authority unavailable or mismatched")
	errStage2aReservationSpent     = errors.New("Stage 2a start is already spent")
	errStage2aReservationExpired   = errors.New("Stage 2a reservation expired before delivery")
)

type stage2aReservationRequest struct {
	start    SoulRunRequest
	launchID string
}

// This digest identifies the installed frozen Soul candidate. Adapter package
// and Souls runtime archive digests have separate sources and semantics.
type stage2aSoulArtifactSHA256 string

// The installed authority loader must source these values while the start is
// serialized: the enrolled host and administrator key, verified exact root
// receipt bytes, live dedicated HQ epoch and endpoint availability, approved
// artifact/definition mapping, and descriptor-verified snapshot measurements.
// Neither a plan request nor shape-valid measurement records establish them.
type stage2aReservationInputs struct {
	hostID             string
	planID             string
	installedPlan      []byte
	installedReceipt   []byte
	runner             SoulRunner
	bridge             SoulBridge
	hqUID, machineUID  int
	enrolledAdminKey   ed25519.PublicKey
	expires            time.Time
	binding            Stage2aMeasurementBinding
	approvedArtifact   stage2aSoulArtifactSHA256 // from the authenticated owner mapping
	installedArtifact  stage2aSoulArtifactSHA256 // from the authenticated installed-byte receipt
	admissionChallenge [32]byte
}

// The resolver and signer are package-private seams. Production requires an
// authenticated installed authority loader and a purpose-limited secure-admin
// signing path. Current Machine has no implementation of either seam.
type stage2aReservationAuthority struct {
	beforeAdminSign func(*os.File) error
	load            func(stage2aReservationRequest) (stage2aReservationInputs, error)
	sign            func([]byte) ([]byte, error)
}

// The provisional assignment and shared v3 measurement binding both carry
// the same measured frozen artifact independently of the legacy digest.
type stage2aReservationAssignment struct {
	SoulStartAssignment
	SoulArtifactSHA256 stage2aSoulArtifactSHA256 `json:"soul_artifact_sha256"`
}

type stage2aReservationPayload struct {
	Contract                   string                       `json:"contract"`
	Kind                       string                       `json:"kind"`
	SchemaVersion              int                          `json:"schema_version"`
	HostID                     string                       `json:"host_id"`
	IssuedAt                   string                       `json:"issued_at"`
	ExpiresAt                  string                       `json:"expires_at"`
	InstalledPlanReceiptSHA256 string                       `json:"installed_plan_receipt_sha256"`
	Assignment                 stage2aReservationAssignment `json:"assignment"`
	MemberEndpoint             SoulMemberLaunchAssignment   `json:"member_endpoint"`
	MeasurementBinding         Stage2aMeasurementBinding    `json:"measurement_binding"`
	AdmissionChallengeSHA256   string                       `json:"admission_challenge_sha256"`
}

type stage2aSignedReservation struct {
	SchemaVersion            int    `json:"schema_version"`
	Purpose                  string `json:"purpose"`
	IssuerPublicKeyBase64URL string `json:"issuer_public_key_base64url"`
	PayloadSHA256            string `json:"payload_sha256"`
	PayloadBase64URL         string `json:"payload_base64url"`
	SignatureBase64URL       string `json:"signature_base64url"`
}

type stage2aReservation struct {
	envelope []byte
	sha256   string
}

func stage2aReservationSHA256(raw []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}

func stage2aReservationBindingMatches(m Stage2aMeasurementBinding, a SoulStartAssignment, hostID string, ownerUID, snapshotGID uint32) bool {
	// machine/v1 permits an omitted Soul artifact for older nonauthorizing
	// readers. A signed reservation requires the exact installed frozen .soul.
	if m.SoulArtifactSHA256 == "" {
		return false
	}
	if _, _, err := stage2aBindingDigestForOwner(m, ownerUID); err != nil {
		return false
	}
	definition, launch := m.Snapshots.Definition, m.Snapshots.LaunchInputs
	return m.HostID == hostID && m.PlanID == a.PlanID && m.InstalledPlanDigest == a.PlanDigest &&
		m.InstallationID == a.InstallationID && m.SoulID == a.SoulID && m.StartID == a.StartID &&
		m.LaunchID == a.LaunchID && m.HQEpoch == a.HQEpoch &&
		m.PackageSHA256 == a.PackageSHA256 &&
		(m.ProfileInForce == "managed-protected" || m.ProfileInForce == "managed-cooperative") &&
		definition.Inode != "0" && launch.Inode != "0" &&
		definition.BirthtimeNS != "0" && launch.BirthtimeNS != "0" &&
		definition.OwnerGID == snapshotGID && launch.OwnerGID == snapshotGID &&
		!strings.EqualFold(definition.RootPath, launch.RootPath) &&
		(definition.Device != launch.Device || definition.Inode != launch.Inode)
}

func prepareStage2aReservation(req stage2aReservationRequest, in stage2aReservationInputs, issued time.Time) (stage2aReservationPayload, error) {
	return prepareStage2aReservationForOwner(req, in, issued, 0, uint32(in.runner.GID))
}

func prepareStage2aReservationForOwner(req stage2aReservationRequest, in stage2aReservationInputs,
	issued time.Time, ownerUID, snapshotGID uint32) (stage2aReservationPayload, error) {
	if !req.start.valid() || !soulLaunchID.MatchString(req.launchID) ||
		!soulInstallationID.MatchString(in.hostID) || len(in.installedReceipt) == 0 ||
		in.machineUID > math.MaxUint32 || (ownerUID != 0 && in.machineUID != int(ownerUID)) ||
		!utf8.ValidString(in.runner.PackageRoot) ||
		!soulDigest.MatchString(string(in.approvedArtifact)) || in.approvedArtifact != in.installedArtifact ||
		in.binding.SoulArtifactSHA256 != string(in.installedArtifact) ||
		len(in.enrolledAdminKey) != ed25519.PublicKeySize || in.admissionChallenge == [32]byte{} {
		return stage2aReservationPayload{}, errStage2aReservationAuthority
	}
	a, err := PrepareSoulStartAssignment(in.runner, in.bridge, in.hqUID, in.machineUID,
		in.planID, req.start.PlanDigest, req.start.StartID, req.launchID, req.start.HQEpoch, issued, in.expires)
	if err != nil || CheckSoulStartAssignment(a, in.planID, in.installedPlan, in.runner, in.bridge,
		in.hqUID, in.machineUID, req.start, req.launchID, issued) != nil || !stage2aReservationBindingMatches(in.binding, a, in.hostID, ownerUID, snapshotGID) {
		return stage2aReservationPayload{}, errStage2aReservationAuthority
	}
	endpoints, err := DeriveSoulBridgeEndpoints(in.runner, in.bridge, in.hqUID, req.start.StartID)
	if err != nil || !reflect.DeepEqual(startEndpoint(endpoints.Member), a.Member) {
		return stage2aReservationPayload{}, errStage2aReservationAuthority
	}
	return stage2aReservationPayload{
		Contract: in.binding.Contract, Kind: "stage2a-reservation", SchemaVersion: in.binding.SchemaVersion, HostID: in.hostID,
		IssuedAt: issued.UTC().Format(time.RFC3339Nano), ExpiresAt: a.ExpiresAt,
		InstalledPlanReceiptSHA256: stage2aReservationSHA256(in.installedReceipt),
		Assignment:                 stage2aReservationAssignment{SoulStartAssignment: a, SoulArtifactSHA256: in.installedArtifact},
		MemberEndpoint:             endpoints.MemberLaunchAssignment(),
		MeasurementBinding:         in.binding,
		AdmissionChallengeSHA256:   stage2aReservationSHA256(in.admissionChallenge[:]),
	}, nil
}

func marshalStage2aReservationJCS(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

// reserveStage2aStart is an unwired root entry point. There is no CLI, daemon
// verb, install rule, or fallback key path. Claims storage must already exist
// under Machine's owner-reviewed root custody before any start can be spent.
func reserveStage2aStart(req stage2aReservationRequest, authority stage2aReservationAuthority) (stage2aReservation, error) {
	if authority.load == nil || authority.sign == nil ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	if err := trustedPath(OSHost{}, soulStartClaimsDir, true); err != nil {
		return stage2aReservation{}, err
	}
	if err := checkDarwinACLs(pathAncestry(soulStartClaimsDir)); err != nil {
		return stage2aReservation{}, err
	}
	dir, err := os.OpenFile(soulStartClaimsDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return stage2aReservation{}, err
	}
	defer dir.Close()
	return reserveStage2aStartIn(dir, 0, 0, req, authority, time.Now)
}

func reserveStage2aStartIn(dir *os.File, uid, gid uint32, req stage2aReservationRequest,
	authority stage2aReservationAuthority, now func() time.Time) (stage2aReservation, error) {
	if !req.start.valid() || !soulLaunchID.MatchString(req.launchID) || authority.load == nil || authority.sign == nil {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	if err := checkStage2aReservationFile(int(dir.Fd()), uid, gid, unix.S_IFDIR|0700); err != nil {
		return stage2aReservation{}, err
	}
	lock, err := lockStage2aReservation(dir, uid, gid, req.start.InstallationID)
	if err != nil {
		return stage2aReservation{}, fmt.Errorf("lock Stage 2a reservation: %w", err)
	}
	defer lock.Close()
	// The stable name also refuses rebinding the same installation/start to a
	// different host, HQ epoch, plan, or launch. The member socket name has the
	// same installation/start scope and must never be reassigned on retry.
	name := soulStartClaimName(req.start.InstallationID, req.start.StartID)
	if err := requireUnspentStage2aReservation(dir, name); err != nil {
		return stage2aReservation{}, err
	}
	in, err := authority.load(req)
	if err != nil {
		return stage2aReservation{}, errStage2aReservationAuthority
	}
	payload, err := prepareStage2aReservation(req, in, now())
	if err != nil {
		return stage2aReservation{}, err
	}
	envelope, err := signStage2aReservation(payload, stage2aReservationPurpose, in.enrolledAdminKey, authority.sign)
	if err != nil {
		return stage2aReservation{}, err
	}
	if err := commitStage2aReservation(dir, name, envelope); err != nil {
		return stage2aReservation{}, fmt.Errorf("commit Stage 2a reservation: %w", err)
	}
	if !in.expires.After(now()) {
		return stage2aReservation{}, errStage2aReservationExpired
	}
	return stage2aReservation{envelope: envelope, sha256: stage2aReservationSHA256(envelope)}, nil
}

func signStage2aReservation(payload stage2aReservationPayload, purpose string,
	enrolledKey ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, error) {
	return signStage2aEnvelope(payload, payload.SchemaVersion, purpose, enrolledKey, sign)
}

func signStage2aEnvelope(payload any, version int, purpose string,
	enrolledKey ed25519.PublicKey, sign func([]byte) ([]byte, error)) ([]byte, error) {
	canonical, err := marshalStage2aReservationJCS(payload)
	if err != nil {
		return nil, err
	}
	preimage := append([]byte(purpose+"\x00"), canonical...)
	// Do not trust the signer to preserve the bytes supplied to it. Check the
	// signature over our own independent copy and against the enrolled key.
	key := bytes.Clone(enrolledKey)
	sig, err := sign(bytes.Clone(preimage))
	if err != nil || !ed25519.Verify(key, preimage, sig) {
		return nil, errStage2aReservationAuthority
	}
	envelope, err := marshalStage2aReservationJCS(stage2aSignedReservation{
		SchemaVersion: version, Purpose: purpose,
		IssuerPublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(key),
		PayloadSHA256:            stage2aReservationSHA256(canonical),
		PayloadBase64URL:         base64.RawURLEncoding.EncodeToString(canonical),
		SignatureBase64URL:       base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

func checkStage2aReservationFile(fd int, uid, gid uint32, mode uint16) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uid || st.Gid != gid || st.Mode != mode || (mode&unix.S_IFMT == unix.S_IFREG && st.Nlink != 1) {
		return errors.New("Stage 2a reservation storage is not private")
	}
	return nil
}

func lockStage2aReservation(dir *os.File, uid, gid uint32, installationID string) (*os.File, error) {
	name := ".stage2a-" + soulEndpointInstallationSlot(installationID) + ".lock"
	const flags = unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_RDWR
	dirFD := int(dir.Fd())
	fd, err := unix.Openat(dirFD, name, flags, 0)
	if errors.Is(err, unix.ENOENT) {
		// Separate exclusive creation from opening the permanent inode.
		// Darwin's ordinary O_CREAT can return ENOENT to concurrent openers
		// during first creation even though an opener successfully created it.
		fd, err = unix.Openat(dirFD, name, flags|unix.O_CREAT|unix.O_EXCL, 0600)
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(dirFD, name, flags, 0)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open installation lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), name)
	if err := checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600); err != nil {
		lock.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		lock.Close()
		return nil, fmt.Errorf("acquire installation lock: %w", err)
	}
	return lock, nil
}

func requireUnspentStage2aReservation(dir *os.File, name string) error {
	var existing unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &existing, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errStage2aReservationSpent
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func commitStage2aReservation(dir *os.File, name string, envelope []byte) (err error) {
	// The containing directory has already been verified root-private. Stage
	// complete bytes on the same filesystem; exclusive rename also arbitrates
	// against any existing legacy started claim that uses the same name.
	dirFD := int(dir.Fd())
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	staged := fmt.Sprintf(".stage2a-reservation-%x", random)
	fd, err := unix.Openat(dirFD, staged, unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_EXCL|unix.O_CREAT|unix.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), staged)
	defer unix.Unlinkat(dirFD, staged, 0)
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(envelope)
	}
	if err == nil {
		_, err = unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	}
	if err != nil {
		return err
	}
	err = unix.RenameatxNp(dirFD, staged, dirFD, name, unix.RENAME_EXCL)
	if errors.Is(err, unix.EEXIST) {
		return errStage2aReservationSpent
	}
	if err != nil {
		return err
	}
	// Once the name exists it is spent, including when directory sync fails.
	// No error path unlinks it or returns the signed bytes to the caller.
	if err := dir.Sync(); err != nil {
		return err
	}
	// Flush the device after syncing the parent's rename metadata while the
	// published file descriptor is still open.
	_, err = unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	return err
}
