//go:build darwin

package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/qwts/managed-machine/internal/plan"
	"golang.org/x/sys/unix"
)

const stage2aLocalTestQDriverPlanLimit = 64 << 10

const stage2aLocalTestContractsTag = "v0.10.3"
const stage2aLocalTestContractsCommit = "896b693b23219444dcbe4af4083fd1bc4b9f178c"
const stage2aLocalTestContractsDigest = "sha256:e72bee1f4471c127a5557fd45756511595aa2e4c2423ed76be52373d46d8a2f3"
const stage2aLocalTestContractsFiles = 658

type stage2aLocalTestContractsPin struct {
	Repository      string   `json:"repository"`
	Tag             string   `json:"tag"`
	Commit          string   `json:"commit"`
	Paths           []string `json:"paths"`
	DigestAlgorithm string   `json:"digest_algorithm"`
	Digest          string   `json:"digest"`
	Files           int      `json:"files"`
}

type stage2aLocalTestQDriverPlan struct {
	Schema          string                       `json:"schema"`
	ContractsSource stage2aLocalTestContractsPin `json:"contracts_source"`
	Driver          json.RawMessage              `json:"driver"`
}

func (p stage2aLocalTestQDriverPlan) pinned() bool {
	c := p.ContractsSource
	return p.Schema == "agent-bot-machine/stage2a-observed-body-local-test-driver-plan/v1" &&
		c.Repository == "https://github.com/true-line/soul-contracts.git" &&
		c.Tag == stage2aLocalTestContractsTag && c.Commit == stage2aLocalTestContractsCommit &&
		slices.Equal(c.Paths, []string{"errors", "fixtures", "schemas"}) &&
		c.DigestAlgorithm == "sha256-manifest-v1" &&
		c.Digest == stage2aLocalTestContractsDigest && c.Files == stage2aLocalTestContractsFiles &&
		len(p.Driver) >= 2 && p.Driver[0] == '{' && stage2aStrictJSON(p.Driver) == nil
}

// The future A producer pins this A-private claim directory from the enrolled
// account. The Q ID then selects one fixed file inside that same directory.
func stage2aLocalTestQDriverPlanPath(state, planID string) (string, error) {
	if !stage2aAbsolutePath(state) || filepath.Clean(state) != state ||
		!plan.ValidID(planID) {
		return "", errStage2aReservationAuthority
	}
	return filepath.Join(state, planID+".stage2a-local-test-driver-plan.json"), nil
}

func stage2aLocalTestQReviewedDriverSHA(state, planID string, uid, gid uint32) (string, error) {
	path, err := stage2aLocalTestQDriverPlanPath(state, planID)
	if err != nil || uid < 400 || gid == 0 || uid != uint32(os.Getuid()) ||
		uid != uint32(os.Geteuid()) || gid != uint32(os.Getgid()) || gid != uint32(os.Getegid()) {
		return "", errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(state, uid)
	if err != nil {
		return "", errStage2aReservationAuthority
	}
	defer dir.Close()
	if checkStage2aReservationFile(int(dir.Fd()), uid, gid, unix.S_IFDIR|0700) != nil {
		return "", errStage2aReservationAuthority
	}
	raw, err := stage2aReadProtectedFileForUID(path, stage2aLocalTestQDriverPlanLimit, uid, gid, 0600)
	if err != nil || stage2aStrictJSONBounded(raw, stage2aLocalTestQDriverPlanLimit, 4096) != nil ||
		len(raw) == 0 || raw[0] != '{' {
		return "", errStage2aReservationAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errStage2aReservationAuthority
	}
	var reviewed stage2aLocalTestQDriverPlan
	if stage2aDecodeExact(raw, &reviewed) != nil || !reviewed.pinned() {
		return "", errStage2aReservationAuthority
	}
	return stage2aReservationSHA256(canonical), nil
}

// This A-signed approval is distinct from schema-2 qualification approval.
// The root installer must load and verify it from a protected file and spend
// its own one-use install claim before publishing an enabled local-test plan.
type stage2aLocalTestQApprovalPayload struct {
	Schema             string                             `json:"schema"`
	Kind               string                             `json:"kind"`
	SchemaVersion      int                                `json:"schema_version"`
	Plan               stage2aLocalTestQPlan              `json:"plan"`
	PlanSHA256         string                             `json:"plan_sha256"`
	ApprovalReference  stage2aLocalTestQApprovalReference `json:"approval_reference"`
	MachineFingerprint string                             `json:"machine_fingerprint"`
	IssuedAt           string                             `json:"issued_at"`
	ExpiresAt          string                             `json:"expires_at"`
}

func stage2aLocalTestQApprovalForReview(q stage2aLocalTestQPlan, a Approval,
	observedHostUUID, installationID, ownerPlanSHA256, machineFingerprint,
	pairCommitment string, key ed25519.PublicKey, now time.Time,
) (stage2aLocalTestQApprovalPayload, []byte, error) {
	var empty stage2aLocalTestQApprovalPayload
	qRaw, err := marshalStage2aReservationJCS(q)
	if err != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	parsed, qDigest, err := parseStage2aLocalTestQPlan(qRaw)
	if err != nil || parsed != q || len(key) != ed25519.PublicKeySize ||
		q.AKeyID != stage2aReservationSHA256(key) ||
		q.HostUUID != observedHostUUID || q.InstallationID != installationID ||
		q.OwnerPlanSHA256 != ownerPlanSHA256 ||
		!digestPattern.MatchString(machineFingerprint) || !digestPattern.MatchString(pairCommitment) ||
		a.Purpose != stage2aLocalTestQPurpose || !ValidApproval(a.PlanID, a.PlanDigest) ||
		qDigest != "sha256:"+a.PlanDigest || a.MachineFingerprint != machineFingerprint ||
		a.PairCommitment != pairCommitment {
		return empty, nil, errStage2aReservationAuthority
	}
	approved, e1 := time.Parse(approvalTime, a.ApprovedAt)
	approvalExpires, e2 := time.Parse(approvalTime, a.ExpiresAt)
	qExpires, e3 := time.Parse(time.RFC3339Nano, q.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || approvalExpires.Sub(approved) != ApprovalTTL ||
		now.Before(approved) || !now.Before(approvalExpires) || !now.Before(qExpires) {
		return empty, nil, errStage2aReservationAuthority
	}
	expires := approvalExpires
	if qExpires.Before(expires) {
		expires = qExpires
	}
	payload := stage2aLocalTestQApprovalPayload{
		Schema: "agent-bot-machine/stage2a-observed-body-local-test-q-approval/v1",
		Kind:   "observed-body-local-test-q-approval", SchemaVersion: 1,
		Plan: q, PlanSHA256: qDigest,
		ApprovalReference: stage2aLocalTestQApprovalReference{
			PlanID: a.PlanID, PlanDigest: a.PlanDigest, PairCommitment: pairCommitment,
		},
		MachineFingerprint: machineFingerprint,
		IssuedAt:           now.UTC().Format(time.RFC3339Nano),
		ExpiresAt:          expires.UTC().Format(time.RFC3339Nano),
	}
	raw, err := marshalStage2aReservationJCS(payload)
	if err != nil || stage2aLocalTestCanonicalPayload(raw, stage2aLocalTestQApprovalPurpose) != nil {
		return empty, nil, errStage2aReservationAuthority
	}
	return payload, raw, nil
}

// Root uses this verifier against its own measured host and reviewed plan.
// The caller must obtain raw from a protected root-owned path and atomically
// spend a separate root claim before installing the plan; this pure verifier
// cannot establish file provenance or one-use install by itself.
func verifyStage2aLocalTestQApprovalEnvelope(envelope []byte, key ed25519.PublicKey,
	expectedPlan stage2aLocalTestQPlan, observedHostUUID, installationID,
	ownerPlanSHA256, machineFingerprint, pairCommitment string, now time.Time,
) (stage2aLocalTestQApprovalPayload, error) {
	var empty stage2aLocalTestQApprovalPayload
	raw, err := verifyStage2aLocalTestEnvelope(envelope, stage2aLocalTestQApprovalPurpose, key)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	var got stage2aLocalTestQApprovalPayload
	if stage2aDecodeExact(raw, &got) != nil ||
		got.Schema != "agent-bot-machine/stage2a-observed-body-local-test-q-approval/v1" ||
		got.Kind != "observed-body-local-test-q-approval" || got.SchemaVersion != 1 ||
		got.Plan != expectedPlan || got.Plan.HostUUID != observedHostUUID ||
		got.Plan.InstallationID != installationID ||
		got.Plan.OwnerPlanSHA256 != ownerPlanSHA256 ||
		got.Plan.AKeyID != stage2aReservationSHA256(key) ||
		got.MachineFingerprint != machineFingerprint || !digestPattern.MatchString(machineFingerprint) ||
		got.ApprovalReference.PairCommitment != pairCommitment || !digestPattern.MatchString(pairCommitment) ||
		!ValidApproval(got.ApprovalReference.PlanID, got.ApprovalReference.PlanDigest) {
		return empty, errStage2aReservationAuthority
	}
	qRaw, err := marshalStage2aReservationJCS(got.Plan)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	_, digest, err := parseStage2aLocalTestQPlan(qRaw)
	if err != nil || digest != got.PlanSHA256 ||
		got.ApprovalReference.PlanDigest != digest[len("sha256:"):] {
		return empty, errStage2aReservationAuthority
	}
	issued, e1 := time.Parse(time.RFC3339Nano, got.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, got.ExpiresAt)
	qExpires, e3 := time.Parse(time.RFC3339Nano, got.Plan.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || now.Before(issued) || !now.Before(expires) ||
		!issued.Before(expires) || expires.After(qExpires) || expires.Sub(issued) > ApprovalTTL {
		return empty, errStage2aReservationAuthority
	}
	return got, nil
}

// A commits the distinct Q approval claim before signing. Signer failure
// leaves the claim occupied, so an interrupted or restarted daemon cannot
// issue another approval envelope from the same owner approval.
func commitAndSignStage2aLocalTestQApproval(store stage2aAdminClaimStore, dir *os.File,
	q stage2aLocalTestQPlan, approval Approval, observedHostUUID, ownerPlanSHA256,
	machineFingerprint, pairCommitment string, key ed25519.PublicKey, now time.Time,
	sign func([]byte) ([]byte, error)) ([]byte, error) {
	if dir == nil || store.checkDirectory(dir) != nil || store.uid < 400 || store.gid == 0 ||
		store.uid != uint32(os.Getuid()) || store.uid != uint32(os.Geteuid()) ||
		store.gid != uint32(os.Getgid()) || store.gid != uint32(os.Getegid()) || sign == nil {
		return nil, errStage2aReservationAuthority
	}
	lock, err := lockStage2aReservation(dir, store.uid, store.gid, q.InstallationID)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	actualDir, pathErr := stage2aFDPath(int(dir.Fd()))
	if store.checkDirectory(dir) != nil || pathErr != nil || actualDir != store.path {
		return nil, errStage2aReservationAuthority
	}
	driverSHA, err := stage2aLocalTestQReviewedDriverSHA(store.path, approval.PlanID, store.uid, store.gid)
	if err != nil || driverSHA != q.DriverPlanSHA256 {
		return nil, errStage2aReservationAuthority
	}
	_, payload, err := stage2aLocalTestQApprovalForReview(q, approval, observedHostUUID,
		q.InstallationID, ownerPlanSHA256, machineFingerprint, pairCommitment, key, now)
	if err != nil {
		return nil, err
	}
	name := ".stage2a-local-test-q-" + soulEndpointInstallationSlot(q.InstallationID) + "-" + approval.PlanID + ".json"
	if err := commitStage2aReservation(dir, name, payload); err != nil {
		return nil, err
	}
	envelope, err := signStage2aVerifiedLocalTestEnvelope(stage2aVerifiedSigningPayloadV3{
		verified: true, purpose: stage2aLocalTestQApprovalPurpose, payload: bytes.Clone(payload),
		machineUID: store.uid, machineGID: store.gid,
	}, key, sign)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

// Keep the schema exact in both source and root-directed test vectors.
func parseStage2aLocalTestQApprovalPayload(raw []byte) (stage2aLocalTestQApprovalPayload, error) {
	var p stage2aLocalTestQApprovalPayload
	if len(raw) == 0 || len(raw) > 8192 || stage2aStrictJSON(raw) != nil ||
		stage2aDecodeExact(raw, &p) != nil ||
		stage2aLocalTestCanonicalPayload(raw, stage2aLocalTestQApprovalPurpose) != nil {
		return stage2aLocalTestQApprovalPayload{}, errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(p)
	if err != nil || !bytes.Equal(canonical, raw) {
		return stage2aLocalTestQApprovalPayload{}, errStage2aReservationAuthority
	}
	return p, nil
}
