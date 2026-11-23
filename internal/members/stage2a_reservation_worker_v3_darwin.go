package members

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const stage2aReservationWorkerCommandV3 = "stage2a-reservation-v3"
const stage2aReservationWorkerReplyLimitV3 = 160 << 10

type stage2aReservationWorkerRequestV3 struct {
	HQUID              int                            `json:"hq_uid"`
	MachineFingerprint string                         `json:"machine_fingerprint"`
	Selector           json.RawMessage                `json:"selector"`
	CandidateGrant     *stage2aSignedCandidateGrantV3 `json:"candidate_grant,omitempty"`
}

type stage2aReservationWorkerReplyV3 struct {
	Stage2aReserveReply
	PolicyDigest string                      `json:"installed_policy_sha256"`
	Mode         stage2aReservationRunModeV3 `json:"mode"`
	Expected     json.RawMessage             `json:"expected"`
}

type stage2aReservationWorkerAuthorityV3 struct {
	mode          stage2aReservationRunModeV3
	store         stage2aAdminClaimStore
	load          func(stage2aReservationRequest) (stage2aReservationEvidenceV3, error)
	loadCandidate func(stage2aReservationRequest) (stage2aQualificationCandidateAuthorityV3, error)
}

func decodeStage2aReservationWorkerRequestV3(raw []byte) (stage2aReservationWorkerRequestV3, Stage2aReserveRequest, error) {
	var q stage2aReservationWorkerRequestV3
	if len(raw) > 4096 || stage2aStrictJSON(raw) != nil || stage2aDecodeExact(raw, &q) != nil ||
		q.HQUID < 300 || q.HQUID > 399 || !digestPattern.MatchString(q.MachineFingerprint) {
		return q, Stage2aReserveRequest{}, errStage2aReservationAuthority
	}
	selector, err := ParseStage2aReserveRequest(q.Selector)
	return q, selector, err
}

// Production callers must provide the independently authenticated installed-R
// and qualified adapter loader. The key resolver rechecks the current paired
// HQ role and epoch before opening A's local key. Neither is caller metadata.
func runStage2aReservationWorkerV3(input io.Reader, output io.Writer,
	keyForPair func(int, string, string) (ed25519.PrivateKey, func() error, error),
	load func(stage2aInstalledRuntimeV3, ed25519.PublicKey) (stage2aReservationWorkerAuthorityV3, error)) error {
	if keyForPair == nil || load == nil || os.Getuid() < 400 || os.Getuid() != os.Geteuid() || !stage2aInstallSealNoIP() {
		return errStage2aReservationAuthority
	}
	me, err := os.Executable()
	if err != nil || me != SoulLauncher {
		return errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil {
		return err
	}
	q, selector, err := decodeStage2aReservationWorkerRequestV3(raw)
	if err != nil {
		return err
	}
	private, unlock, err := keyForPair(q.HQUID, selector.HQEpoch, q.MachineFingerprint)
	defer clear(private)
	if unlock != nil {
		defer unlock()
	}
	if err != nil || len(private) != ed25519.PrivateKeySize || unlock == nil {
		return errStage2aReservationAuthority
	}
	key := private.Public().(ed25519.PublicKey)
	if fmt.Sprintf("%x", sha256.Sum256(key)) != q.MachineFingerprint {
		return errStage2aReservationAuthority
	}
	runtime, err := stage2aLoadInstalledRuntimeV3(key, q.HQUID, selector.HQEpoch, selector.InstallationID)
	if err != nil {
		return errStage2aReservationAuthority
	}
	authority, err := load(runtime, key)
	if err != nil ||
		authority.store.uid != uint32(os.Geteuid()) || authority.store.gid != uint32(os.Getegid()) {
		return errStage2aReservationAuthority
	}
	start := SoulRunRequest{PlanDigest: selector.PlanDigest, InstallationID: selector.InstallationID, StartID: selector.StartID, HQEpoch: selector.HQEpoch}
	request := stage2aReservationRequest{start: start, launchID: selector.LaunchID}
	lease, err := time.Parse(time.RFC3339Nano, runtime.Policy.ApprovedUntil)
	if err != nil {
		return errStage2aReservationAuthority
	}
	sign := func(preimage []byte) ([]byte, error) {
		if stage2aRecheckVerifiedDomainV3(runtime.VerifiedR) != nil || !time.Now().Before(lease) {
			return nil, errStage2aReservationAuthority
		}
		if authority.mode == stage2aCandidateRunV3 {
			parent, err := observeSoulKernelProcess(os.Getppid())
			if err != nil || verifyStage2aCandidateLiveGrantV3(q.CandidateGrant, q.HQUID, selector, parent, key, time.Now()) != nil {
				return nil, errStage2aReservationAuthority
			}
		}
		return ed25519.Sign(private, preimage), nil
	}
	var got stage2aReservation
	var purpose string
	switch authority.mode {
	case stage2aQualifiedRunV3:
		if q.CandidateGrant != nil || authority.load == nil || authority.loadCandidate != nil {
			return errStage2aReservationAuthority
		}
		purpose = stage2aReservationPurposeV3
		got, err = reserveStage2aAdminStartV3(authority.store, request, func(req stage2aReservationRequest) (stage2aReservationEvidenceV3, error) {
			e, err := authority.load(req)
			if err != nil || e.r.ref != runtime.VerifiedR.ref {
				return stage2aReservationEvidenceV3{}, errStage2aReservationAuthority
			}
			return e, nil
		}, sign, time.Now)
	case stage2aCandidateRunV3:
		parent, parentErr := observeSoulKernelProcess(os.Getppid())
		if parentErr != nil || verifyStage2aCandidateLiveGrantV3(q.CandidateGrant, q.HQUID, selector, parent, key, time.Now()) != nil ||
			authority.loadCandidate == nil || authority.load != nil {
			return errStage2aReservationAuthority
		}
		purpose = stage2aQualificationCandidatePurposeV3
		got, err = reserveStage2aQualificationCandidateV3(authority.store, request, func(req stage2aReservationRequest) (stage2aQualificationCandidateAuthorityV3, error) {
			a, err := authority.loadCandidate(req)
			if err != nil || a.base.r.ref != runtime.VerifiedR.ref ||
				q.CandidateGrant.Grant.RDigest != runtime.VerifiedR.ref.InventoryDigest {
				return stage2aQualificationCandidateAuthorityV3{}, errStage2aReservationAuthority
			}
			attempt, err := stage2aCandidateAttemptV3(a, time.Now())
			if err != nil || attempt != q.CandidateGrant.Grant.Attempt {
				return stage2aQualificationCandidateAuthorityV3{}, errStage2aReservationAuthority
			}
			adapter, err := stage2aCandidateAdapterV3(a)
			if err != nil || adapter.PackageSHA256 != q.CandidateGrant.Grant.PackageSHA ||
				adapter.CandidateManifestSHA256 != q.CandidateGrant.Grant.ManifestSHA {
				return stage2aQualificationCandidateAuthorityV3{}, errStage2aReservationAuthority
			}
			return a, nil
		}, sign, time.Now)
	default:
		return errStage2aReservationAuthority
	}
	if err != nil {
		return err
	}
	payload, _, err := verifyStage2aV3Envelope(got.envelope, purpose, key)
	if err != nil {
		return errStage2aReservationAuthority
	}
	if _, err := verifyStage2aReservationModeV3(authority.mode, got.envelope, got.sha256, payload, key, time.Now()); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(stage2aReservationWorkerReplyV3{
		Stage2aReserveReply: Stage2aReserveReply{EnvelopeBase64URL: stage2aEncodeEnvelope(got.envelope), SHA256: got.sha256},
		PolicyDigest:        stage2aReservationSHA256(runtime.PolicyRaw), Mode: authority.mode, Expected: payload})
}

// The authenticated Machine handler calls this from A under the established
// pairing lock. No private signing material crosses the child pipe.
func callStage2aReservationWorkerV3(hqUID int, epoch string, selector Stage2aReserveRequest,
	key ed25519.PublicKey, grant *stage2aSignedCandidateGrantV3) (stage2aReservation, stage2aReservationWorkerReplyV3, error) {
	var empty stage2aReservation
	var reply stage2aReservationWorkerReplyV3
	if os.Getuid() < 400 || os.Getuid() != os.Geteuid() || len(key) != ed25519.PublicKeySize || selector.HQEpoch != epoch ||
		trustedPath(OSHost{}, SoulLauncher, false) != nil || checkDarwinACLs(pathAncestry(SoulLauncher)) != nil {
		return empty, reply, errStage2aReservationAuthority
	}
	request, err := json.Marshal(selector)
	if err != nil {
		return empty, reply, err
	}
	payload, err := json.Marshal(stage2aReservationWorkerRequestV3{HQUID: hqUID,
		MachineFingerprint: fmt.Sprintf("%x", sha256.Sum256(key)), Selector: request, CandidateGrant: grant})
	if err != nil {
		return empty, reply, err
	}
	if _, _, err := decodeStage2aReservationWorkerRequestV3(payload); err != nil {
		return empty, reply, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", stage2aInstallSealProfile, SoulLauncher, stage2aReservationWorkerCommandV3)
	cmd.Dir, cmd.Env, cmd.Stdin = "/", []string{"PATH=/usr/bin:/bin"}, bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil || len(out) > stage2aReservationWorkerReplyLimitV3 || stage2aStrictJSONBounded(out, stage2aReservationWorkerReplyLimitV3, 8192) != nil {
		return empty, reply, errStage2aReservationAuthority
	}
	if stage2aDecodeExact(out, &reply) != nil || !stage2aPrefixedDigest.MatchString(reply.PolicyDigest) {
		return empty, reply, errStage2aReservationAuthority
	}
	envelope, err := decodeStage2aRoleBase64(reply.EnvelopeBase64URL, stage2aV3EnvelopeLimit)
	if err != nil {
		return empty, reply, errStage2aReservationAuthority
	}
	if _, err := verifyStage2aReservationModeV3(reply.Mode, envelope, reply.SHA256, reply.Expected, key, time.Now()); err != nil {
		return empty, reply, err
	}
	return stage2aReservation{envelope: envelope, sha256: reply.SHA256}, reply, nil
}
