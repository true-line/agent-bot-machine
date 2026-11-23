package members

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

const stage2aQualificationCandidatePurposeV3 = "agent-bot/stage2a-qualification-candidate-reservation/v3"

type stage2aQualificationCandidateAdapterV3 struct {
	ComponentID             string `json:"component_id"`
	PackageSHA256           string `json:"package_sha256"`
	ExecutablePath          string `json:"executable_path"`
	ExecutableSHA256        string `json:"executable_sha256"`
	CodeInputsDigest        string `json:"code_inputs_digest"`
	CodeInputCount          int    `json:"code_input_count"`
	CandidateManifestSHA256 string `json:"candidate_manifest_sha256"`
}

type stage2aQualificationCandidateAttemptV3 struct {
	ApprovalPlanID             string `json:"approval_plan_id"`
	ApprovalPlanDigest         string `json:"approval_plan_digest"`
	QualificationRequestSHA256 string `json:"qualification_request_sha256"`
	AttemptReceiptSHA256       string `json:"attempt_receipt_sha256"`
	TestPlanSHA256             string `json:"test_plan_sha256"`
	SuiteRevision              string `json:"suite_revision"`
	ApprovalExpiresAt          string `json:"approval_expires_at"`
	NetworkMode                string `json:"network_mode"`
}

type stage2aQualificationCandidateBindingV3 struct {
	Stage2aMeasurementBinding
	HDescriptorDigest string                                 `json:"h_service_descriptor_digest"`
	RInventory        stage2aDomainInventoryRefV3            `json:"r_inventory"`
	RComponents       []stage2aHReleaseComponentV3           `json:"r_components"`
	Broker            stage2aReservationBrokerV3             `json:"broker_executable"`
	Candidate         stage2aQualificationCandidateAdapterV3 `json:"candidate_adapter"`
}

type stage2aQualificationCandidateReservationV3 struct {
	Contract                   string                                 `json:"contract"`
	Kind                       string                                 `json:"kind"`
	SchemaVersion              int                                    `json:"schema_version"`
	HostID                     string                                 `json:"host_id"`
	IssuedAt                   string                                 `json:"issued_at"`
	ExpiresAt                  string                                 `json:"expires_at"`
	InstalledPlanReceiptSHA256 string                                 `json:"installed_plan_receipt_sha256"`
	Assignment                 stage2aReservationAssignmentV3         `json:"assignment"`
	MemberEndpoint             SoulMemberLaunchAssignment             `json:"member_endpoint"`
	MeasurementBinding         stage2aQualificationCandidateBindingV3 `json:"measurement_binding"`
	AdmissionChallengeSHA256   string                                 `json:"admission_challenge_sha256"`
	Attempt                    stage2aQualificationCandidateAttemptV3 `json:"qualification_attempt"`
}

// Only the secure A authority loader can supply these local records. No
// candidate data belongs in the paired HQ reservation request. Keep this
// seam out of the normal protected loader and the released adapter cache.
type stage2aQualificationCandidateAuthorityV3 struct {
	base                                                stage2aReservationEvidenceV3
	approval                                            Approval
	saved                                               Saved
	owner, testPlanSHA                                  string
	archive                                             stage2aVerifiedCandidateArchiveV3
	candidateComponent                                  string
	approvedInstallationID, approvedInstalledPlanDigest string
	stateDirectory                                      string
}

// The Q approval path writes one immutable 0600 attempt in A's private
// daemon state. Reopen it relative to an independently checked descriptor.
func readStage2aCandidateSpentAttemptV3(state, planID, planDigest string, uid uint32) ([]byte, error) {
	const limit = 8192
	gid := uint32(os.Getgid())
	if !stage2aAbsolutePath(state) || !ValidApproval(planID, planDigest) ||
		uid < 400 || uint32(os.Getuid()) != uid || uint32(os.Geteuid()) != uid || uint32(os.Getegid()) != gid {
		return nil, errStage2aReservationAuthority
	}
	dir, err := openStage2aAdminDirectory(filepath.Join(state, "qualification-attempts"), uid)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if checkStage2aReservationFile(int(dir.Fd()), uid, gid, unix.S_IFDIR|0700) != nil {
		return nil, errStage2aReservationAuthority
	}
	name := planID + ".qualification.json"
	fd, err := unix.Openat(int(dir.Fd()), name, stage2aFileOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if checkStage2aReservationFile(fd, uid, gid, unix.S_IFREG|0600) != nil ||
		checkDarwinACLs([]string{filepath.Join(dir.Name(), name)}) != nil {
		return nil, errStage2aReservationAuthority
	}
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Size <= 0 || before.Size > limit {
		return nil, errStage2aReservationAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || !stage2aSameNode(before, after) {
		return nil, errStage2aReservationAuthority
	}
	return raw, nil
}

func stage2aCandidateAttemptV3(a stage2aQualificationCandidateAuthorityV3, issued time.Time) (stage2aQualificationCandidateAttemptV3, error) {
	var empty stage2aQualificationCandidateAttemptV3
	run := a.saved.QualificationRun
	if run == nil || a.approvedInstallationID != a.base.r.ref.InstallationID ||
		a.approvedInstalledPlanDigest != a.base.base.binding.InstalledPlanDigest ||
		a.approval.PlanID != a.saved.PlanID || a.approval.PlanDigest != a.saved.PlanDigest ||
		!stage2aAbsolutePath(a.stateDirectory) || !stage2aPrefixedDigest.MatchString(a.testPlanSHA) ||
		!qualificationRevision.MatchString(run.Request.SuiteRevision) || run.Request.Host.ID != a.base.base.hostID ||
		run.Request.Target.Account != a.base.base.runner.Account || run.Request.Target.UID != a.base.base.runner.UID {
		return empty, errStage2aReservationAuthority
	}
	raw, err := readStage2aCandidateSpentAttemptV3(a.stateDirectory, a.saved.PlanID, a.saved.PlanDigest, uint32(a.base.base.machineUID))
	var spent QualificationAttempt
	if err != nil || len(raw) > 8192 || stage2aDecodeExact(raw, &spent) != nil {
		return empty, errStage2aReservationAuthority
	}
	started, err := time.Parse(approvalTime, spent.StartedAt)
	expected, expectedErr := newQualificationAttempt(a.approval, run, a.owner, started)
	approvalExpiry, expiryErr := time.Parse(approvalTime, a.approval.ExpiresAt)
	if err != nil || expectedErr != nil || expiryErr != nil || expected != spent ||
		issued.Before(started) || !issued.Before(approvalExpiry) || a.base.base.expires.After(approvalExpiry) {
		return empty, errStage2aReservationAuthority
	}
	return stage2aQualificationCandidateAttemptV3{ApprovalPlanID: spent.PlanID,
		ApprovalPlanDigest: spent.PlanDigest, QualificationRequestSHA256: "sha256:" + spent.RequestSHA256,
		AttemptReceiptSHA256: stage2aReservationSHA256(raw), TestPlanSHA256: a.testPlanSHA,
		SuiteRevision: run.Request.SuiteRevision, ApprovalExpiresAt: a.approval.ExpiresAt,
		NetworkMode: "local-test-provider-only"}, nil
}

func stage2aCandidateAdapterV3(a stage2aQualificationCandidateAuthorityV3) (stage2aQualificationCandidateAdapterV3, error) {
	var empty stage2aQualificationCandidateAdapterV3
	r := a.base.r.ref
	request := a.saved.QualificationRun.Request
	if !stage2aBindingID.MatchString(request.Adapter.ID) ||
		a.archive.componentID != a.candidateComponent || a.archive.packageSHA256 != "sha256:"+request.Adapter.PackageSHA ||
		a.archive.inventoryDigest != r.InventoryDigest ||
		"sha256:"+request.TestProvider.ConfigSHA != a.base.broker.ProviderConfigSHA256 {
		return empty, errStage2aReservationAuthority
	}
	adapter := request.Adapter
	var manifest string
	for _, pin := range a.base.rComponents {
		if pin.ComponentID == a.candidateComponent && pin.ReleaseArtifactSHA256 == "sha256:"+adapter.PackageSHA {
			manifest = pin.ReleaseManifestSHA256
		}
	}
	rows := make(map[string]stage2aDomainFileV3)
	for _, row := range a.base.rInventory.Files {
		if row.ComponentID == a.candidateComponent {
			rows[filepath.Join(r.Snapshot.Path, row.Path)] = row
		}
	}
	exec := rows[adapter.Launch.Executable]
	if !stage2aPrefixedDigest.MatchString(manifest) || manifest != a.archive.manifestSHA256 || exec.Mode != "0550" ||
		exec.SHA256 != "sha256:"+adapter.Launch.ExecutableSHA ||
		len(adapter.Launch.CodeInputs) == 0 || len(adapter.Launch.CodeInputs) > 512 ||
		adapter.PackageSHA == a.base.base.binding.PackageSHA256 {
		return empty, errStage2aReservationAuthority
	}
	paths := make([]string, 0, len(adapter.Launch.CodeInputs))
	previous := ""
	for _, input := range adapter.Launch.CodeInputs {
		if input.Path <= previous || rows[input.Path].SHA256 != "sha256:"+input.SHA256 {
			return empty, errStage2aReservationAuthority
		}
		paths = append(paths, input.Path)
		previous = input.Path
	}
	canonical, err := marshalStage2aReservationJCS(paths)
	if err != nil {
		return empty, errStage2aReservationAuthority
	}
	return stage2aQualificationCandidateAdapterV3{
		ComponentID: a.candidateComponent, PackageSHA256: "sha256:" + adapter.PackageSHA,
		ExecutablePath: adapter.Launch.Executable, ExecutableSHA256: exec.SHA256, CodeInputCount: len(paths),
		CodeInputsDigest:        stage2aV3PurposeDigest("agent-bot/stage2a-adapter-code-inputs/v3", canonical),
		CandidateManifestSHA256: manifest,
	}, nil
}

func prepareStage2aQualificationCandidateV3(req stage2aReservationRequest,
	a stage2aQualificationCandidateAuthorityV3, now time.Time) (stage2aQualificationCandidateReservationV3, error) {
	var empty stage2aQualificationCandidateReservationV3
	common, err := prepareStage2aReservationHREvidenceV3(req, a.base, now)
	if err != nil {
		return empty, err
	}
	attempt, err := stage2aCandidateAttemptV3(a, now)
	if err != nil {
		return empty, err
	}
	candidate, err := stage2aCandidateAdapterV3(a)
	if err != nil {
		return empty, err
	}
	base := common.base
	binding := base.MeasurementBinding
	binding.Kind = "stage2a-qualification-candidate-binding"
	return stage2aQualificationCandidateReservationV3{
		Contract: "machine/v3", Kind: "stage2a-qualification-candidate-reservation", SchemaVersion: 3,
		HostID: base.HostID, IssuedAt: base.IssuedAt, ExpiresAt: base.ExpiresAt,
		InstalledPlanReceiptSHA256: base.InstalledPlanReceiptSHA256, Assignment: stage2aReservationAssignmentV3{base.Assignment, common.descriptorDigest, common.r.InventoryDigest},
		MemberEndpoint: base.MemberEndpoint, AdmissionChallengeSHA256: base.AdmissionChallengeSHA256,
		MeasurementBinding: stage2aQualificationCandidateBindingV3{
			Stage2aMeasurementBinding: binding,
			HDescriptorDigest:         common.descriptorDigest, RInventory: common.r,
			RComponents: a.base.rComponents, Broker: a.base.broker, Candidate: candidate,
		}, Attempt: attempt,
	}, nil
}

func verifyStage2aQualificationCandidateV3(raw []byte, digest string, expected stage2aQualificationCandidateReservationV3,
	key ed25519.PublicKey, now time.Time) error {
	payload, _, err := verifyStage2aV3Envelope(raw, stage2aQualificationCandidatePurposeV3, key)
	var decoded stage2aQualificationCandidateReservationV3
	if err != nil || stage2aReservationSHA256(raw) != digest ||
		stage2aDecodeExact(payload, &decoded) != nil || !reflect.DeepEqual(decoded, expected) {
		return errStage2aReservationAuthority
	}
	canonical, err := marshalStage2aReservationJCS(expected)
	issued, issuedErr := time.Parse(time.RFC3339Nano, expected.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, expected.ExpiresAt)
	approvalExpiry, approvalErr := time.Parse(approvalTime, expected.Attempt.ApprovalExpiresAt)
	if err != nil || !bytes.Equal(payload, canonical) || issuedErr != nil || expiryErr != nil || approvalErr != nil ||
		now.Before(issued) || !now.Before(expires) || expires.Sub(issued) > 30*time.Second || expires.After(approvalExpiry) {
		return errStage2aReservationAuthority
	}
	return nil
}

// A distinct durable attempt/profile claim prevents replay with a fresh
// start ID. Reserve and sign within A's existing per-installation lock. A
// failed signature or uncertain publication leaves both claims spent.
func reserveStage2aQualificationCandidateV3(store stage2aAdminClaimStore, req stage2aReservationRequest,
	load func(stage2aReservationRequest) (stage2aQualificationCandidateAuthorityV3, error),
	sign func([]byte) ([]byte, error), now func() time.Time) (stage2aReservation, error) {
	var result stage2aReservation
	if load == nil || sign == nil || now == nil || !stage2aInstallSealNoIP() {
		return result, errStage2aReservationAuthority
	}
	var a stage2aQualificationCandidateAuthorityV3
	var expected stage2aQualificationCandidateReservationV3
	var id string
	err := stage2aAdminSpend(store, req, func() error {
		var err error
		a, err = load(req)
		if err != nil || uint32(a.base.base.machineUID) != store.uid ||
			stage2aRecheckVerifiedDomainV3(a.base.h) != nil || stage2aRecheckVerifiedDomainV3(a.base.r) != nil {
			return errStage2aReservationAuthority
		}
		expected, err = prepareStage2aQualificationCandidateV3(req, a, now())
		if err != nil {
			return err
		}
		id = ".stage2a-candidate-protected-" + expected.Attempt.ApprovalPlanDigest
		return nil
	}, func(dir *os.File) error {
		active := stage2aActiveClaimName(req.start.InstallationID)
		if requireUnspentStage2aReservation(dir, active) != nil || requireUnspentStage2aReservation(dir, id) != nil ||
			!now().Before(a.base.base.expires) {
			return errStage2aReservationAuthority
		}
		if err := spendStage2aAdminName(dir, id, store.uid, store.gid); err != nil {
			return err
		}
		if err := spendStage2aAdminName(dir, active, store.uid, store.gid); err != nil {
			return err
		}
		canonical, err := marshalStage2aReservationJCS(expected)
		if err != nil {
			return err
		}
		raw, _, err := signStage2aVerifiedEnvelopeV3(stage2aVerifiedSigningPayloadV3{
			verified: true, purpose: stage2aQualificationCandidatePurposeV3,
			payload: canonical, machineUID: store.uid, machineGID: store.gid,
		}, a.base.base.enrolledAdminKey, sign)
		if err != nil {
			return err
		}
		digest := stage2aReservationSHA256(raw)
		if err := verifyStage2aQualificationCandidateV3(raw, digest, expected, a.base.base.enrolledAdminKey, now()); err != nil {
			return err
		}
		name := ".stage2a-candidate-envelope-" + soulStartClaimName(req.start.InstallationID, req.start.StartID)
		if err := commitStage2aReservation(dir, name, raw); err != nil {
			return err
		}
		result = stage2aReservation{envelope: raw, sha256: digest}
		return nil
	})
	if err != nil {
		return stage2aReservation{}, err
	}
	return result, nil
}
