package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const candidateReservationPurposeV3 = "agent-bot/stage2a-qualification-candidate-reservation/v3"

// candidateReportJoinV3 authenticates and compares the candidate reservation
// and the host report summary. It is not an approval-spend, installed-byte,
// physical-gate or release verifier.
func candidateReportJoinV3(reportRaw, reservationEnvelope []byte,
	machineKey ed25519.PublicKey) (candidateMeasurementBindingV3, error) {
	var zero candidateMeasurementBindingV3
	if len(machineKey) != ed25519.PublicKeySize {
		return zero, ErrUnqualified
	}
	payload, err := qSignedRecordV3(reservationEnvelope, candidateReservationPurposeV3, 3, machineKey)
	if err != nil {
		return zero, ErrUnqualified
	}
	p, err := canonicalBytes(payload, 48<<10)
	if err != nil || !hasFields(p, "contract", "kind", "schema_version", "host_id",
		"issued_at", "expires_at", "installed_plan_receipt_sha256", "assignment",
		"member_endpoint", "measurement_binding", "admission_challenge_sha256",
		"qualification_attempt") || string(p["contract"]) != `"machine/v3"` ||
		string(p["kind"]) != `"stage2a-qualification-candidate-reservation"` ||
		string(p["schema_version"]) != "3" {
		return zero, ErrUnqualified
	}
	binding, err := parseCandidateMeasurementBindingV3(p["measurement_binding"])
	if err != nil {
		return zero, ErrUnqualified
	}
	var reservation struct {
		HostID                     string `json:"host_id"`
		IssuedAt                   string `json:"issued_at"`
		ExpiresAt                  string `json:"expires_at"`
		InstalledPlanReceiptSHA256 string `json:"installed_plan_receipt_sha256"`
		AdmissionChallengeSHA256   string `json:"admission_challenge_sha256"`
		Assignment                 struct {
			InstallationID    string `json:"installation_id"`
			SoulID            string `json:"soul_id"`
			StartID           string `json:"start_id"`
			LaunchID          string `json:"launch_id"`
			HQEpoch           string `json:"hq_epoch"`
			PlanID            string `json:"plan_id"`
			PlanDigest        string `json:"plan_digest"`
			PackageSHA256     string `json:"package_sha256"`
			HDescriptorDigest string `json:"h_service_descriptor_digest"`
			RInventoryDigest  string `json:"r_inventory_digest"`
		} `json:"assignment"`
		Attempt struct {
			ApprovalPlanID             string `json:"approval_plan_id"`
			ApprovalPlanDigest         string `json:"approval_plan_digest"`
			QualificationRequestSHA256 string `json:"qualification_request_sha256"`
			AttemptReceiptSHA256       string `json:"attempt_receipt_sha256"`
			TestPlanSHA256             string `json:"test_plan_sha256"`
			SuiteRevision              string `json:"suite_revision"`
			ApprovalExpiresAt          string `json:"approval_expires_at"`
			NetworkMode                string `json:"network_mode"`
		} `json:"qualification_attempt"`
	}
	if json.Unmarshal(payload, &reservation) != nil ||
		reservation.HostID != binding.Base.HostID ||
		!validSHA(reservation.InstalledPlanReceiptSHA256) ||
		!validSHA(reservation.AdmissionChallengeSHA256) ||
		reservation.Assignment.InstallationID != binding.Base.InstallationID ||
		reservation.Assignment.SoulID != binding.Base.SoulID ||
		reservation.Assignment.StartID != binding.Base.StartID ||
		reservation.Assignment.LaunchID != binding.Base.LaunchID ||
		reservation.Assignment.HQEpoch != binding.Base.HQEpoch ||
		reservation.Assignment.PlanID != binding.Base.PlanID ||
		reservation.Assignment.PlanDigest != binding.Base.InstalledPlanDigest ||
		reservation.Assignment.PackageSHA256 != binding.Base.PackageSHA256 ||
		reservation.Assignment.HDescriptorDigest != binding.HServiceDescriptorDigest ||
		reservation.Assignment.RInventoryDigest != binding.RInventory.InventoryDigest ||
		!validSHA(reservation.Attempt.QualificationRequestSHA256) ||
		!validSHA(reservation.Attempt.AttemptReceiptSHA256) ||
		!validSHA(reservation.Attempt.TestPlanSHA256) ||
		len(reservation.Attempt.SuiteRevision) != 40 ||
		!qLowerHexV3(reservation.Attempt.SuiteRevision) ||
		reservation.Attempt.NetworkMode != "local-test-provider-only" {
		return zero, ErrUnqualified
	}
	attempt, err := strictObject(p["qualification_attempt"], 48<<10)
	if err != nil || !hasFields(attempt, "approval_plan_id", "approval_plan_digest",
		"qualification_request_sha256", "attempt_receipt_sha256", "test_plan_sha256",
		"suite_revision", "approval_expires_at", "network_mode") {
		return zero, ErrUnqualified
	}
	issued, e1 := parseTime(reservation.IssuedAt)
	expires, e2 := parseTime(reservation.ExpiresAt)
	approvalExpires, e3 := parseTime(reservation.Attempt.ApprovalExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !expires.After(issued) ||
		expires.Sub(issued) > 30*time.Second || expires.After(approvalExpires) {
		return zero, ErrUnqualified
	}
	report, err := strictObject(reportRaw, MaxReportBytes)
	if err != nil || !bytes.Equal(report["measurement_binding"], binding.ReportProjection) ||
		string(report["profile_in_force"]) != `"managed-protected"` ||
		string(report["suite_revision"]) != `"`+reservation.Attempt.SuiteRevision+`"` {
		return zero, ErrUnqualified
	}
	// The full protected report supplies these principals. A compact producer
	// summary may omit bridge/host, but the public host-report shape requires
	// both and this join then binds the R reader to the actual runner account.
	if hostRaw, present := report["host"]; present {
		var host struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(hostRaw, &host) != nil || host.ID != binding.Base.HostID {
			return zero, ErrUnqualified
		}
	}
	if bridgeRaw, present := report["bridge"]; present {
		var bridge struct {
			Principals struct {
				MachineUID       uint32 `json:"machine_uid"`
				RunnerUID        uint32 `json:"runner_uid"`
				RunnerPrivateGID uint32 `json:"runner_private_gid"`
			} `json:"principals"`
		}
		if json.Unmarshal(bridgeRaw, &bridge) != nil ||
			bridge.Principals.MachineUID != binding.RInventory.MachineUID ||
			bridge.Principals.RunnerUID != binding.RInventory.ReaderUID ||
			bridge.Principals.RunnerPrivateGID != binding.RInventory.ReaderGID {
			return zero, ErrUnqualified
		}
	}
	var recordedAt string
	if json.Unmarshal(report["recorded_at"], &recordedAt) != nil {
		return zero, ErrUnqualified
	}
	recorded, err := parseTime(recordedAt)
	if err != nil || recorded.Before(issued) {
		return zero, ErrUnqualified
	}
	run, err := strictObject(report["run_evidence"], MaxReportBytes)
	if err != nil {
		return zero, ErrUnqualified
	}
	var reservationRef reportReference
	var challenge string
	if json.Unmarshal(run["reservation"], &reservationRef) != nil ||
		json.Unmarshal(run["challenge_sha256"], &challenge) != nil ||
		reservationRef.SHA256 != digest(reservationEnvelope) ||
		challenge != reservation.AdmissionChallengeSHA256 {
		return zero, ErrUnqualified
	}
	var adapter struct {
		PackageSHA256 string `json:"package_sha256"`
	}
	var launch struct {
		Executable       string `json:"executable"`
		ExecutableSHA256 string `json:"executable_sha256"`
		CodeInputs       []struct {
			Path string `json:"path"`
		} `json:"code_inputs"`
	}
	if json.Unmarshal(report["adapter"], &adapter) != nil ||
		json.Unmarshal(report["launch"], &launch) != nil ||
		adapter.PackageSHA256 != binding.CandidateAdapter.PackageSHA256 ||
		launch.Executable != binding.CandidateAdapter.ExecutablePath ||
		launch.ExecutableSHA256 != binding.CandidateAdapter.ExecutableSHA256 ||
		len(launch.CodeInputs) != binding.CandidateAdapter.CodeInputCount {
		return zero, ErrUnqualified
	}
	paths := make([]string, 0, len(launch.CodeInputs))
	previous := ""
	for _, input := range launch.CodeInputs {
		if !reportPath(input.Path) ||
			!strings.HasPrefix(input.Path, binding.RInventory.Snapshot.Path+"/") ||
			input.Path <= previous {
			return zero, ErrUnqualified
		}
		paths = append(paths, input.Path)
		previous = input.Path
	}
	pathJSON, err := json.Marshal(paths)
	if err != nil {
		return zero, ErrUnqualified
	}
	pathJCS, err := jsoncanonicalizer.Transform(pathJSON)
	if err != nil || digest(preimage("agent-bot/stage2a-adapter-code-inputs/v3", pathJCS)) !=
		binding.CandidateAdapter.CodeInputsDigest {
		return zero, ErrUnqualified
	}
	return binding, nil
}

// CheckCandidateHostReportReservationV3 authenticates the designated host
// signature and distinct A reservation before comparing their exact bytes.
// It grants no ordinary protected launch or qualification acceptance.
func CheckCandidateHostReportReservationV3(hostEnvelope, reservationEnvelope []byte,
	policy VerifiedPolicy, machineKey ed25519.PublicKey, now time.Time) error {
	report, err := VerifyHostReportV3(hostEnvelope, policy, now)
	if err != nil {
		return ErrUnqualified
	}
	_, err = candidateReportJoinV3(report, reservationEnvelope, machineKey)
	return err
}
