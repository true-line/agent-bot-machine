package qualification

import (
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"time"
)

const physicalSegmentPurposeV3 = "agent-bot/stage2a-physical-segment/v1"

var (
	physicalLaunchIDV3 = regexp.MustCompile(`^ln_[0-9a-f]{24}$`)
	physicalPlanIDV3   = regexp.MustCompile(`^plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$`)
)

var protectedSegmentRolesV3 = []string{
	"reservation", "b_finalization", "stop", "q_wire", "q_index", "q_eof",
	"owner_acp_to_hq", "hq_acp_to_owner", "os_observation", "installed_inputs",
}

type physicalSegmentV3 struct {
	SchemaVersion            int                        `json:"schema_version"`
	Kind                     string                     `json:"kind"`
	Gate                     string                     `json:"gate"`
	Profile                  string                     `json:"profile"`
	HostID                   string                     `json:"host_id"`
	CohortID                 string                     `json:"cohort_id"`
	SuiteRevision            string                     `json:"suite_revision"`
	OwnerPlanSHA256          string                     `json:"owner_plan_sha256"`
	SegmentID                string                     `json:"segment_id"`
	Purpose                  string                     `json:"purpose"`
	ReportAnchor             bool                       `json:"report_anchor"`
	TerminalState            string                     `json:"terminal_state"`
	InstallationID           string                     `json:"installation_id"`
	SoulID                   string                     `json:"soul_id"`
	StartID                  string                     `json:"start_id"`
	LaunchID                 string                     `json:"launch_id"`
	MeasurementBindingSHA256 string                     `json:"measurement_binding_sha256"`
	QSessionStatus           string                     `json:"q_session_status"`
	QSessionID               string                     `json:"q_session_id"`
	QChallengeSHA256         string                     `json:"q_challenge_sha256"`
	Artifacts                map[string]gateObjectRefV3 `json:"artifacts"`
}

// ResolvedProtectedSegmentChainV3 authenticates the A-signed completed-start
// object links and exact local bytes. ACP/OS custody, installed-byte
// measurement, required negative cases and gate outcome remain unchecked.
type ResolvedProtectedSegmentChainV3 struct {
	resolved                                                                         bool
	binding                                                                          measurementBinding
	cohortBindingSHA256                                                              string
	reportBindingSHA256                                                              string
	Gate, SegmentID, CohortID, InstallationID, SoulID, StartID, LaunchID, QSessionID string
	ManifestSHA256, AttestationSHA256, MeasurementBindingSHA256                      string
	QIndexSHA256, QEOFReceiptSHA256                                                  string
	ReservationSHA256, FinalizationSHA256, LaunchChallengeSHA256                     string
}

func physicalSegmentObjectV3(root string, ref gateObjectRefV3, role string, max int64) ([]byte, error) {
	if ref.Role != role || ref.Issuer != "machine-a" || ref.SizeBytes <= 0 || ref.SizeBytes > max {
		return nil, ErrUnqualified
	}
	raw, err := ResolveGateObjectV3(root, ref.URI, ref.SHA256, max)
	if err != nil || int64(len(raw)) != ref.SizeBytes {
		return nil, ErrUnqualified
	}
	return raw, nil
}

func parseProtectedSegmentV3(raw []byte, gate gateManifestV3, segment gateSegmentV3) (physicalSegmentV3, error) {
	var out physicalSegmentV3
	f, err := canonicalBytes(raw, maxGateManifestBytesV3)
	if err != nil || !hasFields(f, "schema_version", "kind", "gate", "profile", "host_id", "cohort_id", "suite_revision", "owner_plan_sha256", "segment_id", "purpose", "report_anchor", "terminal_state", "installation_id", "soul_id", "start_id", "launch_id", "measurement_binding_sha256", "q_session_status", "q_session_id", "q_challenge_sha256", "artifacts") || json.Unmarshal(raw, &out) != nil ||
		out.SchemaVersion != 1 || out.Kind != "stage2a-physical-segment" || out.Gate != gate.Gate || out.Profile != "managed-protected" || out.Profile != gate.Profile || out.HostID != gate.HostID || out.CohortID != gate.CohortID || out.SuiteRevision != gate.SuiteRevision || out.OwnerPlanSHA256 != gate.OwnerPlanSHA256 || out.SegmentID != segment.SegmentID || out.Purpose != segment.Purpose || out.ReportAnchor != segment.ReportAnchor || out.TerminalState != "stopped" || out.QSessionStatus != "completed" || !qInstallationV3.MatchString(out.InstallationID) || !qSoulV3.MatchString(out.SoulID) || !qStartV3.MatchString(out.StartID) || !physicalLaunchIDV3.MatchString(out.LaunchID) || !validSHA(out.MeasurementBindingSHA256) || len(out.QSessionID) != 32 || !qLowerHexV3(out.QSessionID) || !validSHA(out.QChallengeSHA256) {
		return physicalSegmentV3{}, ErrUnqualified
	}
	if out.SegmentID == gate.PrimarySegmentID && out.MeasurementBindingSHA256 != gate.PrimaryMeasurementBindingSHA256 {
		return physicalSegmentV3{}, ErrUnqualified
	}
	if out.ReportAnchor && out.SegmentID != gate.PrimarySegmentID {
		return physicalSegmentV3{}, ErrUnqualified
	}
	objects, err := strictObject(f["artifacts"], maxGateManifestBytesV3)
	if err != nil || !hasFields(objects, protectedSegmentRolesV3...) || len(out.Artifacts) != len(protectedSegmentRolesV3) {
		return physicalSegmentV3{}, ErrUnqualified
	}
	seen := map[string]bool{}
	for _, role := range protectedSegmentRolesV3 {
		ref, err := parseGateObjectRefV3(objects[role])
		if err != nil || ref.Role != role || ref.Issuer != "machine-a" || ref.SizeBytes <= 0 || seen[ref.SHA256] {
			return physicalSegmentV3{}, ErrUnqualified
		}
		seen[ref.SHA256] = true
	}
	return out, nil
}

func segmentRoleMaxV3(role string) int64 {
	switch role {
	case "reservation", "b_finalization", "stop", "q_index", "q_eof":
		return 64 << 10
	case "q_wire":
		return 32 << 20
	case "os_observation", "installed_inputs":
		return 1 << 20
	default:
		return maxGateBlobBytesV3
	}
}

type protectedAChainV3 struct {
	binding               measurementBinding
	cohortBindingSHA256   string
	reportBindingSHA256   string
	reservationSHA256     string
	finalizationSHA256    string
	stopSHA256            string
	launchChallengeSHA256 string
	stopAt                time.Time
}

func verifyProtectedAChainV3(reservation, finalization, stop []byte,
	segment physicalSegmentV3, key ed25519.PublicKey) (protectedAChainV3, error) {
	var zero protectedAChainV3
	raw, purpose, err := qReservationRecordV3(reservation, key)
	if err != nil {
		return zero, ErrUnqualified
	}
	var reserved struct {
		HostID                   string `json:"host_id"`
		IssuedAt                 string `json:"issued_at"`
		ExpiresAt                string `json:"expires_at"`
		AdmissionChallengeSHA256 string `json:"admission_challenge_sha256"`
		Assignment               struct {
			InstallationID    string `json:"installation_id"`
			SoulID            string `json:"soul_id"`
			StartID           string `json:"start_id"`
			LaunchID          string `json:"launch_id"`
			PlanID            string `json:"plan_id"`
			PlanDigest        string `json:"plan_digest"`
			HQEpoch           string `json:"hq_epoch"`
			RunnerUID         int    `json:"runner_uid"`
			BridgeUID         int    `json:"bridge_uid"`
			HDescriptorDigest string `json:"h_service_descriptor_digest"`
			RInventoryDigest  string `json:"r_inventory_digest"`
		} `json:"assignment"`
		MeasurementBinding json.RawMessage `json:"measurement_binding"`
	}
	if json.Unmarshal(raw, &reserved) != nil || reserved.HostID != segment.HostID || reserved.Assignment.InstallationID != segment.InstallationID || reserved.Assignment.SoulID != segment.SoulID || reserved.Assignment.StartID != segment.StartID || reserved.Assignment.LaunchID != segment.LaunchID || !physicalPlanIDV3.MatchString(reserved.Assignment.PlanID) || !validHex(reserved.Assignment.PlanDigest, 64) || !validHex(reserved.Assignment.HQEpoch, 64) || reserved.Assignment.RunnerUID < 300 || reserved.Assignment.RunnerUID > 399 || reserved.Assignment.BridgeUID < 300 || reserved.Assignment.BridgeUID > 399 || reserved.Assignment.RunnerUID == reserved.Assignment.BridgeUID || reserved.AdmissionChallengeSHA256 == segment.QChallengeSHA256 || !validSHA(reserved.AdmissionChallengeSHA256) || digest(reserved.MeasurementBinding) != segment.MeasurementBindingSHA256 {
		return zero, ErrUnqualified
	}
	var binding measurementBinding
	var hDescriptorDigest, rInventoryDigest string
	var rReaderUID uint32
	switch purpose {
	case qReservationPurposeV3:
		binding, err = parseMeasurementBindingV2(reserved.MeasurementBinding)
	case qOrdinaryReservationPurposeV3:
		var v3 hrMeasurementBindingV3
		v3, err = parseHRMeasurementBindingV3(reserved.MeasurementBinding)
		binding = v3.Base
		hDescriptorDigest, rInventoryDigest, rReaderUID = v3.HServiceDescriptorDigest, v3.RInventory.InventoryDigest, v3.RInventory.ReaderUID
	case qCandidateReservationPurposeV3:
		var v3 candidateMeasurementBindingV3
		v3, err = parseCandidateMeasurementBindingV3(reserved.MeasurementBinding)
		binding = v3.Base
		hDescriptorDigest, rInventoryDigest, rReaderUID = v3.HServiceDescriptorDigest, v3.RInventory.InventoryDigest, v3.RInventory.ReaderUID
	}
	if err != nil || !validHex(binding.SoulArtifactSHA256, 64) || binding.InstallationID != segment.InstallationID || binding.SoulID != segment.SoulID || binding.StartID != segment.StartID || binding.LaunchID != segment.LaunchID || binding.HostID != segment.HostID || binding.ProfileInForce != segment.Profile || binding.PlanID != reserved.Assignment.PlanID || binding.InstalledPlanDigest != reserved.Assignment.PlanDigest || binding.HQEpoch != reserved.Assignment.HQEpoch {
		return zero, ErrUnqualified
	}
	if purpose != qReservationPurposeV3 &&
		(reserved.Assignment.HDescriptorDigest != hDescriptorDigest || reserved.Assignment.RInventoryDigest != rInventoryDigest ||
			reserved.Assignment.RunnerUID != int(rReaderUID)) {
		return zero, ErrUnqualified
	}
	finalRaw, err := qSignedRecordV3(finalization, "agent-bot/stage2a-finalization/v1", 1, key)
	if err != nil {
		return zero, ErrUnqualified
	}
	stopRaw, err := qSignedRecordV3(stop, "agent-bot/stage2a-stop/v1", 1, key)
	if err != nil {
		return zero, ErrUnqualified
	}
	finalFields, err := strictObject(finalRaw, 48<<10)
	if err != nil || !hasFields(finalFields, "schema", "reservation_sha256", "installation_id", "start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch", "bind_receipt_sha256", "relay_socket", "bridge_pid", "finalized_at") {
		return zero, ErrUnqualified
	}
	stopFields, err := strictObject(stopRaw, 48<<10)
	stopNames := []string{"schema", "reservation_sha256", "installation_id", "start_id", "launch_id", "plan_id", "plan_digest", "hq_epoch", "runner_uid", "bridge_uid", "runner_pid", "bridge_pid", "both_uids_idle", "stopped_at"}
	hasChildReceipt := len(stopFields) != len(stopNames)
	if hasChildReceipt {
		stopNames = append(stopNames, "child_launcher_pid", "child_pid", "child_receipt_sha256")
	}
	if err != nil || !hasFields(stopFields, stopNames...) {
		return zero, ErrUnqualified
	}
	var finalized struct {
		Schema            string `json:"schema"`
		ReservationSHA256 string `json:"reservation_sha256"`
		InstallationID    string `json:"installation_id"`
		StartID           string `json:"start_id"`
		LaunchID          string `json:"launch_id"`
		PlanID            string `json:"plan_id"`
		PlanDigest        string `json:"plan_digest"`
		HQEpoch           string `json:"hq_epoch"`
		BridgePID         int    `json:"bridge_pid"`
		BindReceiptSHA256 string `json:"bind_receipt_sha256"`
		FinalizedAt       string `json:"finalized_at"`
	}
	var stopped struct {
		Schema             string `json:"schema"`
		ReservationSHA256  string `json:"reservation_sha256"`
		InstallationID     string `json:"installation_id"`
		StartID            string `json:"start_id"`
		LaunchID           string `json:"launch_id"`
		PlanID             string `json:"plan_id"`
		PlanDigest         string `json:"plan_digest"`
		HQEpoch            string `json:"hq_epoch"`
		RunnerUID          int    `json:"runner_uid"`
		BridgeUID          int    `json:"bridge_uid"`
		RunnerPID          int    `json:"runner_pid"`
		BridgePID          int    `json:"bridge_pid"`
		ChildLauncherPID   int    `json:"child_launcher_pid"`
		ChildPID           int    `json:"child_pid"`
		ChildReceiptSHA256 string `json:"child_receipt_sha256"`
		BothUIDsIdle       bool   `json:"both_uids_idle"`
		StoppedAt          string `json:"stopped_at"`
	}
	if json.Unmarshal(finalRaw, &finalized) != nil || json.Unmarshal(stopRaw, &stopped) != nil || finalized.Schema != "agent-bot-machine/stage2a-finalization/v1" || stopped.Schema != "agent-bot-machine/stage2a-stop/v1" || finalized.ReservationSHA256 != digest(reservation) || stopped.ReservationSHA256 != digest(reservation) || finalized.InstallationID != segment.InstallationID || stopped.InstallationID != segment.InstallationID || finalized.StartID != segment.StartID || stopped.StartID != segment.StartID || finalized.LaunchID != segment.LaunchID || stopped.LaunchID != segment.LaunchID || finalized.PlanID != reserved.Assignment.PlanID || stopped.PlanID != reserved.Assignment.PlanID || finalized.PlanDigest != reserved.Assignment.PlanDigest || stopped.PlanDigest != reserved.Assignment.PlanDigest || finalized.HQEpoch != reserved.Assignment.HQEpoch || stopped.HQEpoch != reserved.Assignment.HQEpoch || !validSHA(finalized.BindReceiptSHA256) || finalized.BridgePID <= 0 || stopped.RunnerUID != reserved.Assignment.RunnerUID || stopped.BridgeUID != reserved.Assignment.BridgeUID || stopped.RunnerPID <= 0 || stopped.BridgePID != finalized.BridgePID || !stopped.BothUIDsIdle {
		return zero, ErrUnqualified
	}
	if hasChildReceipt && (stopped.ChildLauncherPID <= 1 || stopped.ChildPID <= 1 ||
		stopped.ChildLauncherPID == stopped.ChildPID || !validSHA(stopped.ChildReceiptSHA256)) {
		return zero, ErrUnqualified
	}
	finalAt, e1 := parseTime(finalized.FinalizedAt)
	stopAt, e2 := parseTime(stopped.StoppedAt)
	if e1 != nil || e2 != nil || stopAt.Before(finalAt) {
		return zero, ErrUnqualified
	}
	if purpose != qReservationPurposeV3 {
		issuedAt, issueErr := parseTime(reserved.IssuedAt)
		expiresAt, expiryErr := parseTime(reserved.ExpiresAt)
		if issueErr != nil || expiryErr != nil || expiresAt.Sub(issuedAt) > 30*time.Second ||
			finalAt.Before(issuedAt) || !finalAt.Before(expiresAt) {
			return zero, ErrUnqualified
		}
	}
	cohortBinding, err := protectedCohortBindingV3(reserved.MeasurementBinding)
	if err != nil {
		return zero, ErrUnqualified
	}
	reportBinding := reserved.MeasurementBinding
	if purpose != qReservationPurposeV3 {
		fields, fieldErr := canonicalBytes(reserved.MeasurementBinding, MaxReportBytes)
		if fieldErr != nil {
			return zero, ErrUnqualified
		}
		reportBinding, _, err = candidateReportProjectionV3(fields)
		if err != nil {
			return zero, ErrUnqualified
		}
	}
	return protectedAChainV3{binding: binding, cohortBindingSHA256: cohortBinding, reportBindingSHA256: digest(reportBinding), reservationSHA256: digest(reservation), finalizationSHA256: digest(finalization), stopSHA256: digest(stop), launchChallengeSHA256: reserved.AdmissionChallengeSHA256, stopAt: stopAt}, nil
}

// Compare every signed binding field across starts, excluding only the
// explicitly per-start identity. In particular, v2 and v3 cannot be mixed:
// the v2 projection cannot authenticate the v3 H/R, adapter and broker fields.
func protectedCohortBindingV3(raw []byte) (string, error) {
	fields, err := canonicalBytes(raw, MaxReportBytes)
	if err != nil {
		return "", ErrUnqualified
	}
	delete(fields, "start_id")
	delete(fields, "launch_id")
	delete(fields, "hq_epoch")
	stable, err := json.Marshal(fields)
	if err != nil {
		return "", ErrUnqualified
	}
	return digest(stable), nil
}

func sameProtectedCohortV3(want, got string) bool {
	return want != "" && got == want
}

// A supplemental start may have a new launch ID, HQ epoch and Q session, but
// it cannot substitute another installed Soul or plan under the report's
// signed cohort and still count as a resolved protected segment.
func sameProtectedInstalledIdentityV3(want, got measurementBinding) bool {
	return got.InstallationID == want.InstallationID && got.SoulID == want.SoulID &&
		got.HostID == want.HostID && got.ProfileInForce == want.ProfileInForce &&
		got.PlanID == want.PlanID && got.InstalledPlanDigest == want.InstalledPlanDigest &&
		got.PackageSHA256 == want.PackageSHA256 && got.SoulArtifactSHA256 == want.SoulArtifactSHA256 &&
		got.ClaimedDefinitionDigest == want.ClaimedDefinitionDigest &&
		got.DefinitionMeasurement == want.DefinitionMeasurement &&
		got.LaunchInputMeasurement == want.LaunchInputMeasurement &&
		got.Snapshots.Definition == want.Snapshots.Definition &&
		got.Snapshots.LaunchInputs == want.Snapshots.LaunchInputs
}

type physicalSegmentAttestationV3 struct {
	SchemaVersion            int    `json:"schema_version"`
	Kind                     string `json:"kind"`
	Gate                     string `json:"gate"`
	Profile                  string `json:"profile"`
	HostID                   string `json:"host_id"`
	CohortID                 string `json:"cohort_id"`
	SuiteRevision            string `json:"suite_revision"`
	OwnerPlanSHA256          string `json:"owner_plan_sha256"`
	SegmentID                string `json:"segment_id"`
	Purpose                  string `json:"purpose"`
	ReportAnchor             bool   `json:"report_anchor"`
	TerminalState            string `json:"terminal_state"`
	InstallationID           string `json:"installation_id"`
	SoulID                   string `json:"soul_id"`
	StartID                  string `json:"start_id"`
	LaunchID                 string `json:"launch_id"`
	MeasurementBindingSHA256 string `json:"measurement_binding_sha256"`
	QSessionStatus           string `json:"q_session_status"`
	QSessionID               string `json:"q_session_id"`
	QChallengeSHA256         string `json:"q_challenge_sha256"`
	SegmentManifestSHA256    string `json:"segment_manifest_sha256"`
	ReservationSHA256        string `json:"reservation_sha256"`
	BFinalizationSHA256      string `json:"b_finalization_sha256"`
	StopSHA256               string `json:"stop_sha256"`
	QWireSHA256              string `json:"q_wire_sha256"`
	QIndexSHA256             string `json:"q_index_sha256"`
	QEOFSHA256               string `json:"q_eof_sha256"`
	OwnerACPToHQSha256       string `json:"owner_acp_to_hq_sha256"`
	HQACPToOwnerSHA256       string `json:"hq_acp_to_owner_sha256"`
	OSObservationSHA256      string `json:"os_observation_sha256"`
	InstalledInputsSHA256    string `json:"installed_inputs_sha256"`
	SignedAt                 string `json:"signed_at"`
}

func verifyPhysicalAttestationV3(envelope, manifestRaw []byte, manifest physicalSegmentV3,
	chain protectedAChainV3, q VerifiedQPreSignV3, refs map[string]gateObjectRefV3,
	eofEnvelope []byte, key ed25519.PublicKey, now time.Time) error {
	payload, err := qSignedRecordV3(envelope, physicalSegmentPurposeV3, 1, key)
	if err != nil {
		return ErrUnqualified
	}
	f, err := canonicalBytes(payload, 48<<10)
	if err != nil || !hasFields(f, "schema_version", "kind", "gate", "profile", "host_id", "cohort_id", "suite_revision", "owner_plan_sha256", "segment_id", "purpose", "report_anchor", "terminal_state", "installation_id", "soul_id", "start_id", "launch_id", "measurement_binding_sha256", "q_session_status", "q_session_id", "q_challenge_sha256", "segment_manifest_sha256", "reservation_sha256", "b_finalization_sha256", "stop_sha256", "q_wire_sha256", "q_index_sha256", "q_eof_sha256", "owner_acp_to_hq_sha256", "hq_acp_to_owner_sha256", "os_observation_sha256", "installed_inputs_sha256", "signed_at") {
		return ErrUnqualified
	}
	var a physicalSegmentAttestationV3
	if json.Unmarshal(payload, &a) != nil || a.SchemaVersion != 1 || a.Kind != "stage2a-physical-segment-attestation" || a.Gate != manifest.Gate || a.Profile != manifest.Profile || a.HostID != manifest.HostID || a.CohortID != manifest.CohortID || a.SuiteRevision != manifest.SuiteRevision || a.OwnerPlanSHA256 != manifest.OwnerPlanSHA256 || a.SegmentID != manifest.SegmentID || a.Purpose != manifest.Purpose || a.ReportAnchor != manifest.ReportAnchor || a.TerminalState != manifest.TerminalState || a.InstallationID != manifest.InstallationID || a.SoulID != manifest.SoulID || a.StartID != manifest.StartID || a.LaunchID != manifest.LaunchID || a.MeasurementBindingSHA256 != manifest.MeasurementBindingSHA256 || a.QSessionStatus != manifest.QSessionStatus || a.QSessionID != manifest.QSessionID || a.QChallengeSHA256 != manifest.QChallengeSHA256 || a.SegmentManifestSHA256 != digest(manifestRaw) || a.ReservationSHA256 != chain.reservationSHA256 || a.BFinalizationSHA256 != chain.finalizationSHA256 || a.StopSHA256 != chain.stopSHA256 || a.QWireSHA256 != q.WireSHA256 || a.QIndexSHA256 != q.IndexSHA256 || a.QEOFSHA256 != q.EOFReceiptSHA256 || a.OwnerACPToHQSha256 != refs["owner_acp_to_hq"].SHA256 || a.HQACPToOwnerSHA256 != refs["hq_acp_to_owner"].SHA256 || a.OSObservationSHA256 != refs["os_observation"].SHA256 || a.InstalledInputsSHA256 != refs["installed_inputs"].SHA256 {
		return ErrUnqualified
	}
	signedAt, err := parseTime(a.SignedAt)
	if err != nil || signedAt.Before(chain.stopAt) || signedAt.After(now) {
		return ErrUnqualified
	}
	eofRaw, err := qSignedRecordV3(eofEnvelope, QFinishedEOFPurposeV3, 1, key)
	if err != nil {
		return ErrUnqualified
	}
	var eof qEOFV3
	if json.Unmarshal(eofRaw, &eof) != nil {
		return ErrUnqualified
	}
	eofAt, err := parseTime(eof.EOFObservedAt)
	if err != nil || signedAt.Before(eofAt) {
		return ErrUnqualified
	}
	return nil
}

// ResolveSignedProtectedSegmentsV3 authenticates completed, stopped protected
// segment chains from one designated-host report. It intentionally returns
// only a nonauthorizing component: raw ACP/OS capture custody, measured
// installed inputs, attempts, case inventory and T21 are still unverified.
func ResolveSignedProtectedSegmentsV3(reportEnvelope []byte, policy VerifiedPolicy,
	root string, machineKey ed25519.PublicKey, now time.Time) (map[string][]ResolvedProtectedSegmentChainV3, error) {
	if len(machineKey) != ed25519.PublicKeySize || now.IsZero() {
		return nil, ErrUnqualified
	}
	gateBytes, err := ResolveSignedGateManifestsV3(reportEnvelope, policy, root, now)
	if err != nil || len(gateBytes) != 3 {
		return nil, ErrUnqualified
	}
	report, err := VerifyHostReportV3(reportEnvelope, policy, now)
	if err != nil {
		return nil, ErrUnqualified
	}
	var run struct {
		RunEvidence struct {
			Reservation     reportReference `json:"reservation"`
			Finalization    reportReference `json:"finalization"`
			ChallengeSHA256 string          `json:"challenge_sha256"`
		} `json:"run_evidence"`
	}
	if json.Unmarshal(report, &run) != nil {
		return nil, ErrUnqualified
	}
	binding, err := canonicalFieldV3(report, "measurement_binding")
	if err != nil {
		return nil, ErrUnqualified
	}
	reportBinding, err := parseMeasurementBindingV2(binding)
	if err != nil {
		return nil, ErrUnqualified
	}
	result := make(map[string][]ResolvedProtectedSegmentChainV3, 3)
	seenStarts := map[string]bool{}
	seenSessions := map[string]bool{}
	cohortBinding := ""
	anchors := 0
	for _, gateName := range []string{"T01", "T02", "T03"} {
		raw := gateBytes[gateName]
		gate, err := parseGateManifestV3(raw)
		if err != nil || gate.Gate != gateName || gate.Profile != "managed-protected" {
			return nil, ErrUnqualified
		}
		for _, segment := range gate.Segments {
			verified, err := resolveProtectedSegmentV3(root, gate, segment, machineKey, now)
			if err != nil || !sameProtectedInstalledIdentityV3(reportBinding, verified.binding) ||
				seenStarts[verified.InstallationID+"/"+verified.StartID] || seenSessions[verified.QSessionID] {
				return nil, ErrUnqualified
			}
			if cohortBinding == "" {
				cohortBinding = verified.cohortBindingSHA256
			} else if !sameProtectedCohortV3(cohortBinding, verified.cohortBindingSHA256) {
				return nil, ErrUnqualified
			}
			if segment.ReportAnchor {
				anchors++
				if verified.ReservationSHA256 != run.RunEvidence.Reservation.SHA256 || verified.FinalizationSHA256 != run.RunEvidence.Finalization.SHA256 || verified.LaunchChallengeSHA256 != run.RunEvidence.ChallengeSHA256 || verified.reportBindingSHA256 != digest(binding) {
					return nil, ErrUnqualified
				}
			}
			seenStarts[verified.InstallationID+"/"+verified.StartID] = true
			seenSessions[verified.QSessionID] = true
			result[gateName] = append(result[gateName], verified)
		}
	}
	if anchors != 1 {
		return nil, ErrUnqualified
	}
	return result, nil
}

func resolveProtectedSegmentV3(root string, gate gateManifestV3, segment gateSegmentV3,
	key ed25519.PublicKey, now time.Time) (ResolvedProtectedSegmentChainV3, error) {
	var zero ResolvedProtectedSegmentChainV3
	manifestRaw, err := physicalSegmentObjectV3(root, segment.SegmentManifest, "segment_manifest", maxGateManifestBytesV3)
	if err != nil {
		return zero, ErrUnqualified
	}
	manifest, err := parseProtectedSegmentV3(manifestRaw, gate, segment)
	if err != nil {
		return zero, ErrUnqualified
	}
	attestation, err := physicalSegmentObjectV3(root, segment.SegmentAttestation, "segment_attestation", 64<<10)
	if err != nil {
		return zero, ErrUnqualified
	}
	objects := make(map[string][]byte, len(protectedSegmentRolesV3))
	for _, role := range protectedSegmentRolesV3 {
		objects[role], err = physicalSegmentObjectV3(root, manifest.Artifacts[role], role, segmentRoleMaxV3(role))
		if err != nil {
			return zero, ErrUnqualified
		}
	}
	chain, err := verifyProtectedAChainV3(objects["reservation"], objects["b_finalization"], objects["stop"], manifest, key)
	if err != nil {
		return zero, ErrUnqualified
	}
	q, err := VerifyQPreSignV3(objects["q_wire"], objects["q_index"], objects["q_eof"], objects["reservation"], key, now)
	if err != nil || !q.verified || q.SessionID != manifest.QSessionID || q.CohortID != manifest.CohortID || q.InstallationID != manifest.InstallationID || q.SoulID != manifest.SoulID || q.StartID != manifest.StartID || q.HostID != manifest.HostID || q.Profile != manifest.Profile || q.ReservationSHA256 != chain.reservationSHA256 ||
		q.QChallengeSHA256 != manifest.QChallengeSHA256 || q.SuiteRevision != manifest.SuiteRevision {
		return zero, ErrUnqualified
	}
	if verifyPhysicalAttestationV3(attestation, manifestRaw, manifest, chain, q, manifest.Artifacts, objects["q_eof"], key, now) != nil {
		return zero, ErrUnqualified
	}
	return ResolvedProtectedSegmentChainV3{resolved: true, binding: chain.binding, cohortBindingSHA256: chain.cohortBindingSHA256, reportBindingSHA256: chain.reportBindingSHA256, Gate: manifest.Gate, SegmentID: manifest.SegmentID, CohortID: manifest.CohortID, InstallationID: manifest.InstallationID, SoulID: manifest.SoulID, StartID: manifest.StartID, LaunchID: manifest.LaunchID, QSessionID: manifest.QSessionID, ManifestSHA256: digest(manifestRaw), AttestationSHA256: digest(attestation), MeasurementBindingSHA256: manifest.MeasurementBindingSHA256, QIndexSHA256: q.IndexSHA256, QEOFReceiptSHA256: q.EOFReceiptSHA256, ReservationSHA256: chain.reservationSHA256, FinalizationSHA256: chain.finalizationSHA256, LaunchChallengeSHA256: chain.launchChallengeSHA256}, nil
}
