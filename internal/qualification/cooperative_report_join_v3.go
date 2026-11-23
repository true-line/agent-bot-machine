package qualification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path"
	"regexp"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const cooperativeReservationPurposeV3 = "agent-bot/soul-cooperative-reservation/v3"

var cooperativeRunnerAccountV3 = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_-]{0,30}$")

type cooperativeEndpointV3 struct {
	Directory       string `json:"directory"`
	SocketPath      string `json:"socket_path"`
	OwnerUID        uint32 `json:"owner_uid"`
	GroupGID        uint32 `json:"group_gid"`
	DirMode         uint32 `json:"dir_mode"`
	SocketMode      uint32 `json:"socket_mode"`
	ExpectedPeerUID uint32 `json:"expected_peer_uid"`
}

func validCooperativeEndpointV3(e cooperativeEndpointV3, hqUID, runnerUID, runnerGID uint32) bool {
	return reportPath(e.Directory) && reportPath(e.SocketPath) &&
		path.Dir(e.SocketPath) == e.Directory &&
		e.OwnerUID == hqUID && e.GroupGID == runnerGID &&
		e.ExpectedPeerUID == runnerUID &&
		e.DirMode == 0o2750 && e.SocketMode == 0o660
}

// cooperativeReportJoinV3 authenticates a separate A-signed managed-cooperative
// reservation and joins its frozen H/R identity to the designated-host report.
// It does not verify one-use spending, the installed bytes, segment artifacts,
// raw observations, release provenance or a physical T21 result.
func cooperativeReportJoinV3(reportRaw, reservationEnvelope []byte,
	machineKey ed25519.PublicKey) error {
	payload, err := qSignedRecordV3(reservationEnvelope, cooperativeReservationPurposeV3, 3, machineKey)
	if err != nil {
		return ErrUnqualified
	}
	fields, err := canonicalBytes(payload, 48<<10)
	if err != nil || !hasFields(fields, "contract", "kind", "schema_version", "host_id",
		"issued_at", "expires_at", "installed_plan_receipt_sha256", "assignment",
		"endpoints", "measurement_binding", "admission_challenge_sha256") ||
		string(fields["contract"]) != `"machine/v3"` ||
		string(fields["kind"]) != `"soul-cooperative-reservation"` ||
		string(fields["schema_version"]) != "3" {
		return ErrUnqualified
	}
	binding, err := parseHRMeasurementBindingV3(fields["measurement_binding"])
	if err != nil || binding.Base.ProfileInForce != "managed-cooperative" {
		return ErrUnqualified
	}
	bindingFields, err := canonicalBytes(fields["measurement_binding"], MaxReportBytes)
	if err != nil {
		return ErrUnqualified
	}
	projection, _, err := commonReportProjectionV3(bindingFields)
	if err != nil {
		return ErrUnqualified
	}
	assignmentFields, err := strictObject(fields["assignment"], 48<<10)
	if err != nil || !hasFields(assignmentFields, "installation_id", "soul_id", "start_id",
		"launch_id", "plan_id", "plan_digest", "hq_epoch", "expires_at", "runner_account",
		"runner_uid", "runner_gid", "hq_uid", "machine_uid", "package_root",
		"launch_inputs_root", "runtime_root", "node_path", "entry_path", "state_root",
		"state_root_mode", "package_sha256", "soul_artifact_sha256") {
		return ErrUnqualified
	}
	endpointsFields, err := strictObject(fields["endpoints"], 48<<10)
	if err != nil || !hasFields(endpointsFields, "admission", "broker") {
		return ErrUnqualified
	}
	for _, name := range []string{"admission", "broker"} {
		endpointFields, err := strictObject(endpointsFields[name], 48<<10)
		if err != nil || !hasFields(endpointFields, "directory", "socket_path", "owner_uid",
			"group_gid", "dir_mode", "socket_mode", "expected_peer_uid") {
			return ErrUnqualified
		}
	}
	var reservation struct {
		HostID                     string `json:"host_id"`
		IssuedAt                   string `json:"issued_at"`
		ExpiresAt                  string `json:"expires_at"`
		InstalledPlanReceiptSHA256 string `json:"installed_plan_receipt_sha256"`
		AdmissionChallengeSHA256   string `json:"admission_challenge_sha256"`
		Assignment                 struct {
			InstallationID     string `json:"installation_id"`
			SoulID             string `json:"soul_id"`
			StartID            string `json:"start_id"`
			LaunchID           string `json:"launch_id"`
			PlanID             string `json:"plan_id"`
			PlanDigest         string `json:"plan_digest"`
			HQEpoch            string `json:"hq_epoch"`
			ExpiresAt          string `json:"expires_at"`
			RunnerAccount      string `json:"runner_account"`
			RunnerUID          uint32 `json:"runner_uid"`
			RunnerGID          uint32 `json:"runner_gid"`
			HQUID              uint32 `json:"hq_uid"`
			MachineUID         uint32 `json:"machine_uid"`
			PackageRoot        string `json:"package_root"`
			LaunchInputsRoot   string `json:"launch_inputs_root"`
			RuntimeRoot        string `json:"runtime_root"`
			NodePath           string `json:"node_path"`
			EntryPath          string `json:"entry_path"`
			StateRoot          string `json:"state_root"`
			StateRootMode      string `json:"state_root_mode"`
			PackageSHA256      string `json:"package_sha256"`
			SoulArtifactSHA256 string `json:"soul_artifact_sha256"`
		} `json:"assignment"`
		Endpoints struct {
			Admission cooperativeEndpointV3 `json:"admission"`
			Broker    cooperativeEndpointV3 `json:"broker"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(payload, &reservation) != nil ||
		reservation.HostID != binding.Base.HostID ||
		!validSHA(reservation.InstalledPlanReceiptSHA256) ||
		!validSHA(reservation.AdmissionChallengeSHA256) ||
		reservation.Assignment.InstallationID != binding.Base.InstallationID ||
		reservation.Assignment.SoulID != binding.Base.SoulID ||
		reservation.Assignment.StartID != binding.Base.StartID ||
		reservation.Assignment.LaunchID != binding.Base.LaunchID ||
		reservation.Assignment.PlanID != binding.Base.PlanID ||
		reservation.Assignment.PlanDigest != binding.Base.InstalledPlanDigest ||
		reservation.Assignment.HQEpoch != binding.Base.HQEpoch ||
		reservation.Assignment.ExpiresAt != reservation.ExpiresAt ||
		!cooperativeRunnerAccountV3.MatchString(reservation.Assignment.RunnerAccount) ||
		reservation.Assignment.RunnerUID != binding.RInventory.ReaderUID ||
		reservation.Assignment.RunnerGID != binding.RInventory.ReaderGID ||
		reservation.Assignment.MachineUID != binding.RInventory.MachineUID ||
		reservation.Assignment.HQUID == 0 ||
		reservation.Assignment.HQUID == reservation.Assignment.RunnerUID ||
		reservation.Assignment.HQUID == reservation.Assignment.MachineUID ||
		reservation.Assignment.PackageRoot != binding.Base.Snapshots.Definition.RootPath ||
		reservation.Assignment.LaunchInputsRoot != binding.Base.Snapshots.LaunchInputs.RootPath ||
		reservation.Assignment.RuntimeRoot != binding.RInventory.Snapshot.Path ||
		reservation.Assignment.NodePath != path.Join(reservation.Assignment.RuntimeRoot, "bin/node") ||
		reservation.Assignment.EntryPath != path.Join(reservation.Assignment.RuntimeRoot, "bin/agent-bot-souls.mjs") ||
		reservation.Assignment.StateRoot !=
			"/private/var/agent-bot-soul-runner-"+reservation.Assignment.RunnerAccount+"/state" ||
		reservation.Assignment.StateRootMode != "0700" ||
		reservation.Assignment.PackageSHA256 != binding.Base.PackageSHA256 ||
		reservation.Assignment.SoulArtifactSHA256 != binding.Base.SoulArtifactSHA256 ||
		!validCooperativeEndpointV3(reservation.Endpoints.Admission,
			reservation.Assignment.HQUID, reservation.Assignment.RunnerUID, reservation.Assignment.RunnerGID) ||
		!validCooperativeEndpointV3(reservation.Endpoints.Broker,
			reservation.Assignment.HQUID, reservation.Assignment.RunnerUID, reservation.Assignment.RunnerGID) ||
		reservation.Endpoints.Admission.SocketPath == reservation.Endpoints.Broker.SocketPath {
		return ErrUnqualified
	}
	issued, e1 := parseTime(reservation.IssuedAt)
	expires, e2 := parseTime(reservation.ExpiresAt)
	if e1 != nil || e2 != nil || !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return ErrUnqualified
	}
	report, err := strictObject(reportRaw, MaxReportBytes)
	if err != nil || !bytes.Equal(report["measurement_binding"], projection) ||
		string(report["profile_in_force"]) != `"managed-cooperative"` {
		return ErrUnqualified
	}
	if _, hasBridge := report["bridge"]; hasBridge {
		return ErrUnqualified
	}
	var document struct {
		Host struct {
			ID string `json:"id"`
		} `json:"host"`
		RecordedAt string `json:"recorded_at"`
		Adapter    struct {
			PackageSHA256 string `json:"package_sha256"`
		} `json:"adapter"`
		Launch struct {
			Executable       string `json:"executable"`
			ExecutableSHA256 string `json:"executable_sha256"`
			CodeInputs       []struct {
				Path string `json:"path"`
			} `json:"code_inputs"`
		} `json:"launch"`
		RunEvidence struct {
			Reservation     reportReference `json:"reservation"`
			ChallengeSHA256 string          `json:"challenge_sha256"`
		} `json:"run_evidence"`
	}
	if json.Unmarshal(reportRaw, &document) != nil ||
		document.Host.ID != reservation.HostID ||
		document.Adapter.PackageSHA256 != binding.AdapterRelease.PackageSHA256 ||
		document.Launch.Executable != binding.AdapterRelease.ExecutablePath ||
		document.Launch.ExecutableSHA256 != binding.AdapterRelease.ExecutableSHA256 ||
		len(document.Launch.CodeInputs) != binding.AdapterRelease.CodeInputCount ||
		document.RunEvidence.Reservation.SHA256 != digest(reservationEnvelope) ||
		document.RunEvidence.ChallengeSHA256 != reservation.AdmissionChallengeSHA256 {
		return ErrUnqualified
	}
	recorded, err := parseTime(document.RecordedAt)
	if err != nil || recorded.Before(issued) {
		return ErrUnqualified
	}
	paths := make([]string, 0, len(document.Launch.CodeInputs))
	previous := ""
	for _, input := range document.Launch.CodeInputs {
		if !reportPath(input.Path) ||
			!strings.HasPrefix(input.Path, binding.RInventory.Snapshot.Path+"/") ||
			input.Path <= previous {
			return ErrUnqualified
		}
		paths = append(paths, input.Path)
		previous = input.Path
	}
	pathJSON, err := json.Marshal(paths)
	if err != nil {
		return ErrUnqualified
	}
	pathJCS, err := jsoncanonicalizer.Transform(pathJSON)
	if err != nil || digest(preimage("agent-bot/stage2a-adapter-code-inputs/v3", pathJCS)) !=
		binding.AdapterRelease.CodeInputsDigest {
		return ErrUnqualified
	}
	return nil
}

// CheckCooperativeHostReportReservationV3 authenticates the designated host
// report and a distinct A reservation before comparing their exact bytes.
// This diagnostic grants no T21 result, protected launch or acceptance.
func CheckCooperativeHostReportReservationV3(hostEnvelope, reservationEnvelope []byte,
	policy VerifiedPolicy, machineKey ed25519.PublicKey, now time.Time) error {
	report, err := VerifyHostReportV3(hostEnvelope, policy, now)
	if err != nil {
		return ErrUnqualified
	}
	return cooperativeReportJoinV3(report, reservationEnvelope, machineKey)
}
