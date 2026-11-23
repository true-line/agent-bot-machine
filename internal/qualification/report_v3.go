package qualification

import (
	"encoding/json"
)

func validV3Renders(raw json.RawMessage) bool {
	var renders []string
	if json.Unmarshal(raw, &renders) != nil || renders == nil {
		return false
	}
	seen := make(map[string]struct{}, len(renders))
	for _, name := range renders {
		if !reportID.MatchString(name) {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

// reportShapeV3 checks the signed report's internal agreement. Independently
// authenticated reservation, finalization, completed-run and release records
// must still be resolved and compared before positive qualification.
func reportShapeV3(raw []byte) error {
	fields, err := strictObject(raw, MaxReportBytes)
	if err != nil {
		return ErrUnqualified
	}
	commonNames := []string{"adapter", "checks", "cost_bound", "evaluation_cells", "gates", "harness", "host", "launch", "outcome", "profile_in_force", "recorded_at", "renders", "run_id", "runner", "schema_version", "soul_start", "suite_revision", "measurement_binding", "run_evidence"}
	var profile string
	if json.Unmarshal(fields["profile_in_force"], &profile) != nil {
		return ErrUnqualified
	}
	if profile == "managed-protected" {
		commonNames = append(commonNames, "bridge")
	}
	if !hasFields(fields, commonNames...) || !validV3Renders(fields["renders"]) {
		return ErrUnqualified
	}
	binding, err := parseMeasurementBindingV2(fields["measurement_binding"])
	if err != nil || !validHex(binding.SoulArtifactSHA256, 64) {
		return ErrUnqualified
	}
	runFields, err := strictObject(fields["run_evidence"], MaxReportBytes)
	if err != nil || !hasFields(runFields, "reservation", "finalization", "challenge_sha256", "execution_completion") {
		return ErrUnqualified
	}
	var run struct {
		Reservation         reportReference `json:"reservation"`
		Finalization        reportReference `json:"finalization"`
		ChallengeSHA256     string          `json:"challenge_sha256"`
		ExecutionCompletion reportReference `json:"execution_completion"`
	}
	if json.Unmarshal(fields["run_evidence"], &run) != nil || !reportRef(run.Reservation) ||
		!reportRef(run.Finalization) || !reportRef(run.ExecutionCompletion) || !validSHA(run.ChallengeSHA256) ||
		run.Reservation.URI == run.Finalization.URI ||
		run.Reservation.SHA256 == run.Finalization.SHA256 ||
		run.ExecutionCompletion.URI == run.Reservation.URI ||
		run.ExecutionCompletion.URI == run.Finalization.URI ||
		run.ExecutionCompletion.SHA256 == run.Reservation.SHA256 ||
		run.ExecutionCompletion.SHA256 == run.Finalization.SHA256 {
		return ErrUnqualified
	}
	for _, name := range []string{"reservation", "finalization", "execution_completion"} {
		ref, err := strictObject(runFields[name], MaxReportBytes)
		if err != nil || !hasFields(ref, "uri", "sha256") {
			return ErrUnqualified
		}
	}
	copyFields := make(map[string]json.RawMessage, len(fields))
	for name, value := range fields {
		if name != "measurement_binding" && name != "run_evidence" {
			copyFields[name] = value
		}
	}
	var report reportDocument
	if json.Unmarshal(raw, &report) != nil || report.SchemaVersion != 3 ||
		binding.HostID != report.Host.ID || binding.ProfileInForce != report.ProfileInForce {
		return ErrUnqualified
	}
	if profile == "managed-protected" {
		copyFields["schema_version"] = []byte("2")
		prior, err := json.Marshal(copyFields)
		if err != nil || reportShapeV2(prior) != nil {
			return ErrUnqualified
		}
		var bridge bridgeReport
		if json.Unmarshal(fields["bridge"], &bridge) != nil {
			return ErrUnqualified
		}
		if bridge.Principals.MachineUID != binding.Snapshots.Definition.OwnerUID ||
			bridge.Principals.RunnerPrivateGID != binding.Snapshots.Definition.OwnerGID {
			return ErrUnqualified
		}
		a := bridge.Assignment
		if a.InstallationID != binding.InstallationID || a.SoulID != binding.SoulID ||
			a.StartID != binding.StartID || a.LaunchID != binding.LaunchID ||
			a.PlanID != binding.PlanID || a.PlanDigest != "sha256:"+binding.InstalledPlanDigest ||
			a.ReservationSHA != run.Reservation.SHA256 ||
			a.Observation != report.SoulStart.MachineObservation {
			return ErrUnqualified
		}
	} else if profile == "managed-cooperative" {
		copyFields["schema_version"] = []byte("1")
		prior, err := json.Marshal(copyFields)
		if err != nil || reportShape(prior) != nil {
			return ErrUnqualified
		}
	} else {
		return ErrUnqualified
	}
	return nil
}
