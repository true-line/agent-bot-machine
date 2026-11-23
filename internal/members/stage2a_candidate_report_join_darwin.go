package members

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// VerifyStage2aCandidateReportJoinV3 binds the host report's published v2
// measurement summary to the exact independently pinned A-signed candidate
// reservation. The caller also verifies the completed Q wire/index/EOF chain
// and the execution-completion record before requesting a host signature.
func VerifyStage2aCandidateReportJoinV3(report, envelope []byte, machineKey ed25519.PublicKey) error {
	if stage2aStrictJSONBounded(report, 64<<10, 16384) != nil {
		return errStage2aReservationAuthority
	}
	var fields struct {
		Profile       string          `json:"profile_in_force"`
		Recorded      string          `json:"recorded_at"`
		Binding       json.RawMessage `json:"measurement_binding"`
		SuiteRevision string          `json:"suite_revision"`
		Adapter       struct {
			PackageSHA256 string `json:"package_sha256"`
		} `json:"adapter"`
		Launch struct {
			Executable       string `json:"executable"`
			ExecutableSHA256 string `json:"executable_sha256"`
			CodeInputs       []struct {
				Path string `json:"path"`
			} `json:"code_inputs"`
		} `json:"launch"`
		Run struct {
			Reservation struct {
				SHA256 string `json:"sha256"`
			} `json:"reservation"`
			ChallengeSHA256 string `json:"challenge_sha256"`
		} `json:"run_evidence"`
	}
	if json.Unmarshal(report, &fields) != nil || fields.Profile != "managed-protected" {
		return errStage2aReservationAuthority
	}
	payload, _, err := verifyStage2aV3Envelope(envelope, stage2aQualificationCandidatePurposeV3, machineKey)
	var candidate stage2aQualificationCandidateReservationV3
	if err != nil || stage2aDecodeExact(payload, &candidate) != nil {
		return errStage2aReservationAuthority
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, candidate.IssuedAt)
	recorded, recordedErr := time.Parse(time.RFC3339Nano, fields.Recorded)
	guard, err := verifyStage2aReservationModeV3(stage2aCandidateRunV3, envelope, fields.Run.Reservation.SHA256, payload, machineKey, issued)
	if err != nil || issueErr != nil || recordedErr != nil || recorded.Before(issued) ||
		guard.binding.ProfileInForce != fields.Profile || guard.binding.HostID != candidate.HostID ||
		!stage2aPrefixedDigest.MatchString(fields.Run.ChallengeSHA256) || fields.Run.ChallengeSHA256 != candidate.AdmissionChallengeSHA256 ||
		guard.binding.Contract != "machine/v3" || guard.binding.SchemaVersion != 3 {
		return errStage2aReservationAuthority
	}
	adapter := candidate.MeasurementBinding.Candidate
	if fields.SuiteRevision != candidate.Attempt.SuiteRevision ||
		fields.Adapter.PackageSHA256 != adapter.PackageSHA256 ||
		fields.Launch.Executable != adapter.ExecutablePath || fields.Launch.ExecutableSHA256 != adapter.ExecutableSHA256 ||
		len(fields.Launch.CodeInputs) != adapter.CodeInputCount {
		return errStage2aReservationAuthority
	}
	paths := make([]string, 0, len(fields.Launch.CodeInputs))
	for _, input := range fields.Launch.CodeInputs {
		paths = append(paths, input.Path)
	}
	code, err := marshalStage2aReservationJCS(paths)
	if err != nil || stage2aV3PurposeDigest("agent-bot/stage2a-adapter-code-inputs/v3", code) != adapter.CodeInputsDigest {
		return errStage2aReservationAuthority
	}
	binding := guard.binding
	binding.Contract, binding.SchemaVersion = "machine/v2", 2
	summary, err := marshalStage2aReservationJCS(binding)
	if err != nil || !bytes.Equal(fields.Binding, summary) {
		return errStage2aReservationAuthority
	}
	return nil
}
